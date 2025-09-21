#!/usr/bin/env python3
"""
GuardDuty Automated Threat Response System
Automatically responds to GuardDuty findings based on severity and type
"""

import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class GuardDutyResponder:
    """Automated GuardDuty threat response system"""

    def __init__(self, region_name: str = 'us-east-1'):
        """Initialize AWS clients"""
        self.guardduty = boto3.client('guardduty', region_name=region_name)
        self.ec2 = boto3.client('ec2', region_name=region_name)
        self.iam = boto3.client('iam', region_name=region_name)
        self.sns = boto3.client('sns', region_name=region_name)
        self.region = region_name

    def get_active_findings(self, detector_id: str,
                          severity_threshold: float = 4.0) -> List[Dict]:
        """Retrieve active GuardDuty findings above severity threshold"""
        try:
            response = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': severity_threshold
                        },
                        'updatedAt': {
                            'Gte': int((datetime.now() - timedelta(hours=24)).timestamp() * 1000)
                        }
                    }
                }
            )

            if response['FindingIds']:
                findings_detail = self.guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=response['FindingIds']
                )
                return findings_detail['Findings']
            return []

        except Exception as e:
            logger.error(f"Error retrieving findings: {str(e)}")
            return []

    def isolate_compromised_instance(self, instance_id: str) -> bool:
        """Isolate EC2 instance by applying restrictive security group"""
        try:
            # Create isolation security group if it doesn't exist
            isolation_sg = self._create_isolation_security_group()

            # Get current instance details
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]

            # Replace security groups with isolation group
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg]
            )

            logger.info(f"Instance {instance_id} isolated successfully")
            return True

        except Exception as e:
            logger.error(f"Error isolating instance {instance_id}: {str(e)}")
            return False

    def _create_isolation_security_group(self) -> str:
        """Create or get isolation security group"""
        sg_name = 'guardduty-isolation-sg'

        try:
            # Check if security group exists
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
            )

            if response['SecurityGroups']:
                return response['SecurityGroups'][0]['GroupId']

            # Create new isolation security group
            vpc_response = self.ec2.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )
            vpc_id = vpc_response['Vpcs'][0]['VpcId']

            sg_response = self.ec2.create_security_group(
                GroupName=sg_name,
                Description='GuardDuty isolation security group - blocks all traffic',
                VpcId=vpc_id
            )

            # No inbound/outbound rules = complete isolation
            logger.info(f"Created isolation security group: {sg_response['GroupId']}")
            return sg_response['GroupId']

        except Exception as e:
            logger.error(f"Error creating isolation security group: {str(e)}")
            raise

    def disable_compromised_user(self, username: str) -> bool:
        """Disable IAM user and revoke active sessions"""
        try:
            # Attach deny-all policy
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }

            policy_name = f"{username}-emergency-deny"

            self.iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy)
            )

            # Delete access keys
            keys_response = self.iam.list_access_keys(UserName=username)
            for key in keys_response['AccessKeyMetadata']:
                self.iam.delete_access_key(
                    UserName=username,
                    AccessKeyId=key['AccessKeyId']
                )

            logger.info(f"User {username} disabled successfully")
            return True

        except Exception as e:
            logger.error(f"Error disabling user {username}: {str(e)}")
            return False

    def send_alert(self, finding: Dict, action_taken: str) -> None:
        """Send alert notification"""
        try:
            message = {
                "finding_id": finding['Id'],
                "type": finding['Type'],
                "severity": finding['Severity'],
                "title": finding['Title'],
                "description": finding['Description'],
                "action_taken": action_taken,
                "timestamp": datetime.now().isoformat()
            }

            # Log the alert (in production, send to SNS/Slack)
            logger.warning(f"SECURITY ALERT: {json.dumps(message, indent=2)}")

        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")

    def process_findings(self, detector_id: str) -> None:
        """Main processing loop for GuardDuty findings"""
        findings = self.get_active_findings(detector_id)

        for finding in findings:
            finding_type = finding['Type']
            severity = finding['Severity']

            logger.info(f"Processing finding: {finding['Id']} - {finding['Title']}")

            action_taken = "None"

            # High severity findings (7.0+) - Immediate response
            if severity >= 7.0:
                if 'EC2' in finding_type and finding.get('Service', {}).get('ResourceRole') == 'TARGET':
                    # Compromised EC2 instance
                    instance_id = finding['Resource']['InstanceDetails']['InstanceId']
                    if self.isolate_compromised_instance(instance_id):
                        action_taken = f"Isolated EC2 instance {instance_id}"

                elif 'IAMUser' in finding_type:
                    # Compromised IAM user
                    username = finding['Resource']['AccessKeyDetails']['UserName']
                    if self.disable_compromised_user(username):
                        action_taken = f"Disabled IAM user {username}"

            # Medium severity findings (4.0-6.9) - Alert and monitor
            elif severity >= 4.0:
                action_taken = "Alert sent to security team for investigation"

            # Send notification
            self.send_alert(finding, action_taken)

def main():
    """Main execution function"""
    import argparse

    parser = argparse.ArgumentParser(description='GuardDuty Automated Response')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--detector-id', required=True, help='GuardDuty detector ID')
    parser.add_argument('--severity', type=float, default=4.0, help='Minimum severity threshold')

    args = parser.parse_args()

    responder = GuardDutyResponder(region_name=args.region)
    responder.process_findings(args.detector_id)

if __name__ == "__main__":
    main()