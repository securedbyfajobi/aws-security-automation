#!/usr/bin/env python3
"""
Security Incident Response Automation
Automated response workflows for security incidents
"""

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentResponseAutomation:
    """Automated incident response workflows"""

    def __init__(self, region_name: str = 'us-east-1'):
        self.ec2 = boto3.client('ec2', region_name=region_name)
        self.iam = boto3.client('iam')
        self.sns = boto3.client('sns', region_name=region_name)
        self.ssm = boto3.client('ssm', region_name=region_name)

    def create_incident_record(self, incident_type: str, severity: IncidentSeverity,
                             description: str, affected_resources: List[str]) -> str:
        """Create incident record and assign unique ID"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        incident_record = {
            'incident_id': incident_id,
            'type': incident_type,
            'severity': severity.value,
            'description': description,
            'affected_resources': affected_resources,
            'created_at': datetime.now().isoformat(),
            'status': 'open',
            'response_actions': []
        }

        # Save incident record (in production, this would go to a database)
        with open(f"{incident_id}.json", 'w') as f:
            json.dump(incident_record, f, indent=2)

        logger.info(f"Created incident record: {incident_id}")
        return incident_id

    def isolate_compromised_instance(self, instance_id: str, incident_id: str) -> bool:
        """Isolate compromised EC2 instance"""
        try:
            # Create forensic security group
            forensic_sg = self._create_forensic_security_group()

            # Get current instance details
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]

            # Store original security groups for recovery
            self._store_original_config(incident_id, instance_id, {
                'original_security_groups': current_sgs,
                'vpc_id': instance['VpcId'],
                'subnet_id': instance['SubnetId']
            })

            # Replace with forensic security group
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[forensic_sg]
            )

            # Create snapshot for forensics
            for block_device in instance.get('BlockDeviceMappings', []):
                volume_id = block_device['Ebs']['VolumeId']
                self.ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"Forensic snapshot for incident {incident_id}"
                )

            logger.info(f"Instance {instance_id} isolated for incident {incident_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to isolate instance {instance_id}: {str(e)}")
            return False

    def disable_compromised_credentials(self, access_key_id: str, incident_id: str) -> bool:
        """Disable compromised IAM credentials"""
        try:
            # Get user associated with access key
            response = self.iam.get_access_key_last_used(AccessKeyId=access_key_id)
            username = response['UserName']

            # Store original state for recovery
            user_policies = self.iam.list_user_policies(UserName=username)['PolicyNames']
            attached_policies = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']

            self._store_original_config(incident_id, f"user-{username}", {
                'username': username,
                'access_key_id': access_key_id,
                'inline_policies': user_policies,
                'attached_policies': [p['PolicyArn'] for p in attached_policies]
            })

            # Deactivate access key
            self.iam.update_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )

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

            policy_name = f"IncidentResponse-{incident_id}-Deny"
            self.iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy)
            )

            logger.info(f"Disabled credentials for user {username} in incident {incident_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to disable credentials {access_key_id}: {str(e)}")
            return False

    def collect_forensic_data(self, incident_id: str, resource_id: str) -> Dict:
        """Collect forensic data from affected resources"""
        forensic_data = {
            'incident_id': incident_id,
            'resource_id': resource_id,
            'collection_time': datetime.now().isoformat(),
            'data': {}
        }

        try:
            if resource_id.startswith('i-'):  # EC2 instance
                # Get instance metadata
                response = self.ec2.describe_instances(InstanceIds=[resource_id])
                forensic_data['data']['instance_details'] = response['Reservations'][0]['Instances'][0]

                # Get recent CloudTrail events
                forensic_data['data']['recent_api_calls'] = self._get_recent_api_calls(resource_id)

                # Get system logs via SSM
                try:
                    ssm_response = self.ssm.send_command(
                        InstanceIds=[resource_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={
                            'commands': [
                                'last -n 50',  # Recent logins
                                'ps aux',      # Running processes
                                'netstat -tulpn',  # Network connections
                                'find /tmp -type f -mtime -1'  # Recent temp files
                            ]
                        }
                    )
                    forensic_data['data']['system_commands'] = ssm_response['Command']['CommandId']
                except Exception as e:
                    logger.warning(f"Could not collect system logs: {str(e)}")

        except Exception as e:
            logger.error(f"Error collecting forensic data: {str(e)}")

        # Save forensic data
        with open(f"forensics_{incident_id}_{resource_id}.json", 'w') as f:
            json.dump(forensic_data, f, indent=2, default=str)

        return forensic_data

    def _create_forensic_security_group(self) -> str:
        """Create or get forensic security group"""
        sg_name = 'incident-response-forensic-sg'

        try:
            # Check if security group exists
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
            )

            if response['SecurityGroups']:
                return response['SecurityGroups'][0]['GroupId']

            # Create new forensic security group
            vpc_response = self.ec2.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )
            vpc_id = vpc_response['Vpcs'][0]['VpcId']

            sg_response = self.ec2.create_security_group(
                GroupName=sg_name,
                Description='Incident Response forensic isolation group - no network access',
                VpcId=vpc_id
            )

            # Allow only SSH from security team IP (example)
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_response['GroupId'],
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '10.0.0.0/8', 'Description': 'Security team access'}]
                    }
                ]
            )

            return sg_response['GroupId']

        except Exception as e:
            logger.error(f"Error creating forensic security group: {str(e)}")
            raise

    def _store_original_config(self, incident_id: str, resource_id: str, config: Dict):
        """Store original configuration for recovery"""
        recovery_data = {
            'incident_id': incident_id,
            'resource_id': resource_id,
            'original_config': config,
            'stored_at': datetime.now().isoformat()
        }

        with open(f"recovery_{incident_id}_{resource_id}.json", 'w') as f:
            json.dump(recovery_data, f, indent=2)

    def _get_recent_api_calls(self, resource_id: str) -> List[Dict]:
        """Get recent CloudTrail API calls for resource"""
        # This would integrate with CloudTrail logs
        # Simplified example
        return [{"placeholder": "CloudTrail API calls would be retrieved here"}]

def main():
    # Example incident response workflow
    automation = IncidentResponseAutomation()

    # Create incident for compromised instance
    incident_id = automation.create_incident_record(
        incident_type="Compromised Instance",
        severity=IncidentSeverity.HIGH,
        description="Suspicious network activity detected on EC2 instance",
        affected_resources=["i-1234567890abcdef0"]
    )

    print(f"Created incident: {incident_id}")

if __name__ == "__main__":
    main()