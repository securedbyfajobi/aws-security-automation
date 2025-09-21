#!/usr/bin/env python3
"""
CIS Benchmark Scanner for AWS
Automated validation of CIS AWS Foundations Benchmark controls
"""

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CISBenchmarkScanner:
    """CIS AWS Foundations Benchmark compliance scanner"""

    def __init__(self, region_name: str = 'us-east-1'):
        self.iam = boto3.client('iam')
        self.ec2 = boto3.client('ec2', region_name=region_name)
        self.s3 = boto3.client('s3')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region_name)

    def check_cis_1_3(self) -> Tuple[bool, str]:
        """CIS 1.3 - Ensure credentials unused for 90 days or greater are disabled"""
        try:
            users = self.iam.list_users()['Users']
            non_compliant_users = []

            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']

                for key in keys:
                    if key['Status'] == 'Active':
                        # Check if key has been used recently
                        try:
                            last_used = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                            if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                                days_since_use = (datetime.now().replace(tzinfo=None) -
                                                last_used['AccessKeyLastUsed']['LastUsedDate'].replace(tzinfo=None)).days
                                if days_since_use > 90:
                                    non_compliant_users.append(user['UserName'])
                        except Exception:
                            pass

            if non_compliant_users:
                return False, f"Found {len(non_compliant_users)} users with unused credentials: {', '.join(non_compliant_users[:3])}"
            else:
                return True, "All active credentials have been used within 90 days"

        except Exception as e:
            return False, f"Error checking CIS 1.3: {str(e)}"

    def check_cis_2_1(self) -> Tuple[bool, str]:
        """CIS 2.1 - Ensure CloudTrail is enabled in all regions"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']

            multi_region_trails = [trail for trail in trails if trail.get('IsMultiRegionTrail', False)]

            if multi_region_trails:
                return True, f"Found {len(multi_region_trails)} multi-region CloudTrail(s)"
            else:
                return False, "No multi-region CloudTrail found"

        except Exception as e:
            return False, f"Error checking CIS 2.1: {str(e)}"

    def check_cis_2_3(self) -> Tuple[bool, str]:
        """CIS 2.3 - Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']

            for trail in trails:
                if 'S3BucketName' in trail:
                    bucket_name = trail['S3BucketName']

                    try:
                        # Check bucket ACL
                        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                                return False, f"CloudTrail bucket {bucket_name} is publicly accessible"

                        # Check bucket policy
                        try:
                            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                            policy_doc = json.loads(policy['Policy'])
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Principal') == '*':
                                    return False, f"CloudTrail bucket {bucket_name} has public policy"
                        except self.s3.exceptions.NoSuchBucketPolicy:
                            pass

                    except Exception as e:
                        logger.warning(f"Could not check bucket {bucket_name}: {str(e)}")

            return True, "CloudTrail S3 buckets are not publicly accessible"

        except Exception as e:
            return False, f"Error checking CIS 2.3: {str(e)}"

    def check_cis_4_1(self) -> Tuple[bool, str]:
        """CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"""
        try:
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']

            non_compliant_sgs = []
            for sg in security_groups:
                for rule in sg['IpPermissions']:
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                non_compliant_sgs.append(sg['GroupId'])

            if non_compliant_sgs:
                return False, f"Found {len(non_compliant_sgs)} security groups allowing SSH from anywhere"
            else:
                return True, "No security groups allow SSH access from 0.0.0.0/0"

        except Exception as e:
            return False, f"Error checking CIS 4.1: {str(e)}"

    def run_full_scan(self) -> Dict:
        """Run complete CIS benchmark scan"""
        checks = {
            'CIS 1.3': self.check_cis_1_3,
            'CIS 2.1': self.check_cis_2_1,
            'CIS 2.3': self.check_cis_2_3,
            'CIS 4.1': self.check_cis_4_1,
        }

        results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'CIS AWS Foundations Benchmark',
            'checks': {},
            'summary': {
                'total_checks': len(checks),
                'passed': 0,
                'failed': 0,
                'compliance_percentage': 0
            }
        }

        for check_id, check_function in checks.items():
            passed, message = check_function()

            results['checks'][check_id] = {
                'passed': passed,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }

            if passed:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1

        results['summary']['compliance_percentage'] = (
            results['summary']['passed'] / results['summary']['total_checks']
        ) * 100

        return results

def main():
    scanner = CISBenchmarkScanner()
    results = scanner.run_full_scan()

    print(json.dumps(results, indent=2))

    # Save results
    filename = f"cis_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"CIS scan complete: {results['summary']['compliance_percentage']:.1f}% compliant")

if __name__ == "__main__":
    main()