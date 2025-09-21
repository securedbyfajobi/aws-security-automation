#!/usr/bin/env python3
"""
Security-Focused Cost Optimization
Identifies unused security resources and optimization opportunities
"""

import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityCostOptimizer:
    """Optimize security-related AWS costs"""

    def __init__(self, region_name: str = 'us-east-1'):
        self.ec2 = boto3.client('ec2', region_name=region_name)
        self.guardduty = boto3.client('guardduty', region_name=region_name)
        self.security_hub = boto3.client('securityhub', region_name=region_name)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)

    def find_unused_security_groups(self) -> List[Dict]:
        """Find unused security groups"""
        unused_sgs = []

        try:
            # Get all security groups
            sgs = self.ec2.describe_security_groups()['SecurityGroups']

            # Get all network interfaces
            enis = self.ec2.describe_network_interfaces()['NetworkInterfaces']
            used_sg_ids = set()

            for eni in enis:
                for sg in eni['Groups']:
                    used_sg_ids.add(sg['GroupId'])

            # Check for unused security groups
            for sg in sgs:
                if sg['GroupName'] != 'default' and sg['GroupId'] not in used_sg_ids:
                    unused_sgs.append({
                        'GroupId': sg['GroupId'],
                        'GroupName': sg['GroupName'],
                        'Description': sg['Description'],
                        'VpcId': sg.get('VpcId', 'EC2-Classic')
                    })

        except Exception as e:
            logger.error(f"Error finding unused security groups: {str(e)}")

        return unused_sgs

    def analyze_eip_usage(self) -> List[Dict]:
        """Analyze Elastic IP usage and costs"""
        unused_eips = []

        try:
            eips = self.ec2.describe_addresses()['Addresses']

            for eip in eips:
                if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip:
                    # Calculate cost (approximately $0.005 per hour when not attached)
                    hours_per_month = 24 * 30
                    monthly_cost = hours_per_month * 0.005

                    unused_eips.append({
                        'AllocationId': eip['AllocationId'],
                        'PublicIp': eip['PublicIp'],
                        'Domain': eip['Domain'],
                        'EstimatedMonthlyCost': round(monthly_cost, 2)
                    })

        except Exception as e:
            logger.error(f"Error analyzing EIP usage: {str(e)}")

        return unused_eips

    def check_guardduty_usage(self) -> Dict:
        """Check GuardDuty usage and optimization opportunities"""
        guardduty_analysis = {
            'enabled_detectors': [],
            'cost_analysis': {},
            'recommendations': []
        }

        try:
            detectors = self.guardduty.list_detectors()['DetectorIds']

            for detector_id in detectors:
                detector = self.guardduty.get_detector(DetectorId=detector_id)

                guardduty_analysis['enabled_detectors'].append({
                    'DetectorId': detector_id,
                    'Status': detector['Status'],
                    'FindingPublishingFrequency': detector.get('FindingPublishingFrequency'),
                    'DataSources': detector.get('DataSources', {})
                })

                # Check finding frequency for cost optimization
                if detector.get('FindingPublishingFrequency') == 'FIFTEEN_MINUTES':
                    guardduty_analysis['recommendations'].append({
                        'type': 'cost_optimization',
                        'detector_id': detector_id,
                        'recommendation': 'Consider changing finding frequency to SIX_HOURS for cost savings'
                    })

        except Exception as e:
            logger.error(f"Error checking GuardDuty usage: {str(e)}")

        return guardduty_analysis

    def analyze_cloudwatch_logs_retention(self) -> List[Dict]:
        """Analyze CloudWatch Logs retention policies"""
        log_groups_analysis = []

        try:
            paginator = self.cloudwatch.get_paginator('describe_log_groups')

            for page in paginator.paginate():
                for log_group in page['logGroups']:
                    retention_days = log_group.get('retentionInDays')

                    # Check if retention is too long for security logs
                    if retention_days is None or retention_days > 365:
                        estimated_size_mb = log_group.get('storedBytes', 0) / (1024 * 1024)
                        # Rough cost calculation: $0.50 per GB per month
                        estimated_monthly_cost = (estimated_size_mb / 1024) * 0.50

                        log_groups_analysis.append({
                            'logGroupName': log_group['logGroupName'],
                            'retentionInDays': retention_days,
                            'storedMB': round(estimated_size_mb, 2),
                            'estimatedMonthlyCost': round(estimated_monthly_cost, 2),
                            'recommendation': 'Consider setting appropriate retention period'
                        })

        except Exception as e:
            logger.error(f"Error analyzing CloudWatch logs: {str(e)}")

        return log_groups_analysis

    def find_oversized_ebs_volumes(self) -> List[Dict]:
        """Find potentially oversized EBS volumes"""
        oversized_volumes = []

        try:
            volumes = self.ec2.describe_volumes()['Volumes']

            for volume in volumes:
                if volume['State'] == 'in-use':
                    # Get CloudWatch metrics for volume utilization
                    try:
                        end_time = datetime.now()
                        start_time = end_time - timedelta(days=7)

                        # This is a simplified check - in practice, you'd check actual utilization
                        if volume['Size'] > 100:  # Volumes larger than 100GB
                            oversized_volumes.append({
                                'VolumeId': volume['VolumeId'],
                                'Size': volume['Size'],
                                'VolumeType': volume['VolumeType'],
                                'State': volume['State'],
                                'InstanceId': volume.get('Attachments', [{}])[0].get('InstanceId'),
                                'recommendation': 'Review if full capacity is needed'
                            })

                    except Exception as e:
                        logger.warning(f"Could not get metrics for volume {volume['VolumeId']}: {str(e)}")

        except Exception as e:
            logger.error(f"Error finding oversized volumes: {str(e)}")

        return oversized_volumes

    def generate_cost_optimization_report(self) -> Dict:
        """Generate comprehensive cost optimization report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'Security Cost Optimization',
            'findings': {
                'unused_security_groups': self.find_unused_security_groups(),
                'unused_elastic_ips': self.analyze_eip_usage(),
                'guardduty_analysis': self.check_guardduty_usage(),
                'cloudwatch_logs': self.analyze_cloudwatch_logs_retention(),
                'oversized_volumes': self.find_oversized_ebs_volumes()
            },
            'summary': {
                'total_potential_savings': 0,
                'optimization_opportunities': 0
            }
        }

        # Calculate potential savings
        eip_savings = sum(eip['EstimatedMonthlyCost'] for eip in report['findings']['unused_elastic_ips'])
        log_savings = sum(log['estimatedMonthlyCost'] for log in report['findings']['cloudwatch_logs'])

        report['summary']['total_potential_savings'] = round(eip_savings + log_savings, 2)
        report['summary']['optimization_opportunities'] = (
            len(report['findings']['unused_security_groups']) +
            len(report['findings']['unused_elastic_ips']) +
            len(report['findings']['cloudwatch_logs']) +
            len(report['findings']['oversized_volumes'])
        )

        return report

def main():
    optimizer = SecurityCostOptimizer()
    report = optimizer.generate_cost_optimization_report()

    print(json.dumps(report, indent=2, default=str))

    # Save report
    filename = f"security_cost_optimization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"Cost optimization analysis complete. Potential monthly savings: ${report['summary']['total_potential_savings']}")

if __name__ == "__main__":
    main()