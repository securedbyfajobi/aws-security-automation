#!/usr/bin/env python3
"""
CloudTrail Log Analyzer
Real-time analysis of CloudTrail logs for security events
"""

import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CloudTrailAnalyzer:
    """Analyze CloudTrail logs for security events"""

    def __init__(self, region_name: str = 'us-east-1'):
        self.cloudtrail = boto3.client('cloudtrail', region_name=region_name)
        self.logs = boto3.client('logs', region_name=region_name)

        # Define suspicious activities
        self.suspicious_events = {
            'privilege_escalation': [
                'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole',
                'PutUserPolicy', 'PutRolePolicy', 'AddUserToGroup'
            ],
            'data_exfiltration': [
                'GetObject', 'CopyObject', 'CreatePresignedUrl',
                'GetSecretValue', 'GetParameter'
            ],
            'infrastructure_changes': [
                'RunInstances', 'TerminateInstances', 'CreateSecurityGroup',
                'AuthorizeSecurityGroupIngress', 'DeleteSecurityGroup'
            ],
            'access_pattern_changes': [
                'CreateAccessKey', 'UpdateAccessKey', 'DeleteAccessKey',
                'CreateLoginProfile', 'UpdateLoginProfile'
            ]
        }

    def analyze_recent_events(self, hours_back: int = 24) -> Dict:
        """Analyze CloudTrail events from the last N hours"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours_back)

        analysis_results = {
            'analysis_period': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'hours_analyzed': hours_back
            },
            'events_analyzed': 0,
            'suspicious_activities': {
                'privilege_escalation': [],
                'data_exfiltration': [],
                'infrastructure_changes': [],
                'access_pattern_changes': []
            },
            'user_activity_summary': {},
            'failed_operations': [],
            'console_logins': []
        }

        try:
            # Look up CloudTrail events
            events = self.cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxItems=1000  # Adjust based on needs
            )

            for event in events['Events']:
                analysis_results['events_analyzed'] += 1
                event_name = event['EventName']
                username = event.get('Username', 'Unknown')

                # Track user activity
                if username not in analysis_results['user_activity_summary']:
                    analysis_results['user_activity_summary'][username] = {
                        'event_count': 0,
                        'event_types': set(),
                        'source_ips': set(),
                        'error_count': 0
                    }

                user_summary = analysis_results['user_activity_summary'][username]
                user_summary['event_count'] += 1
                user_summary['event_types'].add(event_name)

                # Extract source IP if available
                if 'SourceIPAddress' in event:
                    user_summary['source_ips'].add(event['SourceIPAddress'])

                # Check for errors
                if event.get('ErrorCode'):
                    user_summary['error_count'] += 1
                    analysis_results['failed_operations'].append({
                        'event_name': event_name,
                        'username': username,
                        'error_code': event.get('ErrorCode'),
                        'error_message': event.get('ErrorMessage'),
                        'event_time': event['EventTime'].isoformat(),
                        'source_ip': event.get('SourceIPAddress')
                    })

                # Check for console logins
                if event_name == 'ConsoleLogin':
                    analysis_results['console_logins'].append({
                        'username': username,
                        'source_ip': event.get('SourceIPAddress'),
                        'event_time': event['EventTime'].isoformat(),
                        'response_elements': event.get('ResponseElements', {})
                    })

                # Categorize suspicious activities
                for category, event_types in self.suspicious_events.items():
                    if event_name in event_types:
                        analysis_results['suspicious_activities'][category].append({
                            'event_name': event_name,
                            'username': username,
                            'event_time': event['EventTime'].isoformat(),
                            'source_ip': event.get('SourceIPAddress'),
                            'resources': [r.get('ResourceName', r.get('ResourceType', 'Unknown'))
                                        for r in event.get('Resources', [])]
                        })

            # Convert sets to lists for JSON serialization
            for user, summary in analysis_results['user_activity_summary'].items():
                summary['event_types'] = list(summary['event_types'])
                summary['source_ips'] = list(summary['source_ips'])

        except Exception as e:
            logger.error(f"Error analyzing CloudTrail events: {str(e)}")

        return analysis_results

    def detect_anomalous_behavior(self, analysis_results: Dict) -> List[Dict]:
        """Detect anomalous behavior patterns"""
        anomalies = []

        try:
            for username, activity in analysis_results['user_activity_summary'].items():
                # Check for users with high error rates
                if activity['event_count'] > 10 and activity['error_count'] / activity['event_count'] > 0.3:
                    anomalies.append({
                        'type': 'high_error_rate',
                        'username': username,
                        'description': f"User has {activity['error_count']} errors out of {activity['event_count']} events",
                        'severity': 'medium'
                    })

                # Check for users accessing from multiple IPs
                if len(activity['source_ips']) > 3:
                    anomalies.append({
                        'type': 'multiple_source_ips',
                        'username': username,
                        'description': f"User accessed from {len(activity['source_ips'])} different IP addresses",
                        'source_ips': activity['source_ips'],
                        'severity': 'high'
                    })

                # Check for unusual activity volume
                if activity['event_count'] > 100:
                    anomalies.append({
                        'type': 'high_activity_volume',
                        'username': username,
                        'description': f"User generated {activity['event_count']} events (unusually high)",
                        'severity': 'medium'
                    })

            # Check for multiple failed console logins
            failed_logins = {}
            for login in analysis_results['console_logins']:
                if login.get('response_elements', {}).get('ConsoleLogin') == 'Failure':
                    source_ip = login['source_ip']
                    if source_ip not in failed_logins:
                        failed_logins[source_ip] = 0
                    failed_logins[source_ip] += 1

            for ip, count in failed_logins.items():
                if count > 5:
                    anomalies.append({
                        'type': 'brute_force_attempt',
                        'source_ip': ip,
                        'description': f"Multiple failed console login attempts ({count}) from IP {ip}",
                        'severity': 'critical'
                    })

        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")

        return anomalies

    def generate_security_report(self, hours_back: int = 24) -> Dict:
        """Generate comprehensive CloudTrail security report"""
        analysis = self.analyze_recent_events(hours_back)
        anomalies = self.detect_anomalous_behavior(analysis)

        report = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'CloudTrail Security Analysis',
            'analysis_results': analysis,
            'anomalies_detected': anomalies,
            'summary': {
                'total_events': analysis['events_analyzed'],
                'unique_users': len(analysis['user_activity_summary']),
                'failed_operations': len(analysis['failed_operations']),
                'console_logins': len(analysis['console_logins']),
                'anomalies_found': len(anomalies),
                'high_severity_anomalies': len([a for a in anomalies if a.get('severity') in ['high', 'critical']])
            }
        }

        # Calculate risk score
        risk_factors = [
            report['summary']['high_severity_anomalies'] * 3,
            report['summary']['anomalies_found'],
            len(analysis['suspicious_activities']['privilege_escalation']) * 2,
            len(analysis['suspicious_activities']['data_exfiltration']) * 2
        ]

        report['summary']['risk_score'] = min(sum(risk_factors), 100)  # Cap at 100

        return report

def main():
    analyzer = CloudTrailAnalyzer()
    report = analyzer.generate_security_report(hours_back=24)

    print(json.dumps(report, indent=2, default=str))

    # Save report
    filename = f"cloudtrail_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"CloudTrail analysis complete. Risk score: {report['summary']['risk_score']}/100")

if __name__ == "__main__":
    main()