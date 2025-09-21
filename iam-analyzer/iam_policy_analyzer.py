#!/usr/bin/env python3
"""
IAM Policy Analyzer
Analyzes IAM policies for security risks and compliance issues
"""

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Set

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IAMPolicyAnalyzer:
    """Analyze IAM policies for security risks"""

    def __init__(self):
        self.iam = boto3.client('iam')
        self.high_risk_actions = {
            'iam:*', 'iam:PassRole', 'iam:CreateRole', 'iam:AttachRolePolicy',
            's3:*', 's3:GetBucketPolicy', 's3:PutBucketPolicy',
            'ec2:*', 'ec2:RunInstances', 'ec2:TerminateInstances',
            'lambda:*', 'lambda:InvokeFunction', 'lambda:UpdateFunctionCode'
        }

    def analyze_policy_document(self, policy_doc: Dict) -> Dict:
        """Analyze a single policy document for risks"""
        risks = {
            'high_risk_actions': [],
            'wildcard_resources': [],
            'public_access': [],
            'privilege_escalation': [],
            'admin_access': False
        }

        for statement in policy_doc.get('Statement', []):
            # Check for high-risk actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if action in self.high_risk_actions or action.endswith(':*'):
                    risks['high_risk_actions'].append(action)

                # Check for admin access
                if action == '*':
                    risks['admin_access'] = True

            # Check for wildcard resources
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            for resource in resources:
                if resource == '*':
                    risks['wildcard_resources'].append(resource)

            # Check for public access
            principal = statement.get('Principal', {})
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                risks['public_access'].append(statement)

            # Check for privilege escalation patterns
            if 'iam:PassRole' in actions and '*' in resources:
                risks['privilege_escalation'].append('iam:PassRole with wildcard resources')

        return risks

    def analyze_user_policies(self) -> List[Dict]:
        """Analyze all user policies"""
        results = []

        try:
            users = self.iam.list_users()['Users']

            for user in users:
                user_analysis = {
                    'user_name': user['UserName'],
                    'user_id': user['UserId'],
                    'inline_policies': [],
                    'attached_policies': [],
                    'total_risks': 0
                }

                # Analyze inline policies
                inline_policies = self.iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
                for policy_name in inline_policies:
                    policy_doc = self.iam.get_user_policy(
                        UserName=user['UserName'],
                        PolicyName=policy_name
                    )['PolicyDocument']

                    risks = self.analyze_policy_document(policy_doc)
                    user_analysis['inline_policies'].append({
                        'policy_name': policy_name,
                        'risks': risks
                    })
                    user_analysis['total_risks'] += sum(len(v) if isinstance(v, list) else (1 if v else 0) for v in risks.values())

                # Analyze attached managed policies
                attached_policies = self.iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                for policy in attached_policies:
                    policy_version = self.iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    policy_doc = self.iam.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=policy_version
                    )['PolicyVersion']['Document']

                    risks = self.analyze_policy_document(policy_doc)
                    user_analysis['attached_policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn'],
                        'risks': risks
                    })
                    user_analysis['total_risks'] += sum(len(v) if isinstance(v, list) else (1 if v else 0) for v in risks.values())

                results.append(user_analysis)

        except Exception as e:
            logger.error(f"Error analyzing user policies: {str(e)}")

        return results

    def analyze_role_policies(self) -> List[Dict]:
        """Analyze all role policies"""
        results = []

        try:
            roles = self.iam.list_roles()['Roles']

            for role in roles:
                role_analysis = {
                    'role_name': role['RoleName'],
                    'role_id': role['RoleId'],
                    'assume_role_policy': None,
                    'inline_policies': [],
                    'attached_policies': [],
                    'total_risks': 0
                }

                # Analyze assume role policy
                assume_policy = role.get('AssumeRolePolicyDocument', {})
                if assume_policy:
                    risks = self.analyze_policy_document(assume_policy)
                    role_analysis['assume_role_policy'] = {
                        'risks': risks
                    }
                    role_analysis['total_risks'] += sum(len(v) if isinstance(v, list) else (1 if v else 0) for v in risks.values())

                # Analyze inline policies
                inline_policies = self.iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
                for policy_name in inline_policies:
                    policy_doc = self.iam.get_role_policy(
                        RoleName=role['RoleName'],
                        PolicyName=policy_name
                    )['PolicyDocument']

                    risks = self.analyze_policy_document(policy_doc)
                    role_analysis['inline_policies'].append({
                        'policy_name': policy_name,
                        'risks': risks
                    })
                    role_analysis['total_risks'] += sum(len(v) if isinstance(v, list) else (1 if v else 0) for v in risks.values())

                results.append(role_analysis)

        except Exception as e:
            logger.error(f"Error analyzing role policies: {str(e)}")

        return results

    def generate_security_report(self) -> Dict:
        """Generate comprehensive IAM security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'IAM Security Analysis',
            'user_analysis': self.analyze_user_policies(),
            'role_analysis': self.analyze_role_policies(),
            'summary': {
                'total_users': 0,
                'total_roles': 0,
                'high_risk_users': 0,
                'high_risk_roles': 0,
                'total_risks_found': 0
            }
        }

        # Calculate summary statistics
        report['summary']['total_users'] = len(report['user_analysis'])
        report['summary']['total_roles'] = len(report['role_analysis'])

        for user in report['user_analysis']:
            if user['total_risks'] > 5:  # Threshold for high risk
                report['summary']['high_risk_users'] += 1
            report['summary']['total_risks_found'] += user['total_risks']

        for role in report['role_analysis']:
            if role['total_risks'] > 3:  # Threshold for high risk roles
                report['summary']['high_risk_roles'] += 1
            report['summary']['total_risks_found'] += role['total_risks']

        return report

def main():
    analyzer = IAMPolicyAnalyzer()
    report = analyzer.generate_security_report()

    print(json.dumps(report, indent=2, default=str))

    # Save report
    filename = f"iam_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"IAM analysis complete: Found {report['summary']['total_risks_found']} security risks")

if __name__ == "__main__":
    main()