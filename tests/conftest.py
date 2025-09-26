"""Pytest configuration and shared fixtures."""
import pytest
import boto3
from moto import mock_guardduty, mock_securityhub, mock_iam, mock_s3, mock_sns
from unittest.mock import MagicMock
import os
import sys

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for testing."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'


@pytest.fixture
def guardduty_client(aws_credentials):
    """Mock GuardDuty client."""
    with mock_guardduty():
        yield boto3.client('guardduty', region_name='eu-west-2')


@pytest.fixture
def security_hub_client(aws_credentials):
    """Mock Security Hub client."""
    with mock_securityhub():
        yield boto3.client('securityhub', region_name='eu-west-2')


@pytest.fixture
def iam_client(aws_credentials):
    """Mock IAM client."""
    with mock_iam():
        yield boto3.client('iam', region_name='eu-west-2')


@pytest.fixture
def s3_client(aws_credentials):
    """Mock S3 client."""
    with mock_s3():
        client = boto3.client('s3', region_name='eu-west-2')
        # Create test bucket
        client.create_bucket(
            Bucket='test-security-logs',
            CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}
        )
        yield client


@pytest.fixture
def sns_client(aws_credentials):
    """Mock SNS client."""
    with mock_sns():
        yield boto3.client('sns', region_name='eu-west-2')


@pytest.fixture
def sample_guardduty_finding():
    """Sample GuardDuty finding for testing."""
    return {
        'Id': 'test-finding-id-123',
        'Type': 'CryptoCurrency:EC2/BitcoinTool.B!DNS',
        'Region': 'eu-west-2',
        'Severity': 8.8,
        'Title': 'Bitcoin mining activity detected',
        'Description': 'EC2 instance is communicating with a Bitcoin mining pool',
        'Service': {
            'Action': {
                'ActionType': 'DNS_REQUEST',
                'DnsRequestAction': {
                    'Domain': 'pool.bitcoin.com'
                }
            },
            'ResourceRole': 'TARGET'
        },
        'Resource': {
            'InstanceDetails': {
                'InstanceId': 'i-1234567890abcdef0',
                'InstanceType': 't3.micro',
                'Tags': [
                    {
                        'Key': 'Environment',
                        'Value': 'Production'
                    }
                ]
            }
        },
        'CreatedAt': '2024-01-15T10:30:00.000Z',
        'UpdatedAt': '2024-01-15T10:30:00.000Z'
    }


@pytest.fixture
def sample_security_hub_finding():
    """Sample Security Hub finding for testing."""
    return {
        'SchemaVersion': '2018-10-08',
        'Id': 'arn:aws:securityhub:eu-west-2:123456789012:finding/test-finding',
        'ProductArn': 'arn:aws:securityhub:eu-west-2::product/aws/guardduty',
        'GeneratorId': 'GuardDuty',
        'AwsAccountId': '123456789012',
        'Region': 'eu-west-2',
        'Title': 'Bitcoin mining activity detected',
        'Description': 'EC2 instance is communicating with a Bitcoin mining pool',
        'Severity': {
            'Label': 'HIGH',
            'Normalized': 70
        },
        'Confidence': 8,
        'Criticality': 8,
        'Types': [
            'Unusual Behaviors/VM/Malicious Activity'
        ],
        'FirstObservedAt': '2024-01-15T10:30:00.000Z',
        'LastObservedAt': '2024-01-15T10:30:00.000Z',
        'CreatedAt': '2024-01-15T10:30:00.000Z',
        'UpdatedAt': '2024-01-15T10:30:00.000Z',
        'WorkflowState': 'NEW',
        'RecordState': 'ACTIVE',
        'Resources': [
            {
                'Type': 'AwsEc2Instance',
                'Id': 'arn:aws:ec2:eu-west-2:123456789012:instance/i-1234567890abcdef0',
                'Partition': 'aws',
                'Region': 'eu-west-2',
                'Details': {
                    'AwsEc2Instance': {
                        'Type': 't3.micro',
                        'ImageId': 'ami-12345678',
                        'IpV4Addresses': ['10.0.1.100'],
                        'KeyName': 'my-key-pair',
                        'LaunchedAt': '2024-01-01T00:00:00.000Z'
                    }
                }
            }
        ]
    }


@pytest.fixture
def sample_iam_policy():
    """Sample IAM policy for testing."""
    return {
        'PolicyName': 'test-policy',
        'PolicyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': [
                        's3:GetObject',
                        's3:PutObject'
                    ],
                    'Resource': 'arn:aws:s3:::test-bucket/*'
                },
                {
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }
            ]
        }
    }


@pytest.fixture
def mock_slack_webhook():
    """Mock Slack webhook for testing notifications."""
    return MagicMock()


@pytest.fixture
def test_config():
    """Test configuration dictionary."""
    return {
        'aws': {
            'region': 'eu-west-2',
            'profile': 'default'
        },
        'notifications': {
            'slack': {
                'enabled': True,
                'webhook_url': 'https://hooks.slack.com/services/TEST/TEST/TEST',
                'channels': {
                    'critical': '#security-critical',
                    'high': '#security-alerts'
                }
            },
            'email': {
                'enabled': False
            }
        },
        'security_settings': {
            'guardduty': {
                'enabled': True,
                'auto_remediation': {
                    'enabled': False
                }
            }
        }
    }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )