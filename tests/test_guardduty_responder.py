"""Unit tests for GuardDuty responder module."""
import pytest
from unittest.mock import patch, MagicMock
import json
from guardduty_automation.guardduty_responder import (
    GuardDutyResponder,
    process_finding,
    send_slack_notification,
    remediate_finding
)


class TestGuardDutyResponder:
    """Test class for GuardDuty responder functionality."""

    def test_init(self, guardduty_client, test_config):
        """Test GuardDuty responder initialization."""
        responder = GuardDutyResponder(guardduty_client, test_config)
        assert responder.client == guardduty_client
        assert responder.config == test_config

    def test_process_finding_high_severity(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test processing high severity finding."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        with patch.object(responder, 'send_notification') as mock_notify:
            with patch.object(responder, 'remediate_finding') as mock_remediate:
                result = responder.process_finding(sample_guardduty_finding)

                assert result['status'] == 'processed'
                assert result['severity'] == 'HIGH'
                mock_notify.assert_called_once()
                # Remediation should be called for high severity findings
                mock_remediate.assert_called_once()

    def test_process_finding_low_severity(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test processing low severity finding."""
        # Modify finding to be low severity
        low_severity_finding = sample_guardduty_finding.copy()
        low_severity_finding['Severity'] = 2.0

        responder = GuardDutyResponder(guardduty_client, test_config)

        with patch.object(responder, 'send_notification') as mock_notify:
            with patch.object(responder, 'remediate_finding') as mock_remediate:
                result = responder.process_finding(low_severity_finding)

                assert result['status'] == 'processed'
                assert result['severity'] == 'LOW'
                # Low severity should still notify but not remediate
                mock_notify.assert_called_once()
                mock_remediate.assert_not_called()

    @patch('requests.post')
    def test_send_slack_notification(self, mock_post, guardduty_client, test_config, sample_guardduty_finding):
        """Test Slack notification sending."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = 'ok'

        responder = GuardDutyResponder(guardduty_client, test_config)
        result = responder.send_slack_notification(sample_guardduty_finding)

        assert result is True
        mock_post.assert_called_once()

        # Verify the request was made with correct data
        call_args = mock_post.call_args
        assert call_args[1]['json']['text'] is not None
        assert 'Bitcoin mining' in call_args[1]['json']['text']

    @patch('requests.post')
    def test_send_slack_notification_failure(self, mock_post, guardduty_client, test_config, sample_guardduty_finding):
        """Test Slack notification failure handling."""
        mock_post.return_value.status_code = 500
        mock_post.side_effect = Exception("Network error")

        responder = GuardDutyResponder(guardduty_client, test_config)
        result = responder.send_slack_notification(sample_guardduty_finding)

        assert result is False

    def test_categorize_severity(self, guardduty_client, test_config):
        """Test severity categorization."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        assert responder.categorize_severity(9.0) == 'CRITICAL'
        assert responder.categorize_severity(7.5) == 'HIGH'
        assert responder.categorize_severity(5.0) == 'MEDIUM'
        assert responder.categorize_severity(2.0) == 'LOW'
        assert responder.categorize_severity(0.1) == 'INFORMATIONAL'

    def test_should_auto_remediate(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test auto-remediation decision logic."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        # High severity cryptocurrency finding should be auto-remediated
        assert responder.should_auto_remediate(sample_guardduty_finding) is False  # Config has auto-remediation disabled

        # Enable auto-remediation in config
        config_with_auto = test_config.copy()
        config_with_auto['security_settings']['guardduty']['auto_remediation']['enabled'] = True
        responder_auto = GuardDutyResponder(guardduty_client, config_with_auto)

        assert responder_auto.should_auto_remediate(sample_guardduty_finding) is True

    def test_format_slack_message(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test Slack message formatting."""
        responder = GuardDutyResponder(guardduty_client, test_config)
        message = responder.format_slack_message(sample_guardduty_finding)

        assert isinstance(message, dict)
        assert 'text' in message
        assert 'Bitcoin mining' in message['text']
        assert 'HIGH' in message['text']
        assert 'eu-west-2' in message['text']

    @patch('boto3.client')
    def test_isolate_instance(self, mock_boto_client, guardduty_client, test_config, sample_guardduty_finding):
        """Test EC2 instance isolation."""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        responder = GuardDutyResponder(guardduty_client, test_config)
        result = responder.isolate_instance(sample_guardduty_finding)

        assert result['action'] == 'isolate_instance'
        assert result['instance_id'] == 'i-1234567890abcdef0'

        # Verify EC2 API calls were made
        mock_ec2.describe_instances.assert_called_once()
        mock_ec2.modify_instance_attribute.assert_called()

    def test_extract_instance_id(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test instance ID extraction from finding."""
        responder = GuardDutyResponder(guardduty_client, test_config)
        instance_id = responder.extract_instance_id(sample_guardduty_finding)

        assert instance_id == 'i-1234567890abcdef0'

    def test_extract_instance_id_missing(self, guardduty_client, test_config):
        """Test instance ID extraction when missing."""
        finding_without_instance = {
            'Resource': {}
        }

        responder = GuardDutyResponder(guardduty_client, test_config)
        instance_id = responder.extract_instance_id(finding_without_instance)

        assert instance_id is None

    def test_create_security_group(self, guardduty_client, test_config):
        """Test quarantine security group creation."""
        with patch('boto3.client') as mock_boto:
            mock_ec2 = MagicMock()
            mock_boto.return_value = mock_ec2
            mock_ec2.create_security_group.return_value = {'GroupId': 'sg-quarantine123'}

            responder = GuardDutyResponder(guardduty_client, test_config)
            sg_id = responder.create_quarantine_security_group('vpc-123')

            assert sg_id == 'sg-quarantine123'
            mock_ec2.create_security_group.assert_called_once()

    @pytest.mark.parametrize("finding_type,expected_action", [
        ("CryptoCurrency:EC2/BitcoinTool.B!DNS", "isolate_instance"),
        ("UnauthorizedAPICall:IAMUser/InstanceLaunchUnusual", "disable_user"),
        ("Stealth:IAMUser/CloudTrailLoggingDisabled", "enable_cloudtrail"),
        ("Backdoor:EC2/C&CActivity.B!DNS", "isolate_instance"),
    ])
    def test_determine_remediation_action(self, finding_type, expected_action, guardduty_client, test_config):
        """Test remediation action determination based on finding type."""
        responder = GuardDutyResponder(guardduty_client, test_config)
        action = responder.determine_remediation_action(finding_type)

        assert action == expected_action

    def test_validate_finding_format(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test finding format validation."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        # Valid finding
        assert responder.validate_finding(sample_guardduty_finding) is True

        # Invalid finding - missing required fields
        invalid_finding = {'Id': 'test-id'}
        assert responder.validate_finding(invalid_finding) is False

    def test_finding_age_calculation(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test calculation of finding age."""
        responder = GuardDutyResponder(guardduty_client, test_config)
        age = responder.calculate_finding_age(sample_guardduty_finding)

        # Age should be in hours and greater than 0
        assert isinstance(age, float)
        assert age >= 0

    def test_error_handling_invalid_json(self, guardduty_client, test_config):
        """Test error handling for invalid JSON input."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        with pytest.raises(json.JSONDecodeError):
            responder.process_event_string("invalid json")

    def test_metric_tracking(self, guardduty_client, test_config, sample_guardduty_finding):
        """Test metric tracking functionality."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        with patch.object(responder, 'send_metric') as mock_metric:
            responder.process_finding(sample_guardduty_finding)

            # Verify metrics were sent
            mock_metric.assert_called()

    @pytest.mark.integration
    def test_end_to_end_processing(self, guardduty_client, test_config, sample_guardduty_finding):
        """Integration test for end-to-end finding processing."""
        responder = GuardDutyResponder(guardduty_client, test_config)

        with patch.multiple(responder,
                           send_slack_notification=MagicMock(return_value=True),
                           remediate_finding=MagicMock(return_value={'status': 'success'}),
                           send_metric=MagicMock()):

            result = responder.process_finding(sample_guardduty_finding)

            assert result['status'] == 'processed'
            assert 'finding_id' in result
            assert 'processing_time' in result


# Standalone function tests
def test_process_finding_function(sample_guardduty_finding):
    """Test standalone process_finding function."""
    event = {
        'detail': sample_guardduty_finding
    }

    with patch('guardduty_automation.guardduty_responder.GuardDutyResponder') as mock_responder:
        mock_instance = MagicMock()
        mock_responder.return_value = mock_instance
        mock_instance.process_finding.return_value = {'status': 'success'}

        result = process_finding(event, None)

        assert result['statusCode'] == 200
        mock_instance.process_finding.assert_called_once()


def test_send_slack_notification_function():
    """Test standalone Slack notification function."""
    webhook_url = "https://hooks.slack.com/test"
    message = "Test message"

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200

        result = send_slack_notification(webhook_url, message)

        assert result is True
        mock_post.assert_called_once()