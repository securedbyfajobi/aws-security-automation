#!/usr/bin/env python3
"""
Advanced Alerting and Monitoring System for AWS Security Automation
Provides intelligent alerting with statistical anomaly detection and correlation
"""

import os
import sys
import json
import yaml
import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

import boto3
import numpy as np
import pandas as pd
from sklearn.cluster import IsolationForest
from sklearn.preprocessing import StandardScaler
import requests
from botocore.exceptions import ClientError


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    title: str
    description: str
    severity: str
    source: str
    resource_type: str
    resource_id: str
    region: str
    tags: Dict[str, str]
    created_at: str
    updated_at: str
    status: str
    correlation_id: Optional[str] = None
    anomaly_score: Optional[float] = None
    false_positive_probability: Optional[float] = None


@dataclass
class MetricData:
    """Metric data structure"""
    name: str
    value: float
    timestamp: str
    dimensions: Dict[str, str]
    unit: str


class AdvancedAlertingSystem:
    """Advanced alerting system with statistical correlation and deduplication"""

    def __init__(self, config_path: str = "/etc/security-automation/config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.aws_session = boto3.Session(
            region_name=self.config.get('aws', {}).get('region', 'eu-west-2')
        )
        self.db_path = "/var/lib/security-automation/alerts.db"
        self._init_database()
        self.isolation_forest = None
        self.scaler = StandardScaler()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'aws': {'region': 'eu-west-2'},
            'alerting': {
                'enable_correlation': True,
                'enable_anomaly_detection': True,
                'deduplication_window': 300,  # 5 minutes
                'correlation_threshold': 0.8,
                'anomaly_threshold': 0.3
            },
            'channels': {
                'slack': {
                    'enabled': True,
                    'webhook_url': os.environ.get('SLACK_WEBHOOK'),
                    'channel': '#security-alerts'
                },
                'pagerduty': {
                    'enabled': False,
                    'service_key': os.environ.get('PAGERDUTY_SERVICE_KEY')
                },
                'sns': {
                    'enabled': True,
                    'topic_arn': os.environ.get('SNS_TOPIC_ARN')
                },
                'email': {
                    'enabled': True,
                    'smtp_server': os.environ.get('SMTP_SERVER', 'localhost'),
                    'recipients': ['security-team@company.com']
                }
            }
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/security-automation/alerting.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def _init_database(self):
        """Initialize SQLite database for alert storage"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                region TEXT,
                tags TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                correlation_id TEXT,
                anomaly_score REAL,
                false_positive_probability REAL
            )
        ''')

        # Create metrics table for statistical analysis
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value REAL NOT NULL,
                timestamp TEXT NOT NULL,
                dimensions TEXT,
                unit TEXT
            )
        ''')

        conn.commit()
        conn.close()

    async def process_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Process incoming alert with statistical correlation and deduplication"""
        self.logger.info(f"Processing alert: {alert_data.get('title', 'Unknown')}")

        # Create alert object
        alert = Alert(
            id=alert_data.get('id', f"alert-{datetime.now().isoformat()}"),
            title=alert_data['title'],
            description=alert_data.get('description', ''),
            severity=alert_data.get('severity', 'MEDIUM'),
            source=alert_data.get('source', 'unknown'),
            resource_type=alert_data.get('resource_type', 'unknown'),
            resource_id=alert_data.get('resource_id', 'unknown'),
            region=alert_data.get('region', self.aws_session.region_name),
            tags=alert_data.get('tags', {}),
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            status='open'
        )

        # Check for duplicates
        if await self._is_duplicate_alert(alert):
            self.logger.info(f"Duplicate alert detected, updating existing: {alert.id}")
            return await self._update_existing_alert(alert)

        # Perform anomaly detection
        if self.config['alerting'].get('enable_anomaly_detection', True):
            alert.anomaly_score = await self._calculate_anomaly_score(alert)

        # Perform correlation analysis
        if self.config['alerting'].get('enable_correlation', True):
            alert.correlation_id = await self._find_correlated_alerts(alert)

        # Calculate false positive probability
        alert.false_positive_probability = await self._calculate_false_positive_probability(alert)

        # Store alert in database
        await self._store_alert(alert)

        # Send notifications based on severity and probability
        if await self._should_send_notification(alert):
            await self._send_notifications(alert)

        return alert

    async def _is_duplicate_alert(self, alert: Alert) -> bool:
        """Check if alert is a duplicate within deduplication window"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check for similar alerts in the last 5 minutes
        window_start = (datetime.now() - timedelta(
            seconds=self.config['alerting'].get('deduplication_window', 300)
        )).isoformat()

        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE resource_id = ? AND source = ? AND severity = ?
            AND created_at > ? AND status = 'open'
        ''', (alert.resource_id, alert.source, alert.severity, window_start))

        count = cursor.fetchone()[0]
        conn.close()

        return count > 0

    async def _calculate_anomaly_score(self, alert: Alert) -> float:
        """Calculate anomaly score using isolation forest"""
        try:
            # Get historical alert data for training
            historical_data = await self._get_historical_alert_features()

            if len(historical_data) < 50:  # Need minimum data for training
                return 0.5  # Default score

            # Initialize isolation forest if not already done
            if self.isolation_forest is None:
                self.isolation_forest = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                scaled_data = self.scaler.fit_transform(historical_data)
                self.isolation_forest.fit(scaled_data)

            # Calculate anomaly score for current alert
            alert_features = self._extract_alert_features(alert)
            scaled_features = self.scaler.transform([alert_features])
            anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]

            # Normalize score to 0-1 range (0 = anomaly, 1 = normal)
            normalized_score = (anomaly_score + 0.5) / 1.0
            return max(0.0, min(1.0, normalized_score))

        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return 0.5

    async def _find_correlated_alerts(self, alert: Alert) -> Optional[str]:
        """Find correlated alerts using statistical clustering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get recent alerts for correlation analysis
        lookback_time = (datetime.now() - timedelta(hours=1)).isoformat()

        cursor.execute('''
            SELECT * FROM alerts
            WHERE created_at > ? AND status = 'open'
            ORDER BY created_at DESC
        ''', (lookback_time,))

        recent_alerts = cursor.fetchall()
        conn.close()

        if len(recent_alerts) < 2:
            return None

        try:
            # Extract features and perform clustering
            features = []
            alert_ids = []

            for alert_row in recent_alerts:
                features.append(self._extract_correlation_features(alert_row))
                alert_ids.append(alert_row[0])  # alert id

            # Add current alert
            features.append(self._extract_correlation_features_from_alert(alert))
            alert_ids.append(alert.id)

            # Perform clustering
            from sklearn.cluster import DBSCAN
            clustering = DBSCAN(eps=0.3, min_samples=2)
            clusters = clustering.fit_predict(features)

            # Find correlation ID for current alert
            current_cluster = clusters[-1]
            if current_cluster != -1:  # -1 means noise/no cluster
                # Find other alerts in the same cluster
                correlated_alerts = [alert_ids[i] for i, cluster in enumerate(clusters[:-1])
                                   if cluster == current_cluster]

                if correlated_alerts:
                    return f"correlation-{current_cluster}-{datetime.now().strftime('%Y%m%d')}"

        except Exception as e:
            self.logger.error(f"Correlation analysis failed: {e}")

        return None

    async def _calculate_false_positive_probability(self, alert: Alert) -> float:
        """Calculate probability that alert is a false positive"""
        try:
            # Simple heuristic-based calculation
            # In production, this would use a sophisticated statistical model

            base_probability = 0.1  # Base 10% false positive rate

            # Adjust based on source reliability
            source_reliability = {
                'guardduty': 0.95,
                'securityhub': 0.90,
                'inspector': 0.85,
                'custom': 0.70
            }

            reliability = source_reliability.get(alert.source.lower(), 0.75)
            adjusted_probability = base_probability * (1 - reliability)

            # Adjust based on severity
            severity_weights = {
                'CRITICAL': 0.5,
                'HIGH': 0.7,
                'MEDIUM': 0.9,
                'LOW': 1.2
            }

            severity_weight = severity_weights.get(alert.severity, 1.0)
            final_probability = adjusted_probability * severity_weight

            return min(0.9, max(0.01, final_probability))

        except Exception as e:
            self.logger.error(f"False positive calculation failed: {e}")
            return 0.1

    async def _should_send_notification(self, alert: Alert) -> bool:
        """Determine if notification should be sent based on alert properties"""
        # Don't send notifications for high false positive probability
        if alert.false_positive_probability and alert.false_positive_probability > 0.8:
            return False

        # Always send critical alerts
        if alert.severity == 'CRITICAL':
            return True

        # Send high severity if not likely false positive
        if alert.severity == 'HIGH' and (
            not alert.false_positive_probability or alert.false_positive_probability < 0.5
        ):
            return True

        # Send medium severity if anomalous and not likely false positive
        if alert.severity == 'MEDIUM' and alert.anomaly_score and alert.anomaly_score < 0.3:
            return True

        return False

    async def _send_notifications(self, alert: Alert):
        """Send notifications through configured channels"""
        self.logger.info(f"Sending notifications for alert: {alert.id}")

        notification_tasks = []

        # Slack notification
        if self.config['channels']['slack']['enabled']:
            notification_tasks.append(self._send_slack_notification(alert))

        # SNS notification
        if self.config['channels']['sns']['enabled']:
            notification_tasks.append(self._send_sns_notification(alert))

        # PagerDuty notification (for critical alerts only)
        if (self.config['channels']['pagerduty']['enabled'] and
            alert.severity == 'CRITICAL'):
            notification_tasks.append(self._send_pagerduty_notification(alert))

        # Email notification
        if self.config['channels']['email']['enabled']:
            notification_tasks.append(self._send_email_notification(alert))

        # Execute all notifications concurrently
        await asyncio.gather(*notification_tasks, return_exceptions=True)

    async def _send_slack_notification(self, alert: Alert):
        """Send Slack notification"""
        try:
            webhook_url = self.config['channels']['slack']['webhook_url']
            if not webhook_url:
                return

            color_map = {
                'CRITICAL': '#FF0000',
                'HIGH': '#FF8C00',
                'MEDIUM': '#FFD700',
                'LOW': '#32CD32'
            }

            payload = {
                "channel": self.config['channels']['slack']['channel'],
                "username": "SecurityBot",
                "icon_emoji": ":shield:",
                "attachments": [
                    {
                        "color": color_map.get(alert.severity, '#808080'),
                        "title": f"🚨 {alert.severity} Security Alert",
                        "title_link": f"https://console.aws.amazon.com/",
                        "text": alert.description,
                        "fields": [
                            {
                                "title": "Resource",
                                "value": f"{alert.resource_type}: {alert.resource_id}",
                                "short": True
                            },
                            {
                                "title": "Region",
                                "value": alert.region,
                                "short": True
                            },
                            {
                                "title": "Source",
                                "value": alert.source,
                                "short": True
                            },
                            {
                                "title": "Alert ID",
                                "value": alert.id,
                                "short": True
                            }
                        ],
                        "footer": "AWS Security Automation",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }

            # Add ML insights if available
            if alert.anomaly_score is not None:
                payload["attachments"][0]["fields"].append({
                    "title": "Anomaly Score",
                    "value": f"{alert.anomaly_score:.2f}",
                    "short": True
                })

            if alert.false_positive_probability is not None:
                payload["attachments"][0]["fields"].append({
                    "title": "False Positive Probability",
                    "value": f"{alert.false_positive_probability:.2%}",
                    "short": True
                })

            async with asyncio.get_event_loop().run_in_executor(
                None, requests.post, webhook_url
            ) as response:
                response = requests.post(webhook_url, json=payload, timeout=10)
                response.raise_for_status()

        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")

    async def _send_sns_notification(self, alert: Alert):
        """Send SNS notification"""
        try:
            topic_arn = self.config['channels']['sns']['topic_arn']
            if not topic_arn:
                return

            sns = self.aws_session.client('sns')

            message = {
                'default': f"Security Alert: {alert.title}",
                'sms': f"🚨 {alert.severity}: {alert.title}",
                'email': f"""
Security Alert Details:

Title: {alert.title}
Severity: {alert.severity}
Description: {alert.description}
Resource: {alert.resource_type} - {alert.resource_id}
Region: {alert.region}
Source: {alert.source}
Time: {alert.created_at}
Alert ID: {alert.id}

{'Anomaly Score: ' + str(alert.anomaly_score) if alert.anomaly_score else ''}
{'False Positive Probability: ' + f'{alert.false_positive_probability:.2%}' if alert.false_positive_probability else ''}

Please investigate immediately.
                """
            }

            sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
                MessageStructure='json',
                Subject=f"🚨 {alert.severity} Security Alert: {alert.title}"
            )

        except ClientError as e:
            self.logger.error(f"Failed to send SNS notification: {e}")

    async def generate_alert_dashboard(self) -> Dict[str, Any]:
        """Generate real-time alert dashboard data"""
        conn = sqlite3.connect(self.db_path)

        # Get alert statistics
        stats_query = '''
            SELECT
                severity,
                COUNT(*) as count,
                AVG(CASE WHEN anomaly_score IS NOT NULL THEN anomaly_score END) as avg_anomaly_score,
                AVG(CASE WHEN false_positive_probability IS NOT NULL THEN false_positive_probability END) as avg_fp_probability
            FROM alerts
            WHERE created_at > datetime('now', '-24 hours')
            GROUP BY severity
        '''

        df_stats = pd.read_sql_query(stats_query, conn)

        # Get trend data
        trend_query = '''
            SELECT
                DATE(created_at) as date,
                COUNT(*) as alert_count,
                severity
            FROM alerts
            WHERE created_at > datetime('now', '-30 days')
            GROUP BY DATE(created_at), severity
            ORDER BY date
        '''

        df_trend = pd.read_sql_query(trend_query, conn)
        conn.close()

        return {
            'statistics': df_stats.to_dict('records'),
            'trends': df_trend.to_dict('records'),
            'generated_at': datetime.now().isoformat()
        }

    # Helper methods for statistical feature extraction
    def _extract_alert_features(self, alert: Alert) -> List[float]:
        """Extract numerical features from alert for statistical processing"""
        severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

        return [
            severity_map.get(alert.severity, 0),
            hash(alert.source) % 1000,
            hash(alert.resource_type) % 1000,
            hash(alert.region) % 100,
            len(alert.description),
            len(alert.tags)
        ]

    async def get_alert_metrics(self) -> Dict[str, Any]:
        """Get alert metrics for monitoring dashboard"""
        conn = sqlite3.connect(self.db_path)

        metrics = {}

        # Total alerts in last 24 hours
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE created_at > datetime('now', '-24 hours')
        ''')
        metrics['alerts_24h'] = cursor.fetchone()[0]

        # Critical alerts
        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE severity = 'CRITICAL' AND status = 'open'
        ''')
        metrics['critical_open'] = cursor.fetchone()[0]

        # Average anomaly score
        cursor.execute('''
            SELECT AVG(anomaly_score) FROM alerts
            WHERE anomaly_score IS NOT NULL
            AND created_at > datetime('now', '-24 hours')
        ''')
        result = cursor.fetchone()[0]
        metrics['avg_anomaly_score'] = result if result else 0.0

        conn.close()
        return metrics


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Alerting System")
    parser.add_argument("--test-alert", action="store_true", help="Send test alert")
    parser.add_argument("--dashboard", action="store_true", help="Generate dashboard")
    args = parser.parse_args()

    alerting_system = AdvancedAlertingSystem()

    if args.test_alert:
        # Send test alert
        test_alert = {
            'title': 'Test Security Alert',
            'description': 'This is a test alert from the advanced alerting system',
            'severity': 'HIGH',
            'source': 'test',
            'resource_type': 'EC2Instance',
            'resource_id': 'i-1234567890abcdef0',
            'region': 'eu-west-2'
        }

        loop = asyncio.get_event_loop()
        alert = loop.run_until_complete(alerting_system.process_alert(test_alert))
        print(f"Test alert processed: {alert.id}")

    elif args.dashboard:
        # Generate dashboard
        loop = asyncio.get_event_loop()
        dashboard = loop.run_until_complete(alerting_system.generate_alert_dashboard())
        print(json.dumps(dashboard, indent=2))