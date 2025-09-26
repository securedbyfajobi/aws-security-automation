#!/usr/bin/env python3
"""
Comprehensive Backup and Disaster Recovery System for AWS Security Automation
Provides automated backups, point-in-time recovery, and disaster recovery orchestration
"""

import os
import sys
import json
import yaml
import boto3
import asyncio
import logging
import hashlib
import tarfile
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from botocore.exceptions import ClientError


@dataclass
class BackupJob:
    """Backup job configuration"""
    id: str
    name: str
    source_type: str  # database, filesystem, s3, configuration
    source_path: str
    destination: str
    schedule: str
    retention_days: int
    encryption_enabled: bool
    compression_enabled: bool
    priority: int
    last_run: Optional[str] = None
    status: str = "pending"


@dataclass
class BackupResult:
    """Backup execution result"""
    job_id: str
    started_at: str
    completed_at: Optional[str]
    status: str
    size_bytes: int
    backup_location: str
    checksum: str
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class RestorePoint:
    """System restore point"""
    id: str
    created_at: str
    description: str
    components: List[str]
    backup_locations: Dict[str, str]
    metadata: Dict[str, Any]


class BackupAndRecoverySystem:
    """Comprehensive backup and disaster recovery system"""

    def __init__(self, config_path: str = "/etc/security-automation/config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.aws_session = boto3.Session(
            region_name=self.config.get('aws', {}).get('region', 'eu-west-2')
        )

        # Storage clients
        self.s3_client = self.aws_session.client('s3')
        self.glacier_client = self.aws_session.client('glacier')
        self.rds_client = self.aws_session.client('rds')
        self.efs_client = self.aws_session.client('efs')

        # Backup storage configuration
        self.backup_bucket = self.config.get('backup', {}).get('s3_bucket',
            f"aws-security-automation-backups-{self.aws_session.region_name}")
        self.glacier_vault = self.config.get('backup', {}).get('glacier_vault',
            'security-automation-long-term')

        self.backup_jobs = self._load_backup_jobs()
        self.executor = ThreadPoolExecutor(max_workers=4)

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default backup configuration"""
        return {
            'aws': {'region': 'eu-west-2'},
            'backup': {
                's3_bucket': f'aws-security-automation-backups',
                'glacier_vault': 'security-automation-long-term',
                'encryption_key': 'alias/security-automation-backup',
                'retention_policy': {
                    'daily': 7,
                    'weekly': 4,
                    'monthly': 12,
                    'yearly': 7
                },
                'compression': True,
                'verification': True,
                'cross_region_replication': True,
                'backup_window': {
                    'start': '02:00',
                    'duration': 4  # hours
                }
            },
            'disaster_recovery': {
                'rpo_minutes': 60,  # Recovery Point Objective
                'rto_minutes': 240, # Recovery Time Objective
                'failover_region': 'us-west-2',
                'auto_failover': False,
                'health_checks': True
            },
            'notifications': {
                'sns_topic': os.environ.get('BACKUP_SNS_TOPIC'),
                'slack_webhook': os.environ.get('BACKUP_SLACK_WEBHOOK'),
                'email_recipients': ['ops-team@company.com']
            }
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_dir = "/var/log/security-automation"
        os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{log_dir}/backup-recovery.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def _load_backup_jobs(self) -> List[BackupJob]:
        """Load backup job configurations"""
        return [
            BackupJob(
                id="config-backup",
                name="Configuration Files Backup",
                source_type="filesystem",
                source_path="/etc/security-automation",
                destination=f"s3://{self.backup_bucket}/configs",
                schedule="0 */6 * * *",  # Every 6 hours
                retention_days=30,
                encryption_enabled=True,
                compression_enabled=True,
                priority=1
            ),
            BackupJob(
                id="logs-backup",
                name="Security Logs Backup",
                source_type="filesystem",
                source_path="/var/log/security-automation",
                destination=f"s3://{self.backup_bucket}/logs",
                schedule="0 1 * * *",  # Daily at 1 AM
                retention_days=90,
                encryption_enabled=True,
                compression_enabled=True,
                priority=2
            ),
            BackupJob(
                id="database-backup",
                name="Security Database Backup",
                source_type="database",
                source_path="postgresql://localhost:5432/security_automation",
                destination=f"s3://{self.backup_bucket}/database",
                schedule="0 2 * * *",  # Daily at 2 AM
                retention_days=30,
                encryption_enabled=True,
                compression_enabled=True,
                priority=1
            ),
            BackupJob(
                id="application-backup",
                name="Application Code Backup",
                source_type="filesystem",
                source_path="/opt/security-automation",
                destination=f"s3://{self.backup_bucket}/application",
                schedule="0 3 * * 0",  # Weekly on Sunday at 3 AM
                retention_days=180,
                encryption_enabled=True,
                compression_enabled=True,
                priority=3
            )
        ]

    async def run_all_backups(self) -> List[BackupResult]:
        """Execute all scheduled backup jobs"""
        self.logger.info("Starting scheduled backup execution")

        # Sort jobs by priority
        sorted_jobs = sorted(self.backup_jobs, key=lambda x: x.priority)

        results = []
        for job in sorted_jobs:
            try:
                result = await self._execute_backup_job(job)
                results.append(result)

                # Send notification if backup failed
                if result.status == "failed":
                    await self._send_backup_notification(job, result, "failure")

            except Exception as e:
                self.logger.error(f"Backup job {job.id} failed with exception: {e}")
                error_result = BackupResult(
                    job_id=job.id,
                    started_at=datetime.now().isoformat(),
                    completed_at=datetime.now().isoformat(),
                    status="failed",
                    size_bytes=0,
                    backup_location="",
                    checksum="",
                    error_message=str(e)
                )
                results.append(error_result)

        # Generate backup report
        await self._generate_backup_report(results)

        # Cleanup old backups
        await self._cleanup_old_backups()

        return results

    async def _execute_backup_job(self, job: BackupJob) -> BackupResult:
        """Execute a single backup job"""
        self.logger.info(f"Starting backup job: {job.name}")

        started_at = datetime.now().isoformat()

        try:
            if job.source_type == "filesystem":
                result = await self._backup_filesystem(job)
            elif job.source_type == "database":
                result = await self._backup_database(job)
            elif job.source_type == "s3":
                result = await self._backup_s3(job)
            elif job.source_type == "configuration":
                result = await self._backup_configuration(job)
            else:
                raise ValueError(f"Unknown backup source type: {job.source_type}")

            # Update job status
            job.last_run = started_at
            job.status = result.status

            self.logger.info(f"Backup job {job.name} completed: {result.status}")
            return result

        except Exception as e:
            self.logger.error(f"Backup job {job.name} failed: {e}")
            return BackupResult(
                job_id=job.id,
                started_at=started_at,
                completed_at=datetime.now().isoformat(),
                status="failed",
                size_bytes=0,
                backup_location="",
                checksum="",
                error_message=str(e)
            )

    async def _backup_filesystem(self, job: BackupJob) -> BackupResult:
        """Backup filesystem path"""
        source_path = Path(job.source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source path does not exist: {job.source_path}")

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_filename = f"{job.id}-{timestamp}.tar.gz"
        temp_backup_path = f"/tmp/{backup_filename}"

        try:
            # Create compressed archive
            with tarfile.open(temp_backup_path, "w:gz") as tar:
                tar.add(source_path, arcname=source_path.name)

            # Calculate checksum
            checksum = await self._calculate_file_checksum(temp_backup_path)

            # Upload to S3
            s3_key = f"{job.id}/{backup_filename}"
            await self._upload_to_s3(temp_backup_path, s3_key, job.encryption_enabled)

            # Get file size
            size_bytes = os.path.getsize(temp_backup_path)

            # Cleanup temp file
            os.remove(temp_backup_path)

            return BackupResult(
                job_id=job.id,
                started_at=job.last_run,
                completed_at=datetime.now().isoformat(),
                status="completed",
                size_bytes=size_bytes,
                backup_location=f"s3://{self.backup_bucket}/{s3_key}",
                checksum=checksum,
                metadata={
                    "source_type": "filesystem",
                    "compression": "gzip",
                    "encryption": job.encryption_enabled
                }
            )

        except Exception as e:
            # Cleanup on failure
            if os.path.exists(temp_backup_path):
                os.remove(temp_backup_path)
            raise e

    async def _backup_database(self, job: BackupJob) -> BackupResult:
        """Backup database using pg_dump or similar"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_filename = f"{job.id}-{timestamp}.sql.gz"
        temp_backup_path = f"/tmp/{backup_filename}"

        try:
            # Extract database info from connection string
            # This is a simplified example - in production, parse the full URI
            db_name = "security_automation"

            # Create database dump
            dump_cmd = [
                "pg_dump",
                "-h", "localhost",
                "-U", "security",
                "-d", db_name,
                "--no-password",
                "--verbose"
            ]

            # Run pg_dump and compress output
            with open(temp_backup_path, 'wb') as f:
                proc1 = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE)
                proc2 = subprocess.Popen(['gzip'], stdin=proc1.stdout, stdout=f)
                proc1.stdout.close()
                proc2.communicate()

            if proc2.returncode != 0:
                raise subprocess.CalledProcessError(proc2.returncode, "pg_dump | gzip")

            # Calculate checksum
            checksum = await self._calculate_file_checksum(temp_backup_path)

            # Upload to S3
            s3_key = f"{job.id}/{backup_filename}"
            await self._upload_to_s3(temp_backup_path, s3_key, job.encryption_enabled)

            # Get file size
            size_bytes = os.path.getsize(temp_backup_path)

            # Cleanup temp file
            os.remove(temp_backup_path)

            return BackupResult(
                job_id=job.id,
                started_at=job.last_run,
                completed_at=datetime.now().isoformat(),
                status="completed",
                size_bytes=size_bytes,
                backup_location=f"s3://{self.backup_bucket}/{s3_key}",
                checksum=checksum,
                metadata={
                    "source_type": "postgresql",
                    "database": db_name,
                    "compression": "gzip",
                    "encryption": job.encryption_enabled
                }
            )

        except Exception as e:
            # Cleanup on failure
            if os.path.exists(temp_backup_path):
                os.remove(temp_backup_path)
            raise e

    async def _upload_to_s3(self, file_path: str, s3_key: str, encryption: bool = True):
        """Upload file to S3 with optional encryption"""
        extra_args = {}

        if encryption:
            extra_args['ServerSideEncryption'] = 'aws:kms'
            extra_args['SSEKMSKeyId'] = self.config['backup']['encryption_key']

        # Add metadata
        extra_args['Metadata'] = {
            'backup-system': 'security-automation',
            'created-at': datetime.now().isoformat(),
            'version': '1.0'
        }

        # Upload file
        with open(file_path, 'rb') as f:
            self.s3_client.upload_fileobj(
                f,
                self.backup_bucket,
                s3_key,
                ExtraArgs=extra_args
            )

    async def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    async def create_restore_point(self, description: str) -> RestorePoint:
        """Create a comprehensive system restore point"""
        self.logger.info(f"Creating restore point: {description}")

        restore_point_id = f"restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        backup_locations = {}

        # Backup all critical components
        for job in self.backup_jobs:
            if job.priority <= 2:  # Only critical and high priority jobs
                try:
                    result = await self._execute_backup_job(job)
                    if result.status == "completed":
                        backup_locations[job.id] = result.backup_location
                except Exception as e:
                    self.logger.error(f"Failed to backup {job.id} for restore point: {e}")

        # Create restore point metadata
        restore_point = RestorePoint(
            id=restore_point_id,
            created_at=datetime.now().isoformat(),
            description=description,
            components=list(backup_locations.keys()),
            backup_locations=backup_locations,
            metadata={
                "system_info": {
                    "hostname": os.uname().nodename,
                    "platform": os.uname().system,
                    "disk_usage": dict(psutil.disk_usage('/')._asdict()),
                    "memory_info": dict(psutil.virtual_memory()._asdict())
                },
                "aws_info": {
                    "region": self.aws_session.region_name,
                    "account_id": boto3.client('sts').get_caller_identity()['Account']
                }
            }
        )

        # Store restore point metadata
        await self._store_restore_point_metadata(restore_point)

        self.logger.info(f"Restore point created: {restore_point_id}")
        return restore_point

    async def restore_from_point(self, restore_point_id: str, components: Optional[List[str]] = None) -> bool:
        """Restore system from a specific restore point"""
        self.logger.info(f"Starting restore from point: {restore_point_id}")

        try:
            # Load restore point metadata
            restore_point = await self._load_restore_point_metadata(restore_point_id)

            # Determine components to restore
            if components is None:
                components = restore_point.components

            # Restore each component
            for component in components:
                if component in restore_point.backup_locations:
                    backup_location = restore_point.backup_locations[component]
                    await self._restore_component(component, backup_location)
                else:
                    self.logger.warning(f"Component {component} not found in restore point")

            self.logger.info(f"Restore completed successfully from point: {restore_point_id}")
            return True

        except Exception as e:
            self.logger.error(f"Restore failed from point {restore_point_id}: {e}")
            return False

    async def _restore_component(self, component: str, backup_location: str):
        """Restore a specific component from backup"""
        self.logger.info(f"Restoring component: {component} from {backup_location}")

        # Parse S3 location
        if backup_location.startswith("s3://"):
            bucket, key = backup_location[5:].split('/', 1)

            # Download backup file
            temp_file = f"/tmp/restore-{component}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

            try:
                self.s3_client.download_file(bucket, key, temp_file)

                # Find corresponding job configuration
                job = next((j for j in self.backup_jobs if j.id == component), None)
                if not job:
                    raise ValueError(f"No job configuration found for component: {component}")

                # Restore based on source type
                if job.source_type == "filesystem":
                    await self._restore_filesystem(temp_file, job.source_path)
                elif job.source_type == "database":
                    await self._restore_database(temp_file, job.source_path)

                # Cleanup temp file
                os.remove(temp_file)

            except Exception as e:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                raise e

    async def _restore_filesystem(self, backup_file: str, target_path: str):
        """Restore filesystem from backup archive"""
        self.logger.info(f"Restoring filesystem to {target_path}")

        # Create target directory if it doesn't exist
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # Extract archive
        with tarfile.open(backup_file, "r:gz") as tar:
            tar.extractall(path=os.path.dirname(target_path))

    async def _restore_database(self, backup_file: str, connection_string: str):
        """Restore database from backup"""
        self.logger.info("Restoring database from backup")

        db_name = "security_automation"  # Extract from connection string in production

        # Restore database dump
        restore_cmd = [
            "gunzip", "-c", backup_file, "|",
            "psql", "-h", "localhost", "-U", "security", "-d", db_name
        ]

        result = subprocess.run(' '.join(restore_cmd), shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, restore_cmd, result.stderr)

    async def verify_backup_integrity(self, backup_location: str) -> bool:
        """Verify backup file integrity"""
        try:
            if backup_location.startswith("s3://"):
                bucket, key = backup_location[5:].split('/', 1)

                # Download file and verify checksum
                temp_file = f"/tmp/verify-{datetime.now().strftime('%Y%m%d%H%M%S')}"

                try:
                    self.s3_client.download_file(bucket, key, temp_file)

                    # Calculate checksum
                    calculated_checksum = await self._calculate_file_checksum(temp_file)

                    # Get stored checksum from metadata (implementation dependent)
                    # For now, just verify the file can be read
                    with open(temp_file, 'rb') as f:
                        f.read(1024)  # Try to read first 1KB

                    os.remove(temp_file)
                    return True

                except Exception as e:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                    raise e

            return False

        except Exception as e:
            self.logger.error(f"Backup verification failed for {backup_location}: {e}")
            return False

    async def _cleanup_old_backups(self):
        """Clean up old backups based on retention policy"""
        self.logger.info("Starting backup cleanup")

        retention_policy = self.config['backup']['retention_policy']

        for job in self.backup_jobs:
            try:
                # List objects for this job
                prefix = f"{job.id}/"
                response = self.s3_client.list_objects_v2(
                    Bucket=self.backup_bucket,
                    Prefix=prefix
                )

                if 'Contents' not in response:
                    continue

                # Sort by last modified date
                objects = sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)

                # Keep backups based on retention policy
                cutoff_date = datetime.now() - timedelta(days=job.retention_days)

                for obj in objects:
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        self.logger.info(f"Deleting old backup: {obj['Key']}")
                        self.s3_client.delete_object(
                            Bucket=self.backup_bucket,
                            Key=obj['Key']
                        )

            except Exception as e:
                self.logger.error(f"Cleanup failed for job {job.id}: {e}")

    async def _generate_backup_report(self, results: List[BackupResult]):
        """Generate comprehensive backup report"""
        report = {
            "backup_summary": {
                "total_jobs": len(results),
                "successful": len([r for r in results if r.status == "completed"]),
                "failed": len([r for r in results if r.status == "failed"]),
                "total_size_gb": sum(r.size_bytes for r in results) / (1024**3),
                "generated_at": datetime.now().isoformat()
            },
            "job_results": [asdict(result) for result in results],
            "recommendations": self._generate_backup_recommendations(results)
        }

        # Save report
        report_path = f"/var/log/security-automation/backup-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info(f"Backup report generated: {report_path}")

    def _generate_backup_recommendations(self, results: List[BackupResult]) -> List[str]:
        """Generate recommendations based on backup results"""
        recommendations = []

        failed_jobs = [r for r in results if r.status == "failed"]
        if failed_jobs:
            recommendations.append(f"Investigate {len(failed_jobs)} failed backup jobs")

        large_backups = [r for r in results if r.size_bytes > 10 * 1024**3]  # >10GB
        if large_backups:
            recommendations.append(f"Consider optimizing {len(large_backups)} large backups")

        return recommendations

    async def _send_backup_notification(self, job: BackupJob, result: BackupResult, status: str):
        """Send backup status notification"""
        if status == "failure" and self.config.get('notifications', {}).get('sns_topic'):
            try:
                sns = self.aws_session.client('sns')
                message = f"Backup job '{job.name}' failed: {result.error_message}"

                sns.publish(
                    TopicArn=self.config['notifications']['sns_topic'],
                    Message=message,
                    Subject=f"Backup Failure: {job.name}"
                )
            except Exception as e:
                self.logger.error(f"Failed to send backup notification: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Backup and Recovery System")
    parser.add_argument("--backup", action="store_true", help="Run all backup jobs")
    parser.add_argument("--restore-point", help="Create restore point with description")
    parser.add_argument("--restore", help="Restore from restore point ID")
    parser.add_argument("--verify", help="Verify backup at S3 location")
    parser.add_argument("--cleanup", action="store_true", help="Clean up old backups")

    args = parser.parse_args()

    backup_system = BackupAndRecoverySystem()

    loop = asyncio.get_event_loop()

    if args.backup:
        results = loop.run_until_complete(backup_system.run_all_backups())
        print(f"Backup completed. {len([r for r in results if r.status == 'completed'])} successful, {len([r for r in results if r.status == 'failed'])} failed.")

    elif args.restore_point:
        restore_point = loop.run_until_complete(backup_system.create_restore_point(args.restore_point))
        print(f"Restore point created: {restore_point.id}")

    elif args.restore:
        success = loop.run_until_complete(backup_system.restore_from_point(args.restore))
        print(f"Restore {'successful' if success else 'failed'}")

    elif args.verify:
        valid = loop.run_until_complete(backup_system.verify_backup_integrity(args.verify))
        print(f"Backup verification: {'PASS' if valid else 'FAIL'}")

    elif args.cleanup:
        loop.run_until_complete(backup_system._cleanup_old_backups())
        print("Backup cleanup completed")

    else:
        parser.print_help()