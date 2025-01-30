import boto3
from typing import Dict, Any, Optional, List
from botocore.exceptions import ClientError
from ..models.scan import AWSCredentials, Finding, FindingSeverity
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class AWSManager:
    def __init__(self, credentials: AWSCredentials):
        self.credentials = credentials
        self.session = self._create_session()

    def _create_session(self):
        """Create a new boto3 session with the provided credentials"""
        return boto3.Session(
            aws_access_key_id=self.credentials.aws_access_key_id,
            aws_secret_access_key=self.credentials.aws_secret_access_key,
            region_name=self.credentials.region_name
        )

    def get_client(self, service_name: str):
        """Get a boto3 client for the specified service"""
        return self.session.client(service_name)

    async def test_credentials(self) -> bool:
        """Test if the AWS credentials are valid"""
        try:
            logger.info("Testing AWS credentials...")
            sts = self.get_client('sts')
            identity = sts.get_caller_identity()
            logger.info(f"Successfully validated AWS credentials. Account ID: {identity['Account']}")
            return True
        except Exception as e:
            logger.error(f"Failed to validate AWS credentials: {str(e)}", exc_info=True)
            return False

    async def list_regions(self) -> List[str]:
        """List all available AWS regions"""
        try:
            ec2 = self.get_client('ec2')
            regions = ec2.describe_regions()
            return [region['RegionName'] for region in regions['Regions']]
        except Exception as e:
            logger.error(f"Failed to list AWS regions: {str(e)}")
            return []

class SecurityScanner:
    def __init__(self, aws_manager: AWSManager):
        self.aws = aws_manager
        self.findings: List[Finding] = []
        self.region = aws_manager.credentials.region_name

    async def initialize(self):
        """Initialize the scanner"""
        try:
            # Test AWS credentials
            if not await self.aws.test_credentials():
                raise Exception("Invalid AWS credentials")

            # Get account ID
            sts = self.aws.get_client('sts')
            self.account_id = sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {str(e)}")
            raise

    def add_finding(
            self,
            severity: str,
            title: str,
            description: str,
            resource_id: Optional[str] = None,
            resource_type: Optional[str] = None,
            remediation_steps: Optional[List[str]] = None
        ):
        """Helper method to add findings with consistent formatting"""
        finding = Finding(
            severity=severity,
            title=title,
            description=description,
            resource_id=resource_id,
            resource_type=resource_type,
            remediation_steps=remediation_steps
        )
        self.findings.append(finding)
        return finding

    async def scan_service(self, service: str) -> List[Finding]:
        """Scan a specific AWS service"""
        try:
            logger.info(f"Starting scan for service: {service}")
            self.findings = []  # Reset findings for this service
            
            if service == 'iam':
                logger.info("Scanning IAM service...")
                await self.scan_iam()
            elif service == 's3':
                logger.info("Scanning S3 service...")
                await self.scan_s3()
            elif service == 'ec2':
                logger.info("Scanning EC2 service...")
                await self.scan_ec2()
            elif service == 'rds':
                logger.info("Scanning RDS service...")
                await self.scan_rds()
            else:
                logger.warning(f"Unsupported service: {service}")
                return []

            logger.info(f"Scan completed for {service}. Found {len(self.findings)} issues.")
            return self.findings
        except Exception as e:
            logger.error(f"Error scanning {service}: {str(e)}", exc_info=True)
            error_finding = Finding(
                severity="high",
                title=f"Failed to scan {service.upper()}",
                description=f"Error scanning {service.upper()}: {str(e)}",
                resource_type=service.upper(),
                remediation_steps=[
                    "Check AWS credentials and permissions",
                    "Ensure the service is available in your region",
                    "Check AWS service quotas and limits"
                ]
            )
            return [error_finding]

    async def scan_iam(self):
        """Scan IAM configurations for security issues"""
        try:
            iam = self.aws.get_client('iam')

            # Check password policy
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                if policy.get('MaxPasswordAge', 0) > 90:
                    self.add_finding(
                        severity='medium',
                        title='Weak Password Policy',
                        description='Password expiration is set to more than 90 days',
                        resource_type='IAM Password Policy',
                        remediation_steps=[
                            'Go to IAM Console → Account Settings',
                            'Edit Password Policy',
                            'Set "Password expiration period" to 90 days or less'
                        ]
                    )
            except ClientError:
                self.add_finding(
                    severity='high',
                    title='No Password Policy',
                    description='No password policy is set for the account',
                    resource_type='IAM Password Policy',
                    remediation_steps=[
                        'Go to IAM Console → Account Settings',
                        'Create a new password policy with strong requirements'
                    ]
                )

            # Check root account
            root_mfa = iam.get_account_summary()['SummaryMap']['AccountMFAEnabled']
            if not root_mfa:
                self.add_finding(
                    severity='critical',
                    title='Root Account Without MFA',
                    description='Root account does not have MFA enabled',
                    resource_type='Root Account',
                    remediation_steps=[
                        'Sign in as root user',
                        'Go to IAM Console → Security credentials',
                        'Enable MFA for root account'
                    ]
                )

            # Check IAM users
            users = iam.list_users()['Users']
            for user in users:
                username = user['UserName']
                
                # Check for console access without MFA
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        self.add_finding(
                            severity='high',
                            title='User Without MFA',
                            description=f'User {username} has console access but no MFA device',
                            resource_id=username,
                            resource_type='IAM User',
                            remediation_steps=[
                                f'Contact user {username} to set up MFA',
                                'Enable MFA enforcement through SCP or IAM policy'
                            ]
                        )
                except ClientError:
                    pass  # User doesn't have console access

                # Check access keys
                keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in keys:
                    key_id = key['AccessKeyId']
                    if (datetime.now(timezone.utc) - key['CreateDate']).days > 90:
                        self.add_finding(
                            severity='medium',
                            title='Old Access Key',
                            description=f'Access key for user {username} is over 90 days old',
                            resource_id=key_id,
                            resource_type='IAM Access Key',
                            remediation_steps=[
                                f'Create new access key for user {username}',
                                'Update applications with new key',
                                f'Delete old access key {key_id}'
                            ]
                        )

                # Check for direct policy attachments
                attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
                if attached_policies:
                    self.add_finding(
                        severity='low',
                        title='Direct Policy Attachment',
                        description=f'User {username} has directly attached policies. Prefer group-based permissions.',
                        resource_id=username,
                        resource_type='IAM User',
                        remediation_steps=[
                            'Create or identify appropriate IAM group',
                            'Add user to group',
                            'Move policies from user to group',
                            'Remove direct policy attachments'
                        ]
                    )

        except Exception as e:
            logger.error(f"Error scanning IAM: {str(e)}")
            self.add_finding(
                severity='high',
                title='IAM Scan Failed',
                description=f'Error scanning IAM configurations: {str(e)}',
                resource_type='IAM',
                remediation_steps=[
                    'Check IAM permissions',
                    'Ensure IAM service is available'
                ]
            )

    async def scan_s3(self):
        """Scan S3 buckets for security issues"""
        try:
            logger.info("Starting S3 scan...")
            s3 = self.aws.get_client('s3')
            
            logger.info("Listing all S3 buckets...")
            buckets = s3.list_buckets()['Buckets']
            logger.info(f"Found {len(buckets)} buckets")

            for bucket in buckets:
                bucket_name = bucket['Name']
                logger.info(f"Scanning bucket: {bucket_name}")
                try:
                    # Check bucket policy
                    try:
                        logger.info(f"Checking bucket policy for {bucket_name}")
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        logger.info(f"Bucket {bucket_name} has a policy")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                            logger.warning(f"Bucket {bucket_name} has no bucket policy")
                            self.add_finding(
                                severity='medium',
                                title='Missing Bucket Policy',
                                description=f'S3 bucket {bucket_name} has no bucket policy',
                                resource_id=bucket_name,
                                resource_type='S3 Bucket',
                                remediation_steps=[
                                    'Review bucket usage and access requirements',
                                    'Create appropriate bucket policy'
                                ]
                            )
                        else:
                            logger.error(f"Error checking bucket policy for {bucket_name}: {str(e)}")
                            raise

                    # Check bucket versioning
                    logger.info(f"Checking versioning for bucket {bucket_name}")
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if 'Status' not in versioning or versioning['Status'] != 'Enabled':
                        logger.warning(f"Bucket {bucket_name} does not have versioning enabled")
                        self.add_finding(
                            severity='medium',
                            title='Versioning Disabled',
                            description=f'S3 bucket {bucket_name} does not have versioning enabled',
                            resource_id=bucket_name,
                            resource_type='S3 Bucket',
                            remediation_steps=[
                                'Enable versioning for data protection',
                                'Consider lifecycle policies for version management'
                            ]
                        )

                    # Check encryption
                    logger.info(f"Checking encryption for bucket {bucket_name}")
                    try:
                        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                        logger.info(f"Bucket {bucket_name} has encryption enabled")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            logger.warning(f"Bucket {bucket_name} does not have default encryption enabled")
                            self.add_finding(
                                severity='high',
                                title='Default Encryption Disabled',
                                description=f'S3 bucket {bucket_name} does not have default encryption enabled',
                                resource_id=bucket_name,
                                resource_type='S3 Bucket',
                                remediation_steps=[
                                    'Enable default encryption using AES-256 or AWS-KMS',
                                    'Review existing objects for encryption status'
                                ]
                            )
                        else:
                            logger.error(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
                            raise

                    # Check public access
                    logger.info(f"Checking public access settings for bucket {bucket_name}")
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    block_config = public_access['PublicAccessBlockConfiguration']
                    if not all([
                        block_config.get('BlockPublicAcls', False),
                        block_config.get('BlockPublicPolicy', False),
                        block_config.get('IgnorePublicAcls', False),
                        block_config.get('RestrictPublicBuckets', False)
                    ]):
                        logger.warning(f"Bucket {bucket_name} does not have all public access blocks enabled")
                        self.add_finding(
                            severity='critical',
                            title='Public Access Not Blocked',
                            description=f'S3 bucket {bucket_name} does not have all public access blocks enabled',
                            resource_id=bucket_name,
                            resource_type='S3 Bucket',
                            remediation_steps=[
                                'Enable "Block all public access"',
                                'Review bucket policies and ACLs',
                                'Remove any public access grants'
                            ]
                        )

                except Exception as e:
                    logger.error(f"Error scanning bucket {bucket_name}: {str(e)}", exc_info=True)
                    self.add_finding(
                        severity='high',
                        title=f'Bucket Scan Failed',
                        description=f'Error scanning bucket {bucket_name}: {str(e)}',
                        resource_id=bucket_name,
                        resource_type='S3 Bucket',
                        remediation_steps=[
                            'Check S3 permissions',
                            'Ensure bucket exists and is accessible'
                        ]
                    )

            logger.info(f"S3 scan completed. Found {len(self.findings)} issues.")

        except Exception as e:
            logger.error(f"Error scanning S3: {str(e)}", exc_info=True)
            self.add_finding(
                severity='high',
                title='S3 Scan Failed',
                description=f'Error scanning S3 buckets: {str(e)}',
                resource_type='S3',
                remediation_steps=[
                    'Check S3 permissions',
                    'Ensure S3 service is available'
                ]
            )

    async def scan_ec2(self):
        """Scan EC2 instances and related resources for security issues"""
        try:
            ec2 = self.aws.get_client('ec2')
            
            # Get all instances
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP
                    if 'PublicIpAddress' in instance:
                        self.add_finding(
                            severity='medium',
                            title='Public IP Assigned',
                            description=f'EC2 instance {instance_id} has a public IP address',
                            resource_id=instance_id,
                            resource_type='EC2 Instance',
                            remediation_steps=[
                                'Review if public IP is required',
                                'Consider using private subnets with NAT gateway',
                                'Implement proper security group rules'
                            ]
                        )
                    
                    # Check security groups
                    for sg in instance['SecurityGroups']:
                        sg_id = sg['GroupId']
                        sg_details = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                        
                        for rule in sg_details['IpPermissions']:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    port = rule.get('FromPort', 'any')
                                    protocol = rule.get('IpProtocol', 'any')
                                    self.add_finding(
                                        severity='high',
                                        title='Open Security Group',
                                        description=f'Security group {sg_id} allows inbound access from anywhere (0.0.0.0/0) on port {port}/{protocol}',
                                        resource_id=sg_id,
                                        resource_type='Security Group',
                                        remediation_steps=[
                                            'Review security group rules',
                                            'Restrict access to specific IP ranges',
                                            'Remove unnecessary open ports'
                                        ]
                                    )

            # Check unencrypted volumes
            volumes = ec2.describe_volumes()['Volumes']
            for volume in volumes:
                volume_id = volume['VolumeId']
                if not volume.get('Encrypted'):
                    self.add_finding(
                        severity='medium',
                        title='Unencrypted EBS Volume',
                        description=f'EBS volume {volume_id} is not encrypted',
                        resource_id=volume_id,
                        resource_type='EBS Volume',
                        remediation_steps=[
                            'Create encrypted snapshot',
                            'Create new encrypted volume from snapshot',
                            'Replace unencrypted volume'
                        ]
                    )

        except Exception as e:
            logger.error(f"Error scanning EC2: {str(e)}")
            self.add_finding(
                severity='high',
                title='EC2 Scan Failed',
                description=f'Error scanning EC2 resources: {str(e)}',
                resource_type='EC2',
                remediation_steps=[
                    'Check EC2 permissions',
                    'Ensure EC2 service is available'
                ]
            )

    async def scan_rds(self):
        """Scan RDS instances and clusters for security issues"""
        try:
            rds = self.aws.get_client('rds')
            
            # Check DB instances
            instances = rds.describe_db_instances()['DBInstances']
            for instance in instances:
                instance_id = instance['DBInstanceIdentifier']
                
                # Check public accessibility
                if instance.get('PubliclyAccessible'):
                    self.add_finding(
                        severity='high',
                        title='Public RDS Instance',
                        description=f'RDS instance {instance_id} is publicly accessible',
                        resource_id=instance_id,
                        resource_type='RDS Instance',
                        remediation_steps=[
                            'Disable public accessibility',
                            'Use private subnets',
                            'Implement proper security group rules'
                        ]
                    )
                
                # Check encryption
                if not instance.get('StorageEncrypted'):
                    self.add_finding(
                        severity='medium',
                        title='Unencrypted RDS Instance',
                        description=f'RDS instance {instance_id} is not encrypted',
                        resource_id=instance_id,
                        resource_type='RDS Instance',
                        remediation_steps=[
                            'Create encrypted snapshot',
                            'Restore from encrypted snapshot',
                            'Enable encryption for new instances'
                        ]
                    )
                
                # Check backup retention
                if instance.get('BackupRetentionPeriod', 0) < 7:
                    self.add_finding(
                        severity='low',
                        title='Short Backup Retention',
                        description=f'RDS instance {instance_id} has backup retention period less than 7 days',
                        resource_id=instance_id,
                        resource_type='RDS Instance',
                        remediation_steps=[
                            'Increase backup retention period',
                            'Review backup strategy',
                            'Consider point-in-time recovery needs'
                        ]
                    )

        except Exception as e:
            logger.error(f"Error scanning RDS: {str(e)}")
            self.add_finding(
                severity='high',
                title='RDS Scan Failed',
                description=f'Error scanning RDS resources: {str(e)}',
                resource_type='RDS',
                remediation_steps=[
                    'Check RDS permissions',
                    'Ensure RDS service is available'
                ]
            )
