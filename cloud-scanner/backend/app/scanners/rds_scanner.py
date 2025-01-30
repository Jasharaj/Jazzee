from typing import List
from .base_scanner import BaseScanner
from ..models.scan_result import Finding, ResourceConfig

class RDSScanner(BaseScanner):
    def __init__(self, session):
        super().__init__(session)
        self.rds_client = session.client('rds')

    async def scan(self) -> List[Finding]:
        instances = await self.get_resources()
        
        for instance in instances:
            # Check for public accessibility
            if instance.configuration.get('publicly_accessible'):
                self.add_finding(Finding(
                    severity="high",
                    title="RDS Instance Publicly Accessible",
                    description=f"RDS instance {instance.resource_id} is publicly accessible",
                    resource_id=instance.resource_id,
                    resource_type="rds",
                    compliance_standard="CIS 2.3.1",
                    remediation_steps=[
                        "Modify the RDS instance to disable public accessibility",
                        "Use VPC endpoints or VPN for database access",
                        "Implement proper security group rules"
                    ]
                ))

            # Check for encryption
            if not instance.configuration.get('storage_encrypted'):
                self.add_finding(Finding(
                    severity="high",
                    title="RDS Storage Not Encrypted",
                    description=f"RDS instance {instance.resource_id} does not have storage encryption enabled",
                    resource_id=instance.resource_id,
                    resource_type="rds",
                    compliance_standard="CIS 2.3.2",
                    remediation_steps=[
                        "Create encrypted snapshot of the database",
                        "Restore from encrypted snapshot to new instance",
                        "Update application configuration to use new endpoint"
                    ]
                ))

            # Check for automated backups
            if not instance.configuration.get('backup_retention_period', 0) > 0:
                self.add_finding(Finding(
                    severity="medium",
                    title="RDS Automated Backups Disabled",
                    description=f"RDS instance {instance.resource_id} does not have automated backups enabled",
                    resource_id=instance.resource_id,
                    resource_type="rds",
                    compliance_standard="CIS 2.3.3",
                    remediation_steps=[
                        "Enable automated backups",
                        "Set appropriate backup retention period",
                        "Configure backup window"
                    ]
                ))

        return self.findings

    async def get_resources(self) -> List[ResourceConfig]:
        paginator = self.rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                self.add_resource(ResourceConfig(
                    resource_id=instance['DBInstanceIdentifier'],
                    resource_type="rds",
                    region=self.rds_client.meta.region_name,
                    configuration={
                        'engine': instance['Engine'],
                        'engine_version': instance['EngineVersion'],
                        'storage_encrypted': instance.get('StorageEncrypted', False),
                        'publicly_accessible': instance.get('PubliclyAccessible', False),
                        'backup_retention_period': instance.get('BackupRetentionPeriod', 0),
                        'multi_az': instance.get('MultiAZ', False),
                        'instance_class': instance['DBInstanceClass']
                    },
                    tags={tag['Key']: tag['Value'] for tag in instance.get('TagList', [])}
                ))
        
        return self.resources
