from typing import List
import boto3
from .base_scanner import BaseScanner
from ..models.scan_result import Finding, ResourceConfig

class EC2Scanner(BaseScanner):
    def __init__(self, session):
        super().__init__(session)
        self.ec2_client = session.client('ec2')

    async def scan(self) -> List[Finding]:
        instances = await self.get_resources()
        security_groups = self.ec2_client.describe_security_groups()['SecurityGroups']

        # Check security groups
        for sg in security_groups:
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if rule.get('FromPort') == 22 or rule.get('FromPort') == 3389:
                            self.add_finding(Finding(
                                severity="high",
                                title="Security Group Allows Public SSH/RDP Access",
                                description=f"Security Group {sg['GroupId']} allows public access to port {rule.get('FromPort')}",
                                resource_id=sg['GroupId'],
                                resource_type="ec2_security_group",
                                compliance_standard="CIS 4.1",
                                remediation_steps=[
                                    "Remove the 0.0.0.0/0 CIDR from the security group rule",
                                    "Implement a bastion host for remote access",
                                    "Use AWS Systems Manager Session Manager for secure shell access"
                                ]
                            ))

        # Check EC2 instances
        for instance in instances:
            if not instance.configuration.get('monitoring', {}).get('state') == 'enabled':
                self.add_finding(Finding(
                    severity="low",
                    title="EC2 Detailed Monitoring Disabled",
                    description=f"Instance {instance.resource_id} does not have detailed monitoring enabled",
                    resource_id=instance.resource_id,
                    resource_type="ec2",
                    compliance_standard="CIS 4.15",
                    remediation_steps=[
                        "Enable detailed monitoring for the EC2 instance",
                        "Configure CloudWatch alarms for the instance"
                    ]
                ))

        return self.findings

    async def get_resources(self) -> List[ResourceConfig]:
        paginator = self.ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    self.add_resource(ResourceConfig(
                        resource_id=instance['InstanceId'],
                        resource_type="ec2",
                        region=self.ec2_client.meta.region_name,
                        configuration={
                            'instance_type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'monitoring': instance['Monitoring'],
                            'launch_time': instance['LaunchTime'].isoformat(),
                            'security_groups': instance['SecurityGroups']
                        },
                        tags={tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    ))
        
        return self.resources
