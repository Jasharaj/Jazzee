from typing import List
from datetime import datetime, timezone
from .base_scanner import BaseScanner
from ..models.scan_result import Finding, ResourceConfig

class IAMScanner(BaseScanner):
    def __init__(self, session):
        super().__init__(session)
        self.iam_client = session.client('iam')

    async def scan(self) -> List[Finding]:
        users = await self.get_resources()
        
        for user in users:
            # Check for access keys
            access_keys = self.iam_client.list_access_keys(UserName=user.resource_id)['AccessKeyMetadata']
            for key in access_keys:
                key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                if key_age > 90:
                    self.add_finding(Finding(
                        severity="medium",
                        title="IAM Access Key Rotation Required",
                        description=f"Access key for user {user.resource_id} is {key_age} days old",
                        resource_id=user.resource_id,
                        resource_type="iam_user",
                        compliance_standard="CIS 1.4",
                        remediation_steps=[
                            "Create new access key",
                            "Update applications with new key",
                            "Disable and delete old key"
                        ]
                    ))

            # Check for MFA
            mfa_devices = self.iam_client.list_mfa_devices(UserName=user.resource_id)['MFADevices']
            if not mfa_devices:
                self.add_finding(Finding(
                    severity="high",
                    title="MFA Not Enabled",
                    description=f"User {user.resource_id} does not have MFA enabled",
                    resource_id=user.resource_id,
                    resource_type="iam_user",
                    compliance_standard="CIS 1.2",
                    remediation_steps=[
                        "Enable virtual MFA device",
                        "Configure hardware MFA device",
                        "Enforce MFA usage through IAM policies"
                    ]
                ))

            # Check for direct policy attachments
            attached_policies = self.iam_client.list_attached_user_policies(UserName=user.resource_id)['AttachedPolicies']
            if attached_policies:
                self.add_finding(Finding(
                    severity="medium",
                    title="Direct Policy Attachment",
                    description=f"User {user.resource_id} has directly attached policies. Use groups instead",
                    resource_id=user.resource_id,
                    resource_type="iam_user",
                    compliance_standard="CIS 1.16",
                    remediation_steps=[
                        "Create/identify appropriate IAM group",
                        "Add user to group",
                        "Remove directly attached policies",
                        "Attach policies to group instead"
                    ]
                ))

        return self.findings

    async def get_resources(self) -> List[ResourceConfig]:
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                # Get user policies
                attached_policies = self.iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                inline_policies = self.iam_client.list_user_policies(UserName=user['UserName'])['PolicyNames']
                
                self.add_resource(ResourceConfig(
                    resource_id=user['UserName'],
                    resource_type="iam_user",
                    region='global',
                    configuration={
                        'arn': user['Arn'],
                        'create_date': user['CreateDate'].isoformat(),
                        'path': user['Path'],
                        'user_id': user['UserId'],
                        'attached_policies': [p['PolicyName'] for p in attached_policies],
                        'inline_policies': inline_policies
                    },
                    tags={tag['Key']: tag['Value'] for tag in self.iam_client.list_user_tags(UserName=user['UserName'])['Tags']}
                ))
        
        return self.resources
