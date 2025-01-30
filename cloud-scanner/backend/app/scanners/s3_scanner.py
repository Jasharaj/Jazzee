from typing import List
import boto3
from .base_scanner import BaseScanner
from ..models.scan_result import Finding, ResourceConfig

class S3Scanner(BaseScanner):
    def __init__(self, session):
        super().__init__(session)
        self.s3_client = session.client('s3')

    async def scan(self) -> List[Finding]:
        buckets = await self.get_resources()
        
        for bucket in buckets:
            # Check for public access
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket.resource_id)
                if '"Principal": "*"' in policy['Policy']:
                    self.add_finding(Finding(
                        severity="high",
                        title="S3 Bucket Publicly Accessible",
                        description=f"Bucket {bucket.resource_id} has a policy allowing public access",
                        resource_id=bucket.resource_id,
                        resource_type="s3",
                        compliance_standard="CIS 1.2.3",
                        remediation_steps=[
                            "Review bucket policy and remove public access if not required",
                            "Enable S3 Block Public Access settings",
                            "Audit bucket ACLs"
                        ]
                    ))
            except self.s3_client.exceptions.NoSuchBucketPolicy:
                pass

            # Check encryption
            try:
                encryption = self.s3_client.get_bucket_encryption(Bucket=bucket.resource_id)
            except self.s3_client.exceptions.ClientError:
                self.add_finding(Finding(
                    severity="medium",
                    title="S3 Bucket Without Default Encryption",
                    description=f"Bucket {bucket.resource_id} does not have default encryption enabled",
                    resource_id=bucket.resource_id,
                    resource_type="s3",
                    compliance_standard="CIS 1.2.4",
                    remediation_steps=[
                        "Enable default encryption using AWS KMS keys",
                        "Configure bucket policy to enforce encryption"
                    ]
                ))

        return self.findings

    async def get_resources(self) -> List[ResourceConfig]:
        response = self.s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            region = self.s3_client.get_bucket_location(Bucket=bucket['Name'])
            region = region['LocationConstraint'] or 'us-east-1'
            
            self.add_resource(ResourceConfig(
                resource_id=bucket['Name'],
                resource_type="s3",
                region=region,
                configuration={
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'region': region
                },
                tags=self.get_bucket_tags(bucket['Name'])
            ))
        
        return self.resources

    def get_bucket_tags(self, bucket_name: str) -> dict:
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            return {tag['Key']: tag['Value'] for tag in response['TagSet']}
        except self.s3_client.exceptions.ClientError:
            return {}
