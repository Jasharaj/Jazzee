from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class ResourceConfig(BaseModel):
    resource_id: str
    resource_type: str
    region: str
    configuration: dict
    tags: Optional[dict] = None

class Finding(BaseModel):
    severity: str = Field(..., description="high, medium, or low")
    title: str
    description: str
    resource_id: str
    resource_type: str
    compliance_standard: Optional[str] = None
    remediation_steps: List[str]

class ScanResult(BaseModel):
    scan_id: str = Field(..., description="Unique identifier for the scan")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    aws_account_id: str
    resources_scanned: int
    findings: List[Finding]
    scan_duration: float  # in seconds
    status: str = Field(..., description="completed, failed, or in_progress")
    error_message: Optional[str] = None

class ComplianceStatus(BaseModel):
    standard: str  # e.g., "CIS", "NIST", "PCI"
    version: str
    compliant_controls: int
    total_controls: int
    findings: List[Finding]
