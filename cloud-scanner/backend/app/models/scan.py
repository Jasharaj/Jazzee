from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import uuid

class ScanStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class AWSCredentials(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    region_name: str = "us-east-1"

class Finding(BaseModel):
    severity: FindingSeverity
    title: str
    description: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    remediation_steps: Optional[List[str]] = None

class ScanConfiguration(BaseModel):
    id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    aws_credentials: AWSCredentials
    services: List[str] = ["iam", "s3"]  # List of AWS services to scan
    schedule: Optional[str] = None  # Cron expression for scheduled scans
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_config_id: str
    user_id: str
    status: ScanStatus = ScanStatus.PENDING
    findings: List[Finding] = []
    services_scanned: List[str] = []
    total_resources_scanned: int = 0
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None

class ScanSummary(BaseModel):
    total_scans: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    services_scanned: List[str] = []
    last_scan_time: Optional[datetime] = None

class ScheduledScan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_config_id: str
    user_id: str
    cron_expression: str
    is_active: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
