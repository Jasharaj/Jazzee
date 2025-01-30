from motor.motor_asyncio import AsyncIOMotorClient
from typing import List, Optional, Dict, Any
from ..models.scan import (
    ScanConfiguration,
    ScanResult,
    ScanSummary,
    ScheduledScan,
    Finding,
    ScanStatus
)
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGODB_URL)
db = client.cloud_scanner

# Collections
scan_configs = db.scan_configs
scan_results = db.scan_results
scheduled_scans = db.scheduled_scans

async def create_scan_config(config: ScanConfiguration) -> ScanConfiguration:
    """Create a new scan configuration"""
    config_dict = config.model_dump()
    result = await scan_configs.insert_one(config_dict)
    config_dict["id"] = str(result.inserted_id)
    return ScanConfiguration(**config_dict)

async def get_scan_configs(user_id: Optional[str] = None) -> List[ScanConfiguration]:
    """Get all scan configurations for a user"""
    query = {"user_id": user_id} if user_id else {}
    cursor = scan_configs.find(query)
    configs = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        configs.append(ScanConfiguration(**doc))
    return configs

async def get_scan_config(config_id: str) -> Optional[ScanConfiguration]:
    """Get a specific scan configuration"""
    doc = await scan_configs.find_one({"_id": config_id})
    if doc:
        doc["id"] = str(doc["_id"])
        return ScanConfiguration(**doc)
    return None

async def update_scan_config(config_id: str, config: ScanConfiguration) -> Optional[ScanConfiguration]:
    """Update a scan configuration"""
    config_dict = config.model_dump()
    result = await scan_configs.update_one(
        {"_id": config_id},
        {"$set": config_dict}
    )
    if result.modified_count:
        config_dict["id"] = config_id
        return ScanConfiguration(**config_dict)
    return None

async def delete_scan_config(config_id: str) -> bool:
    """Delete a scan configuration"""
    result = await scan_configs.delete_one({"_id": config_id})
    return result.deleted_count > 0

async def create_scan_result(result: ScanResult) -> ScanResult:
    """Create a new scan result"""
    result_dict = result.model_dump()
    result = await scan_results.insert_one(result_dict)
    result_dict["id"] = str(result.inserted_id)
    return ScanResult(**result_dict)

async def get_scan_results(
    user_id: Optional[str] = None,
    config_id: Optional[str] = None
) -> List[ScanResult]:
    """Get scan results with optional filters"""
    query = {}
    if user_id:
        query["user_id"] = user_id
    if config_id:
        query["scan_config_id"] = config_id

    cursor = scan_results.find(query).sort("start_time", -1)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        results.append(ScanResult(**doc))
    return results

async def get_scan_result(scan_id: str) -> Optional[ScanResult]:
    """Get a specific scan result"""
    doc = await scan_results.find_one({"_id": scan_id})
    if doc:
        doc["id"] = str(doc["_id"])
        return ScanResult(**doc)
    return None

async def update_scan_result(scan_id: str, result: ScanResult) -> Optional[ScanResult]:
    """Update a scan result"""
    result_dict = result.model_dump()
    result = await scan_results.update_one(
        {"_id": scan_id},
        {"$set": result_dict}
    )
    if result.modified_count:
        result_dict["id"] = scan_id
        return ScanResult(**result_dict)
    return None

async def get_scan_summary(user_id: Optional[str] = None) -> ScanSummary:
    """Get a summary of all scans"""
    query = {"user_id": user_id} if user_id else {}
    
    # Get all scan results
    cursor = scan_results.find(query)
    total_scans = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0
    low_findings = 0
    services = set()
    last_scan_time = None

    async for doc in cursor:
        total_scans += 1
        services.update(doc.get("services_scanned", []))
        
        # Count findings by severity
        for finding in doc.get("findings", []):
            severity = finding.get("severity")
            if severity == "critical":
                critical_findings += 1
            elif severity == "high":
                high_findings += 1
            elif severity == "medium":
                medium_findings += 1
            elif severity == "low":
                low_findings += 1

        # Track last scan time
        scan_time = doc.get("end_time") or doc.get("start_time")
        if scan_time and (not last_scan_time or scan_time > last_scan_time):
            last_scan_time = scan_time

    return ScanSummary(
        total_scans=total_scans,
        critical_findings=critical_findings,
        high_findings=high_findings,
        medium_findings=medium_findings,
        low_findings=low_findings,
        services_scanned=list(services),
        last_scan_time=last_scan_time
    )

async def create_scheduled_scan(scheduled_scan: ScheduledScan) -> ScheduledScan:
    """Create a new scheduled scan"""
    scan_dict = scheduled_scan.model_dump()
    result = await scheduled_scans.insert_one(scan_dict)
    scan_dict["id"] = str(result.inserted_id)
    return ScheduledScan(**scan_dict)

async def get_scheduled_scans(user_id: Optional[str] = None) -> List[ScheduledScan]:
    """Get all scheduled scans for a user"""
    query = {"user_id": user_id} if user_id else {}
    cursor = scheduled_scans.find(query)
    scans = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        scans.append(ScheduledScan(**doc))
    return scans

async def update_scheduled_scan(schedule_id: str, scheduled_scan: ScheduledScan) -> Optional[ScheduledScan]:
    """Update a scheduled scan"""
    scan_dict = scheduled_scan.model_dump()
    result = await scheduled_scans.update_one(
        {"_id": schedule_id},
        {"$set": scan_dict}
    )
    if result.modified_count:
        scan_dict["id"] = schedule_id
        return ScheduledScan(**scan_dict)
    return None

async def delete_scheduled_scan(schedule_id: str) -> bool:
    """Delete a scheduled scan"""
    result = await scheduled_scans.delete_one({"_id": schedule_id})
    return result.deleted_count > 0
