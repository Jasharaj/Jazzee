from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Optional
from ...models.scan import (
    ScanConfiguration,
    ScanResult,
    ScanSummary,
    AWSCredentials,
    ScheduledScan,
    ScanStatus
)
from ...core.aws import AWSManager, SecurityScanner
from ...core.auth import get_current_user
from ...models.user import User
from ...database.mongodb import db
import uuid
from datetime import datetime
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

async def get_scan_config(config_id: str, user: User) -> ScanConfiguration:
    """Get scan configuration and verify ownership"""
    config = await db.database["scan_configs"].find_one({
        "id": config_id,
        "user_id": user.id
    })
    if not config:
        raise HTTPException(status_code=404, detail="Scan configuration not found")
    return ScanConfiguration(**config)

async def run_scan(scan_id: str, config: ScanConfiguration, user: User):
    """Background task to run the security scan"""
    try:
        # Update scan status to in progress
        await db.database["scan_results"].update_one(
            {"id": scan_id},
            {"$set": {"status": ScanStatus.IN_PROGRESS}}
        )

        # Initialize AWS manager and scanner
        aws_manager = AWSManager(config.aws_credentials)
        scanner = SecurityScanner(aws_manager)

        findings = []
        total_resources = 0

        # Run scans for each service
        if "iam" in config.services:
            iam_results = await scanner.scan_iam()
            findings.extend(iam_results["findings"])
            total_resources += iam_results["scanned_resources"]

        if "s3" in config.services:
            s3_results = await scanner.scan_s3()
            findings.extend(s3_results["findings"])
            total_resources += s3_results["scanned_resources"]

        # Update scan results
        end_time = datetime.utcnow()
        await db.database["scan_results"].update_one(
            {"id": scan_id},
            {
                "$set": {
                    "status": ScanStatus.COMPLETED,
                    "findings": findings,
                    "total_resources_scanned": total_resources,
                    "end_time": end_time
                }
            }
        )

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        await db.database["scan_results"].update_one(
            {"id": scan_id},
            {
                "$set": {
                    "status": ScanStatus.FAILED,
                    "error_message": str(e),
                    "end_time": datetime.utcnow()
                }
            }
        )

@router.post("/configurations", response_model=ScanConfiguration)
async def create_scan_configuration(
    config: ScanConfiguration,
    current_user: User = Depends(get_current_user)
):
    """Create a new scan configuration"""
    config.user_id = current_user.id
    await db.database["scan_configs"].insert_one(config.dict())
    return config

@router.get("/configurations", response_model=List[ScanConfiguration])
async def list_scan_configurations(current_user: User = Depends(get_current_user)):
    """List all scan configurations for the current user"""
    configs = await db.database["scan_configs"].find(
        {"user_id": current_user.id}
    ).to_list(None)
    return [ScanConfiguration(**config) for config in configs]

@router.post("/start", response_model=ScanResult)
async def start_scan(
    config_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Start a new security scan"""
    config = await get_scan_config(config_id, current_user)
    
    # Create scan result
    scan_result = ScanResult(
        id=str(uuid.uuid4()),
        scan_config_id=config_id,
        user_id=current_user.id,
        services_scanned=config.services
    )
    
    # Save initial scan result
    await db.database["scan_results"].insert_one(scan_result.dict())
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_result.id, config, current_user)
    
    return scan_result

@router.get("/results/{scan_id}", response_model=ScanResult)
async def get_scan_results(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get results of a specific scan"""
    result = await db.database["scan_results"].find_one({
        "id": scan_id,
        "user_id": current_user.id
    })
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**result)

@router.get("/results", response_model=List[ScanResult])
async def list_scan_results(
    current_user: User = Depends(get_current_user),
    limit: int = 10,
    skip: int = 0
):
    """List scan results for the current user"""
    results = await db.database["scan_results"].find(
        {"user_id": current_user.id}
    ).sort("start_time", -1).skip(skip).limit(limit).to_list(None)
    return [ScanResult(**result) for result in results]

@router.get("/summary", response_model=ScanSummary)
async def get_scan_summary(current_user: User = Depends(get_current_user)):
    """Get summary of all scans for the current user"""
    pipeline = [
        {"$match": {"user_id": current_user.id}},
        {"$unwind": "$findings"},
        {
            "$group": {
                "_id": None,
                "total_scans": {"$sum": 1},
                "critical_findings": {
                    "$sum": {"$cond": [{"$eq": ["$findings.severity", "critical"]}, 1, 0]}
                },
                "high_findings": {
                    "$sum": {"$cond": [{"$eq": ["$findings.severity", "high"]}, 1, 0]}
                },
                "medium_findings": {
                    "$sum": {"$cond": [{"$eq": ["$findings.severity", "medium"]}, 1, 0]}
                },
                "low_findings": {
                    "$sum": {"$cond": [{"$eq": ["$findings.severity", "low"]}, 1, 0]}
                },
                "services_scanned": {"$addToSet": "$services_scanned"},
                "last_scan_time": {"$max": "$start_time"}
            }
        }
    ]
    
    summary = await db.database["scan_results"].aggregate(pipeline).to_list(1)
    if not summary:
        return ScanSummary(
            total_scans=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            services_scanned=[],
            last_scan_time=None
        )
    
    summary = summary[0]
    summary["services_scanned"] = [item for sublist in summary["services_scanned"] for item in sublist]
    return ScanSummary(**summary)
