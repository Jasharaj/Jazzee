from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, WebSocket
from typing import List, Optional
from sqlalchemy.orm import Session
from ..models.scan import (
    ScanConfiguration as ScanConfigSchema,
    ScanResult as ScanResultSchema,
    ScanSummary,
    AWSCredentials,
    ScanStatus,
    Finding
)
from ..models.database import ScanConfiguration, ScanResult
from ..core.aws import AWSManager, SecurityScanner
from ..core.websocket import manager
from ..core.database import get_db
from ..api.auth import get_current_user
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/scan-configs", response_model=ScanConfigSchema)
async def create_scan_configuration(config: ScanConfigSchema, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Create a new scan configuration"""
    try:
        db_config = ScanConfiguration(
            user_id=current_user.email,
            name=config.name,
            description=config.description,
            aws_credentials=config.aws_credentials.model_dump(),
            services=config.services
        )
        db.add(db_config)
        db.commit()
        db.refresh(db_config)
        
        return ScanConfigSchema(
            id=str(db_config.id),
            user_id=db_config.user_id,
            name=db_config.name,
            description=db_config.description,
            aws_credentials=AWSCredentials(**db_config.aws_credentials),
            services=db_config.services,
            created_at=db_config.created_at.isoformat(),
            updated_at=db_config.updated_at.isoformat()
        )
    except Exception as e:
        logger.error(f"Failed to create scan configuration: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-configs", response_model=List[ScanConfigSchema])
async def list_scan_configurations(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all scan configurations for the current user"""
    try:
        db_configs = db.query(ScanConfiguration).filter(ScanConfiguration.user_id == current_user.email).all()
        return [
            ScanConfigSchema(
                id=str(config.id),
                user_id=config.user_id,
                name=config.name,
                description=config.description,
                aws_credentials=AWSCredentials(**config.aws_credentials),
                services=config.services,
                created_at=config.created_at.isoformat(),
                updated_at=config.updated_at.isoformat()
            )
            for config in db_configs
        ]
    except Exception as e:
        logger.error(f"Failed to list scan configurations: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_scan(scan_result_id: int, db: Session):
    """Background task to run a security scan"""
    try:
        # Get scan result and configuration
        db_scan_result = db.query(ScanResult).filter(ScanResult.id == scan_result_id).first()
        if not db_scan_result:
            raise ValueError("Scan result not found")

        db_config = db.query(ScanConfiguration).filter(ScanConfiguration.id == db_scan_result.scan_config_id).first()
        if not db_config:
            raise ValueError("Scan configuration not found")

        # Update scan status to in progress
        db_scan_result.status = ScanStatus.IN_PROGRESS
        db_scan_result.updated_at = datetime.utcnow()
        db.commit()

        # Send status update via WebSocket
        await manager.send_message({
            "type": "scan_update",
            "data": {
                "scan_id": str(db_scan_result.id),
                "status": ScanStatus.IN_PROGRESS
            }
        }, db_scan_result.user_id)

        # Initialize AWS scanner
        aws_manager = AWSManager(AWSCredentials(**db_config.aws_credentials))
        scanner = SecurityScanner(aws_manager)
        await scanner.initialize()

        # Run scans for each service
        findings = []
        services_scanned = []
        total_resources = 0

        for service in db_config.services:
            try:
                # Send service scan start update
                await manager.send_message({
                    "type": "service_scan",
                    "data": {
                        "scan_id": str(db_scan_result.id),
                        "service": service,
                        "status": "started"
                    }
                }, db_scan_result.user_id)

                service_findings = await scanner.scan_service(service)
                if service_findings:
                    findings.extend([finding.model_dump() for finding in service_findings])
                    services_scanned.append(service)

                # Send service scan completion update
                await manager.send_message({
                    "type": "service_scan",
                    "data": {
                        "scan_id": str(db_scan_result.id),
                        "service": service,
                        "status": "completed",
                        "findings_count": len(service_findings) if service_findings else 0
                    }
                }, db_scan_result.user_id)

            except Exception as e:
                logger.error(f"Error scanning service {service}: {str(e)}")
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
                findings.append(error_finding.model_dump())

                # Send service scan error update
                await manager.send_message({
                    "type": "service_scan",
                    "data": {
                        "scan_id": str(db_scan_result.id),
                        "service": service,
                        "status": "error",
                        "error": str(e)
                    }
                }, db_scan_result.user_id)

        # Update scan result with findings
        db_scan_result.findings = findings
        db_scan_result.services_scanned = services_scanned
        db_scan_result.total_resources_scanned = total_resources
        db_scan_result.status = ScanStatus.COMPLETED
        db_scan_result.updated_at = datetime.utcnow()
        db.commit()

        # Send final update via WebSocket
        await manager.send_message({
            "type": "scan_complete",
            "data": {
                "scan_id": str(db_scan_result.id),
                "findings_count": len(findings),
                "services_scanned": services_scanned
            }
        }, db_scan_result.user_id)

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        if db_scan_result:
            db_scan_result.status = ScanStatus.FAILED
            db_scan_result.error_message = str(e)
            db_scan_result.updated_at = datetime.utcnow()
            db.commit()

            # Send error update via WebSocket
            await manager.send_message({
                "type": "scan_error",
                "data": {
                    "scan_id": str(db_scan_result.id),
                    "error": str(e)
                }
            }, db_scan_result.user_id)

@router.post("/scans/{config_id}/start")
async def start_scan(config_id: str, background_tasks: BackgroundTasks, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Start a new security scan"""
    try:
        # Check if configuration exists
        db_config = db.query(ScanConfiguration).filter(
            ScanConfiguration.id == int(config_id),
            ScanConfiguration.user_id == current_user.email
        ).first()
        if not db_config:
            raise HTTPException(status_code=404, detail="Scan configuration not found")

        # Create scan result
        db_scan_result = ScanResult(
            scan_config_id=db_config.id,
            user_id=current_user.email,
            status=ScanStatus.PENDING,
            findings=[],
            services_scanned=[],
            total_resources_scanned=0
        )
        db.add(db_scan_result)
        db.commit()
        db.refresh(db_scan_result)

        # Start background scan
        background_tasks.add_task(run_scan, db_scan_result.id, db)
        
        return {"scan_id": str(db_scan_result.id)}
    except Exception as e:
        logger.error(f"Failed to start scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans", response_model=List[ScanResultSchema])
async def list_scan_results(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """List scan results for the current user"""
    try:
        db_results = db.query(ScanResult).filter(ScanResult.user_id == current_user.email).all()
        return [
            ScanResultSchema(
                id=str(result.id),
                scan_config_id=str(result.scan_config_id),
                user_id=result.user_id,
                status=result.status,
                findings=[Finding(**finding) for finding in result.findings],
                services_scanned=result.services_scanned,
                total_resources_scanned=result.total_resources_scanned,
                created_at=result.created_at.isoformat(),
                updated_at=result.updated_at.isoformat(),
                error_message=result.error_message
            )
            for result in db_results
        ]
    except Exception as e:
        logger.error(f"Failed to list scan results: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summary", response_model=ScanSummary)
async def get_summary(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get a summary of all scans for the current user"""
    try:
        # Initialize summary with default values
        summary = {
            "total_scans": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "services_scanned": set(),
            "last_scan_time": None
        }
        
        # Get all completed scans for the user
        db_results = db.query(ScanResult).filter(
            ScanResult.user_id == current_user.email,
            ScanResult.status == ScanStatus.COMPLETED
        ).all()
        
        # Calculate summary
        for scan in db_results:
            summary["total_scans"] += 1
            
            # Update last scan time
            scan_time = scan.updated_at or scan.created_at
            if scan_time and (not summary["last_scan_time"] or scan_time > summary["last_scan_time"]):
                summary["last_scan_time"] = scan_time
            
            # Count findings by severity
            for finding in scan.findings:
                severity = finding.get("severity", "").lower()
                if severity == "critical":
                    summary["critical_findings"] += 1
                elif severity == "high":
                    summary["high_findings"] += 1
                elif severity == "medium":
                    summary["medium_findings"] += 1
                elif severity == "low":
                    summary["low_findings"] += 1
            
            # Add scanned services
            summary["services_scanned"].update(scan.services_scanned)
        
        # Convert set to list for JSON serialization
        summary["services_scanned"] = list(summary["services_scanned"])
        
        # Convert last_scan_time to ISO format if exists
        if summary["last_scan_time"]:
            summary["last_scan_time"] = summary["last_scan_time"].isoformat()
        
        return ScanSummary(**summary)
    except Exception as e:
        logger.error(f"Failed to get summary: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    """WebSocket endpoint for real-time scan updates"""
    try:
        if not token:
            await websocket.close(code=1008, reason="No authentication token provided")
            return

        current_user = await get_current_user(token)
        if not current_user:
            await websocket.close(code=1008, reason="Invalid authentication token")
            return

        await manager.connect(websocket, current_user.email)
        try:
            while True:
                data = await websocket.receive_text()
                # Handle any incoming messages if needed
        except Exception as e:
            logger.error(f"WebSocket error: {str(e)}")
        finally:
            manager.disconnect(websocket, current_user.email)
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        try:
            await websocket.close(code=1011, reason=str(e))
        except:
            pass
