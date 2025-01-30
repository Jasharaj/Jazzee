from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from ..core.database import Base
from datetime import datetime

class ScanConfiguration(Base):
    __tablename__ = "scan_configurations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    aws_credentials = Column(JSON)
    services = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = relationship("ScanResult", back_populates="scan_config")

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_config_id = Column(Integer, ForeignKey("scan_configurations.id"))
    user_id = Column(String, index=True)
    status = Column(String)
    findings = Column(JSON, default=list)
    services_scanned = Column(JSON, default=list)
    total_resources_scanned = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error_message = Column(String, nullable=True)

    scan_config = relationship("ScanConfiguration", back_populates="scan_results")
