"""
Report Model for Generated Reports Management
Phase 6 - Web Dashboard Backend
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.sql import func
from app.core.database import Base

class Report(Base):
    """Report model for managing generated reports"""
    
    __tablename__ = "reports"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Report identification
    report_uuid = Column(String(36), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Report configuration
    report_type = Column(String(50), nullable=False)  # executive, technical, comprehensive
    format = Column(String(20), nullable=False)  # html, json, pdf
    
    # File information
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)  # File size in bytes
    file_hash = Column(String(64), nullable=True)  # SHA256 hash for integrity
    
    # Content metadata
    target = Column(String(255), nullable=False, index=True)
    scan_data = Column(JSON, nullable=True)  # Summary of scan data used
    generation_parameters = Column(JSON, nullable=True)  # Parameters used for generation
    
    # Status and processing
    status = Column(String(50), default="pending", index=True)  # pending, generating, completed, failed
    generation_time = Column(Integer, nullable=True)  # Generation time in seconds
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    # Associated scan
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    
    # User association
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Access control
    is_public = Column(Boolean, default=False)
    shared_with = Column(JSON, nullable=True)  # List of user IDs who can access
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    accessed_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<Report(id={self.id}, name='{self.name}', format='{self.format}')>"
    
    def to_dict(self):
        """Convert report to dictionary"""
        return {
            "id": self.id,
            "report_uuid": self.report_uuid,
            "name": self.name,
            "description": self.description,
            "report_type": self.report_type,
            "format": self.format,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "target": self.target,
            "scan_data": self.scan_data,
            "generation_parameters": self.generation_parameters,
            "status": self.status,
            "generation_time": self.generation_time,
            "error_message": self.error_message,
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "is_public": self.is_public,
            "shared_with": self.shared_with,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "accessed_at": self.accessed_at.isoformat() if self.accessed_at else None
        }
    
    def to_summary(self):
        """Convert report to summary format"""
        return {
            "id": self.id,
            "report_uuid": self.report_uuid,
            "name": self.name,
            "target": self.target,
            "report_type": self.report_type,
            "format": self.format,
            "file_size": self.file_size,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

# Relationships will be handled through imports in __init__.py
