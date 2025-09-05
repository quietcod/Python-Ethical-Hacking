"""
Scan Model for Reconnaissance Scan Management
Phase 6 - Web Dashboard Backend
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.sql import func
from app.core.database import Base

class Scan(Base):
    """Scan model for managing reconnaissance scans"""
    
    __tablename__ = "scans"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Scan identification
    scan_uuid = Column(String(36), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Target information
    target = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # domain, ip, url, cidr
    
    # Scan configuration
    profile = Column(String(100), nullable=False)  # quick, full, passive, etc.
    tools = Column(JSON, nullable=True)  # List of tools to run
    parameters = Column(JSON, nullable=True)  # Additional scan parameters
    
    # Scan status and progress
    status = Column(String(50), default="pending", index=True)  # pending, running, completed, failed, cancelled
    progress = Column(Integer, default=0)  # Progress percentage (0-100)
    current_tool = Column(String(100), nullable=True)  # Currently running tool
    
    # Results and output
    results = Column(JSON, nullable=True)  # Scan results in JSON format
    output_directory = Column(String(500), nullable=True)  # Path to output files
    log_file = Column(String(500), nullable=True)  # Path to log file
    
    # Performance metrics
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in seconds
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    # User association
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<Scan(id={self.id}, target='{self.target}', status='{self.status}')>"
    
    def to_dict(self):
        """Convert scan to dictionary"""
        return {
            "id": self.id,
            "scan_uuid": self.scan_uuid,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "target_type": self.target_type,
            "profile": self.profile,
            "tools": self.tools,
            "parameters": self.parameters,
            "status": self.status,
            "progress": self.progress,
            "current_tool": self.current_tool,
            "results": self.results,
            "output_directory": self.output_directory,
            "log_file": self.log_file,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "error_message": self.error_message,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_summary(self):
        """Convert scan to summary format"""
        return {
            "id": self.id,
            "scan_uuid": self.scan_uuid,
            "name": self.name,
            "target": self.target,
            "profile": self.profile,
            "status": self.status,
            "progress": self.progress,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "duration": self.duration,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

# Relationships will be handled through imports in __init__.py
