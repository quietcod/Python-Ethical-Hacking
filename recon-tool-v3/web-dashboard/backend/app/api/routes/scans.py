"""
Scan Management API Routes
Phase 6 - Web Dashboard Backend
"""

import uuid
import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
import sys
import os
from pathlib import Path

# Add parent directory to path for recon_tool imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent.parent))

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.websocket_manager import websocket_manager
from app.models.user import User
from app.models.scan import Scan

router = APIRouter()

# Pydantic models
class ScanCreate(BaseModel):
    name: str
    description: str = None
    target: str
    target_type: str = "domain"  # domain, ip, url, cidr
    profile: str = "quick"  # quick, full, passive, web_focused, network_focused, osint_focused
    tools: List[str] = None
    parameters: dict = None

class ScanUpdate(BaseModel):
    name: str = None
    description: str = None
    status: str = None

class ScanResponse(BaseModel):
    id: int
    scan_uuid: str
    name: str
    description: Optional[str] = None
    target: str
    target_type: str
    profile: str
    tools: Optional[List[str]] = None
    parameters: Optional[dict] = None
    status: str
    progress: int
    current_tool: Optional[str] = None
    results: Optional[dict] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: Optional[int] = None
    error_message: Optional[str] = None
    created_at: str

class ScanSummary(BaseModel):
    id: int
    scan_uuid: str
    name: str
    target: str
    profile: str
    status: str
    progress: int
    start_time: Optional[str] = None
    duration: Optional[int] = None
    created_at: str

# Background task to run actual scan
async def run_scan_background(scan_id: int, db_path: str):
    """Background task to execute the actual reconnaissance scan"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Create new database session for background task
    engine = create_engine(f"sqlite:///{db_path}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    try:
        # Get scan from database
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        # Update scan status to running
        scan.status = "running"
        scan.start_time = datetime.utcnow()
        scan.progress = 5
        db.commit()
        
        # Send WebSocket update
        await websocket_manager.send_scan_update(
            f"user_{scan.user_id}",  # Use user_id as client_id
            {
                "scan_id": scan.id,
                "status": "running",
                "progress": 5,
                "message": "Scan started"
            }
        )
        
        # Simulate scan progress (replace with actual recon_tool integration)
        tools = ["subdomain_enumerator", "network_scanner", "port_scanner", "vulnerability_scanner"]
        progress_step = 90 // len(tools)  # Leave 10% for completion
        
        for i, tool in enumerate(tools):
            # Update current tool and progress
            scan.current_tool = tool
            scan.progress = 10 + (i * progress_step)
            db.commit()
            
            # Send progress update
            await websocket_manager.send_scan_update(
                f"user_{scan.user_id}",
                {
                    "scan_id": scan.id,
                    "status": "running",
                    "progress": scan.progress,
                    "current_tool": tool,
                    "message": f"Running {tool}"
                }
            )
            
            # Simulate tool execution time
            await asyncio.sleep(2)
        
        # Complete scan
        scan.status = "completed"
        scan.progress = 100
        scan.end_time = datetime.utcnow()
        scan.duration = int((scan.end_time - scan.start_time).total_seconds())
        scan.current_tool = None
        
        # Mock results
        scan.results = {
            "summary": {
                "target": scan.target,
                "profile": scan.profile,
                "tools_run": tools,
                "findings_count": 15,
                "vulnerabilities": 3,
                "ports_found": 8,
                "subdomains_found": 12
            },
            "findings": [
                {
                    "tool": "subdomain_enumerator",
                    "type": "subdomain",
                    "value": f"api.{scan.target}",
                    "confidence": "high"
                },
                {
                    "tool": "port_scanner",
                    "type": "open_port",
                    "value": "80/tcp",
                    "service": "http"
                },
                {
                    "tool": "vulnerability_scanner",
                    "type": "vulnerability",
                    "value": "Missing security headers",
                    "severity": "medium"
                }
            ]
        }
        
        db.commit()
        
        # Send completion notification
        await websocket_manager.send_scan_complete(
            f"user_{scan.user_id}",
            {
                "scan_id": scan.id,
                "status": "completed",
                "progress": 100,
                "duration": scan.duration,
                "results": scan.results
            }
        )
        
    except Exception as e:
        # Handle scan failure
        scan.status = "failed"
        scan.error_message = str(e)
        scan.end_time = datetime.utcnow()
        if scan.start_time:
            scan.duration = int((scan.end_time - scan.start_time).total_seconds())
        db.commit()
        
        # Send error notification
        await websocket_manager.send_error(
            f"user_{scan.user_id}",
            f"Scan failed: {str(e)}"
        )
    
    finally:
        db.close()

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create and start a new reconnaissance scan"""
    
    # Generate UUID for scan
    scan_uuid = str(uuid.uuid4())
    
    # Create scan record
    scan = Scan(
        scan_uuid=scan_uuid,
        name=scan_data.name,
        description=scan_data.description,
        target=scan_data.target,
        target_type=scan_data.target_type,
        profile=scan_data.profile,
        tools=scan_data.tools,
        parameters=scan_data.parameters,
        status="pending",
        progress=0,
        user_id=current_user.id
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Start background scan task
    background_tasks.add_task(
        run_scan_background,
        scan.id,
        "recon_dashboard.db"  # Pass database path
    )
    
    return scan.to_dict()

@router.get("/", response_model=List[ScanSummary])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user's scans"""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return [scan.to_summary() for scan in scans]

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan details"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan.to_dict()

@router.put("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: int,
    scan_update: ScanUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update scan (limited operations)"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Update allowed fields
    if scan_update.name is not None:
        scan.name = scan_update.name
    if scan_update.description is not None:
        scan.description = scan_update.description
    
    # Handle status changes (limited)
    if scan_update.status is not None:
        if scan_update.status == "cancelled" and scan.status in ["pending", "running"]:
            scan.status = "cancelled"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status change"
            )
    
    db.commit()
    db.refresh(scan)
    
    return scan.to_dict()

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete scan"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Only allow deletion of completed, failed, or cancelled scans
    if scan.status in ["running", "pending"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete running or pending scan"
        )
    
    db.delete(scan)
    db.commit()
    
    return {"message": "Scan deleted successfully"}

@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed scan results"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan not completed yet"
        )
    
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "results": scan.results,
        "completed_at": scan.end_time.isoformat() if scan.end_time else None
    }
