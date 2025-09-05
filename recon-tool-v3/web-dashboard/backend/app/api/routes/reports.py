"""
Report Management API Routes
Phase 6 - Web Dashboard Backend
"""

import uuid
import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path for recon_tool imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent.parent))

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.report import Report
from app.models.scan import Scan

router = APIRouter()

# Pydantic models
class ReportCreate(BaseModel):
    name: str
    description: str = None
    report_type: str = "comprehensive"  # executive, technical, comprehensive
    format: str = "html"  # html, json, pdf
    scan_id: int = None
    target: str = None
    generation_parameters: dict = None

class ReportResponse(BaseModel):
    id: int
    report_uuid: str
    name: str
    description: Optional[str] = None
    report_type: str
    format: str
    file_path: str
    file_size: Optional[int] = None
    target: str
    status: str
    generation_time: Optional[int] = None
    scan_id: Optional[int] = None
    created_at: str

class ReportSummary(BaseModel):
    id: int
    report_uuid: str
    name: str
    target: str
    report_type: str
    format: str
    file_size: Optional[int] = None
    status: str
    created_at: str

# Background task to generate report
async def generate_report_background(report_id: int, db_path: str):
    """Background task to generate the actual report"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import json
    import time
    
    # Create new database session for background task
    engine = create_engine(f"sqlite:///{db_path}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    try:
        # Get report from database
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return
        
        # Update status to generating
        report.status = "generating"
        db.commit()
        
        start_time = time.time()
        
        # Create reports directory if it doesn't exist
        reports_dir = Path(__file__).parent.parent.parent.parent.parent / "results" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{report.target}_{report.report_type}_{timestamp}.{report.format}"
        file_path = reports_dir / filename
        
        # Mock report generation based on format
        if report.format == "html":
            # Generate HTML report
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - {report.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
        .finding {{ border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Reconnaissance Report</h1>
        <h2>{report.target}</h2>
        <p>Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
        <p>Report Type: {report.report_type.title()}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report contains the results of reconnaissance activities conducted against {report.target}.</p>
        <ul>
            <li><strong>Subdomains Found:</strong> 12</li>
            <li><strong>Open Ports:</strong> 8</li>
            <li><strong>Vulnerabilities:</strong> 3</li>
            <li><strong>Risk Level:</strong> Medium</li>
        </ul>
    </div>
    
    <h2>Detailed Findings</h2>
    
    <div class="finding high">
        <h3>Missing Security Headers</h3>
        <p><strong>Severity:</strong> High</p>
        <p><strong>Description:</strong> The target website is missing critical security headers.</p>
        <p><strong>Recommendation:</strong> Implement proper security headers including HSTS, CSP, and X-Frame-Options.</p>
    </div>
    
    <div class="finding medium">
        <h3>Subdomain Enumeration</h3>
        <p><strong>Severity:</strong> Medium</p>
        <p><strong>Description:</strong> Multiple subdomains discovered that may expand attack surface.</p>
        <p><strong>Subdomains:</strong> api.{report.target}, admin.{report.target}, dev.{report.target}</p>
    </div>
    
    <div class="finding low">
        <h3>Open Ports</h3>
        <p><strong>Severity:</strong> Low</p>
        <p><strong>Description:</strong> Standard web services detected.</p>
        <p><strong>Ports:</strong> 80/tcp (HTTP), 443/tcp (HTTPS)</p>
    </div>
    
    <h2>Recommendations</h2>
    <ol>
        <li>Implement security headers to protect against common attacks</li>
        <li>Review subdomain exposure and secure development environments</li>
        <li>Conduct regular security assessments</li>
        <li>Monitor for new subdomains and services</li>
    </ol>
    
    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
        <p><small>This report was generated by Recon-Tool-v3 Web Dashboard</small></p>
    </div>
</body>
</html>
"""
            with open(file_path, 'w') as f:
                f.write(html_content)
        
        elif report.format == "json":
            # Generate JSON report
            json_data = {
                "report_info": {
                    "target": report.target,
                    "report_type": report.report_type,
                    "generated_at": datetime.utcnow().isoformat(),
                    "scan_id": report.scan_id
                },
                "summary": {
                    "subdomains_found": 12,
                    "open_ports": 8,
                    "vulnerabilities": 3,
                    "risk_level": "Medium"
                },
                "findings": [
                    {
                        "id": 1,
                        "type": "vulnerability",
                        "severity": "high",
                        "title": "Missing Security Headers",
                        "description": "The target website is missing critical security headers",
                        "recommendation": "Implement proper security headers"
                    },
                    {
                        "id": 2,
                        "type": "subdomain",
                        "severity": "medium",
                        "title": "Subdomain Enumeration",
                        "subdomains": [f"api.{report.target}", f"admin.{report.target}", f"dev.{report.target}"]
                    },
                    {
                        "id": 3,
                        "type": "port_scan",
                        "severity": "low",
                        "title": "Open Ports",
                        "ports": ["80/tcp", "443/tcp"]
                    }
                ],
                "recommendations": [
                    "Implement security headers to protect against common attacks",
                    "Review subdomain exposure and secure development environments",
                    "Conduct regular security assessments",
                    "Monitor for new subdomains and services"
                ]
            }
            
            with open(file_path, 'w') as f:
                json.dump(json_data, f, indent=2)
        
        # Update report with completion info
        generation_time = int(time.time() - start_time)
        file_size = os.path.getsize(file_path)
        
        report.status = "completed"
        report.file_path = str(file_path)
        report.file_size = file_size
        report.generation_time = generation_time
        db.commit()
        
    except Exception as e:
        # Handle generation failure
        report.status = "failed"
        report.error_message = str(e)
        db.commit()
    
    finally:
        db.close()

@router.post("/", response_model=ReportResponse)
async def create_report(
    report_data: ReportCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create and generate a new report"""
    
    # Validate scan if provided
    scan = None
    if report_data.scan_id:
        scan = db.query(Scan).filter(
            Scan.id == report_data.scan_id,
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
                detail="Cannot generate report for incomplete scan"
            )
    
    # Determine target
    target = report_data.target or (scan.target if scan else "unknown")
    
    # Generate UUID for report
    report_uuid = str(uuid.uuid4())
    
    # Create report record
    report = Report(
        report_uuid=report_uuid,
        name=report_data.name,
        description=report_data.description,
        report_type=report_data.report_type,
        format=report_data.format,
        target=target,
        scan_id=report_data.scan_id,
        generation_parameters=report_data.generation_parameters,
        status="pending",
        user_id=current_user.id,
        file_path=""  # Will be set by background task
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    # Start background generation task
    background_tasks.add_task(
        generate_report_background,
        report.id,
        "recon_dashboard.db"
    )
    
    return report.to_dict()

@router.get("/", response_model=List[ReportSummary])
async def list_reports(
    skip: int = 0,
    limit: int = 100,
    format: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user's reports"""
    query = db.query(Report).filter(Report.user_id == current_user.id)
    
    if format:
        query = query.filter(Report.format == format)
    if status:
        query = query.filter(Report.status == status)
    
    reports = query.order_by(Report.created_at.desc()).offset(skip).limit(limit).all()
    return [report.to_summary() for report in reports]

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get report details"""
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id
    ).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    return report.to_dict()

@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download report file"""
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id
    ).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    if report.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report not ready for download"
        )
    
    if not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found"
        )
    
    # Update access time
    report.accessed_at = datetime.utcnow()
    db.commit()
    
    # Determine media type
    media_type = {
        "html": "text/html",
        "json": "application/json",
        "pdf": "application/pdf"
    }.get(report.format, "application/octet-stream")
    
    filename = f"{report.name}.{report.format}"
    
    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename
    )

@router.delete("/{report_id}")
async def delete_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete report"""
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id
    ).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Delete file if exists
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except Exception as e:
            print(f"Warning: Could not delete report file: {e}")
    
    # Delete database record
    db.delete(report)
    db.commit()
    
    return {"message": "Report deleted successfully"}
