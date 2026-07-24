import json
import os
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database.database import get_db
from app.database.models import ScanSession, Alert, Report
from app.mitre.mapper import MitreMapper
from app.reporting.report_generator import ReportGenerator
from app.core.config import get_settings
from app.template_setup import templates

router = APIRouter()

@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    sessions = db.query(ScanSession).order_by(ScanSession.started_at.desc()).all()
    return templates.TemplateResponse(request, "reports.html", {
        "reports": reports,
        "sessions": sessions,
    })

@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def view_report(request: Request, report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        return HTMLResponse("<html><body><h1>Report not found</h1></body></html>")
    session = db.query(ScanSession).filter(ScanSession.id == report.session_id).first()
    alerts = db.query(Alert).filter(Alert.session_id == report.session_id).all()
    return templates.TemplateResponse(request, "report_detail.html", {
        "report": report,
        "session": session,
        "alerts": alerts,
    })

@router.post("/api/reports/generate/{session_id}")
async def generate_report(session_id: int, db: Session = Depends(get_db)):
    settings = get_settings()
    mapper = MitreMapper(settings.mitre.attack_data_path)
    report_gen = ReportGenerator(db, mapper)
    report_data = report_gen.generate_report(session_id)
    report_id = report_gen.save_report(report_data, session_id)
    
    summary = report_data.get("executive_summary", "")
    risk = report_data.get("risk_assessment", {"score": 0, "level": "Info"})
    alerts = db.query(Alert).filter(Alert.session_id == session_id).all()
    
    report = Report(
        session_id=session_id,
        title=f"Investigation Report - Session {session_id}",
        overall_risk_score=risk.get("score", 0),
        risk_level=risk.get("level", "Info"),
        total_alerts=len(alerts),
        total_critical=sum(1 for a in alerts if a.severity == "critical"),
        total_high=sum(1 for a in alerts if a.severity == "high"),
        total_medium=sum(1 for a in alerts if a.severity == "medium"),
        total_low=sum(1 for a in alerts if a.severity == "low"),
        summary=summary[:500],
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    return {"status": "success", "report_id": report.id}

@router.get("/api/reports/{report_id}/download")
async def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        return {"status": "error", "message": "Report not found"}
    return {
        "status": "success",
        "report_id": report.id,
        "title": report.title,
        "risk_level": report.risk_level,
        "risk_score": report.overall_risk_score,
        "summary": report.summary,
        "generated_at": report.generated_at.isoformat(),
    }
