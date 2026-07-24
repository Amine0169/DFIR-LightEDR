from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any
from datetime import datetime, timezone

from app.database.database import get_db
from app.database.models import Host, ScanSession, Alert
from app.template_setup import templates

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    total_hosts = db.query(Host).count()
    total_scans = db.query(ScanSession).count()
    recent_alerts = db.query(Alert).order_by(Alert.detected_at.desc()).limit(10).all()
    
    alert_severity = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    alerts_by_severity = {sev: cnt for sev, cnt in alert_severity}
    
    latest_session = db.query(ScanSession).order_by(ScanSession.started_at.desc()).first()
    
    mitre_tactics = db.query(Alert.mitre_tactic, func.count(Alert.id)).filter(
        Alert.mitre_tactic.isnot(None)
    ).group_by(Alert.mitre_tactic).order_by(func.count(Alert.id).desc()).all()
    
    hosts = db.query(Host).order_by(Host.last_seen.desc()).all()
    
    context = {
        "total_hosts": total_hosts,
        "total_scans": total_scans,
        "total_alerts": sum(alerts_by_severity.values()) if alerts_by_severity else 0,
        "recent_alerts": recent_alerts,
        "alerts_by_severity": alerts_by_severity,
        "latest_scan": latest_session,
        "mitre_tactics": mitre_tactics,
        "hosts": hosts,
    }
    return templates.TemplateResponse(request, "dashboard.html", context)

@router.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    total_hosts = db.query(Host).count()
    total_scans = db.query(ScanSession).count()
    
    alert_severity = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    alerts_by_severity = {sev: cnt for sev, cnt in alert_severity}
    
    return {
        "total_hosts": total_hosts,
        "total_scans": total_scans,
        "alerts_by_severity": alerts_by_severity,
    }

@router.get("/api/alerts/recent")
async def get_recent_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.detected_at.desc()).limit(10).all()
    return [
        {
            "id": a.id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "description": a.description,
            "mitre_technique_id": a.mitre_technique_id,
            "detected_at": a.detected_at.isoformat(),
            "session_id": a.session_id,
        }
        for a in alerts
    ]

@router.get("/api/risk-trend")
async def get_risk_trend(db: Session = Depends(get_db)):
    sessions = db.query(ScanSession).order_by(ScanSession.started_at.asc()).limit(30).all()
    return {
        "labels": [s.started_at.strftime("%Y-%m-%d %H:%M") for s in sessions],
        "data": [s.total_alerts for s in sessions],
    }
