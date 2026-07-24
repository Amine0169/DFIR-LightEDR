from typing import List, Optional
from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import ScanSession, Alert, Process, NetworkConnection, RegistryKey, EventLog
from app.collector.collector_manager import CollectorManager
from app.collector.kape_targets import KAPE_TARGETS, get_targets_by_category
from app.detection.detection_manager import DetectionManager
from app.core.config import get_settings
from app.template_setup import templates

router = APIRouter()

@router.get("/investigations", response_class=HTMLResponse)
async def investigations_page(request: Request, db: Session = Depends(get_db)):
    sessions = db.query(ScanSession).order_by(ScanSession.started_at.desc()).all()
    return templates.TemplateResponse(request, "investigations.html", {"sessions": sessions})

@router.get("/investigations/{session_id}", response_class=HTMLResponse)
async def investigation_detail(request: Request, session_id: int, db: Session = Depends(get_db)):
    session = db.query(ScanSession).filter(ScanSession.id == session_id).first()
    alerts = db.query(Alert).filter(Alert.session_id == session_id).all()
    processes = db.query(Process).filter(Process.session_id == session_id).limit(50).all()
    connections = db.query(NetworkConnection).filter(NetworkConnection.session_id == session_id).limit(50).all()
    registry = db.query(RegistryKey).filter(RegistryKey.session_id == session_id).all()
    kape_targets_list = session.kape_targets.split(",") if session and session.kape_targets else []
    return templates.TemplateResponse(request, "investigation_detail.html", {
        "session": session,
        "alerts": alerts,
        "processes": processes,
        "connections": connections,
        "registry": registry,
        "kape_targets_list": kape_targets_list,
        "kape_categories": get_targets_by_category(),
    })

@router.get("/api/hunt/{host_id}")
async def hunt_host(
    host_id: int,
    targets: Optional[str] = Query(None, description="Comma-separated KAPE target names"),
    db: Session = Depends(get_db),
):
    """
    Velociraptor-inspired live hunt: query a host for specific artifact targets.
    GET /api/hunt/1?targets=Processes,Network,Sysmon_Events
    """
    from app.database.models import Host
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        return {"error": "Host not found"}

    if targets:
        target_list = [t.strip() for t in targets.split(",") if t.strip() in KAPE_TARGETS]
    else:
        target_list = list(KAPE_TARGETS.keys())

    return {
        "host": host.hostname,
        "ip": host.ip_address,
        "concept": "Velociraptor-inspired live hunt query",
        "targets_requested": target_list,
        "targets_detail": {t: KAPE_TARGETS[t] for t in target_list if t in KAPE_TARGETS},
    }

@router.post("/api/scan")
async def trigger_scan(db: Session = Depends(get_db)):
    settings = get_settings()
    mgr = CollectorManager(db, settings)
    result = mgr.run_full_scan()
    det_mgr = DetectionManager(settings.model_dump(), db)
    det_mgr.run_detection(result["session_id"])
    return {"status": "started", "session_id": result["session_id"]}

@router.get("/api/scan/{session_id}/status")
async def scan_status(session_id: int, db: Session = Depends(get_db)):
    session = db.query(ScanSession).filter(ScanSession.id == session_id).first()
    if not session:
        return {"error": "Session not found"}
    return {
        "session_id": session.id,
        "status": session.status,
        "total_artifacts": session.total_artifacts,
        "total_alerts": session.total_alerts,
        "started_at": session.started_at.isoformat(),
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
    }
