from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import Host, ScanSession, Alert
from app.template_setup import templates

router = APIRouter()

@router.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request, db: Session = Depends(get_db)):
    hosts = db.query(Host).all()
    return templates.TemplateResponse(request, "hosts.html", {"hosts": hosts})

@router.get("/api/hosts")
async def get_hosts(db: Session = Depends(get_db)):
    hosts = db.query(Host).all()
    return [
        {
            "id": h.id,
            "hostname": h.hostname,
            "os_type": h.os_type,
            "ip_address": h.ip_address,
            "last_seen": h.last_seen.isoformat(),
            "status": h.status,
        }
        for h in hosts
    ]

@router.get("/api/hosts/{host_id}")
async def get_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        return {"error": "Host not found"}
    
    session_count = db.query(ScanSession).filter(ScanSession.host_id == host_id).count()
    alert_count = db.query(Alert).join(ScanSession).filter(ScanSession.host_id == host_id).count()
    
    return {
        "id": host.id,
        "hostname": host.hostname,
        "os_type": host.os_type,
        "os_version": host.os_version,
        "ip_address": host.ip_address,
        "mac_address": host.mac_address,
        "first_seen": host.first_seen.isoformat(),
        "last_seen": host.last_seen.isoformat(),
        "status": host.status,
        "session_count": session_count,
        "alert_count": alert_count,
    }
