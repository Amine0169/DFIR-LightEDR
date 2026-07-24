import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Host, ScanSession, Process, NetworkConnection, EventLog, RegistryKey, ScheduledTask
from app.detection.detection_manager import DetectionManager
from app.core.config import get_settings

logger = logging.getLogger("core.logger")

router = APIRouter()

class AgentCollectPayload(BaseModel):
    hostname: str
    os_type: str
    os_version: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    scan_type: str = "remote"
    sysmon_status: Optional[Dict[str, Any]] = None
    agent_version: Optional[str] = None
    agent_concept: Optional[str] = None
    kape_targets: List[str] = []
    processes: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    event_logs: List[Dict[str, Any]] = []
    registry_keys: List[Dict[str, Any]] = []
    scheduled_tasks: List[Dict[str, Any]] = []

@router.post("/api/ingest")
async def ingest_agent_data(payload: AgentCollectPayload, db: Session = Depends(get_db)):
    host = db.query(Host).filter_by(hostname=payload.hostname).first()
    if host:
        host.last_seen = datetime.now(timezone.utc)
        host.ip_address = payload.ip_address
        host.os_type = payload.os_type
        host.os_version = payload.os_version or host.os_version
    else:
        host = Host(
            hostname=payload.hostname,
            os_type=payload.os_type,
            os_version=payload.os_version or "",
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            username=payload.hostname,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(host)
    db.commit()
    db.refresh(host)

    sysmon_detected = False
    sysmon_events = 0
    if payload.sysmon_status:
        sysmon_detected = payload.sysmon_status.get("installed", False)
        sysmon_events = payload.sysmon_status.get("events_available", 0)

    session = ScanSession(
        host_id=host.id,
        scan_type=payload.scan_type,
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        agent_version=payload.agent_version,
        agent_concept=payload.agent_concept,
        kape_targets=",".join(payload.kape_targets) if payload.kape_targets else None,
        sysmon_detected=sysmon_detected,
        sysmon_events=sysmon_events,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    total_artifacts = 0

    for item in payload.processes:
        proc = Process(
            session_id=session.id,
            name=item.get("name", ""),
            pid=item.get("pid", 0),
            ppid=item.get("ppid"),
            path=item.get("exe"),
            cmdline=item.get("cmdline"),
            username=item.get("username"),
            hash_md5=item.get("md5"),
            hash_sha256=item.get("sha256"),
            is_suspicious=item.get("is_suspicious", False),
            suspicion_reason=item.get("suspicion_reason"),
        )
        db.add(proc)
        total_artifacts += 1

    for item in payload.network_connections:
        conn = NetworkConnection(
            session_id=session.id,
            local_ip=item.get("local_address") or "0.0.0.0",
            local_port=item.get("local_port") or 0,
            remote_ip=item.get("remote_address") or "0.0.0.0",
            remote_port=item.get("remote_port") or 0,
            protocol=item.get("protocol", "TCP"),
            state=item.get("status", "UNKNOWN"),
            pid=item.get("pid"),
            process_name=item.get("process_name"),
        )
        db.add(conn)
        total_artifacts += 1

    for item in payload.event_logs:
        timestamp = None
        if item.get("time_created"):
            try:
                timestamp = datetime.fromisoformat(item["time_created"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        evt = EventLog(
            session_id=session.id,
            source=item.get("provider", "unknown"),
            event_id_windows=int(item.get("event_id", 0)),
            level=item.get("level", "info"),
            channel=item.get("channel", ""),
            message=item.get("data", ""),
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        db.add(evt)
        total_artifacts += 1

    for item in payload.registry_keys:
        rk = RegistryKey(
            session_id=session.id,
            hive=item.get("hive", ""),
            key_path=item.get("key_path", ""),
            value_name=item.get("value_name", ""),
            value_data=str(item.get("value_data", "")),
            value_type=item.get("value_type", "REG_SZ"),
            is_persistence=item.get("is_persistence", False),
        )
        db.add(rk)
        total_artifacts += 1

    for item in payload.scheduled_tasks:
        st = ScheduledTask(
            session_id=session.id,
            name=item.get("name", ""),
            path=item.get("path", ""),
            command=item.get("command", ""),
            arguments=item.get("arguments"),
            trigger_type="scheduled",
            status=item.get("status", ""),
            author=item.get("author"),
        )
        db.add(st)
        total_artifacts += 1

    session.total_artifacts = total_artifacts
    db.commit()

    logger.info(f"Ingested {total_artifacts} artifacts from {payload.hostname} (session={session.id})")

    try:
        settings = get_settings()
        det_mgr = DetectionManager(settings.model_dump(), db)
        alerts = det_mgr.run_detection(session.id)
        session.total_alerts = len(alerts)
        db.commit()
        logger.info(f"Detection complete for session {session.id}: {len(alerts)} alerts")
    except Exception as e:
        logger.warning(f"Detection failed for session {session.id}: {e}")

    return {
        "status": "ok",
        "host_id": host.id,
        "session_id": session.id,
        "total_artifacts": total_artifacts,
        "total_alerts": session.total_alerts,
    }
