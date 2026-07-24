from fastapi import APIRouter, Request, Query, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional

from app.database.database import get_db
from app.database.models import Alert
from app.template_setup import templates

router = APIRouter()

@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.detected_at.desc()).limit(100).all()
    return templates.TemplateResponse(request, "alerts.html", {"alerts": alerts})

@router.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    total = query.count()
    items = query.order_by(Alert.detected_at.desc()).offset(offset).limit(limit).all()
    return {
        "items": [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "rule_type": a.rule_type,
                "severity": a.severity,
                "description": a.description,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_tactic": a.mitre_tactic,
                "risk_score": a.risk_score,
                "detected_at": a.detected_at.isoformat(),
                "is_resolved": a.is_resolved,
            }
            for a in items
        ],
        "total": total,
    }

@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"error": "Alert not found"}
    return {
        "id": alert.id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "description": alert.description,
        "mitre_technique_id": alert.mitre_technique_id,
        "mitre_tactic": alert.mitre_tactic,
        "risk_score": alert.risk_score,
        "detected_at": alert.detected_at.isoformat(),
        "is_resolved": alert.is_resolved,
    }

@router.put("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"status": "error", "message": "Alert not found"}
    alert.is_resolved = True
    db.commit()
    return {"status": "success", "message": f"Alert {alert_id} resolved"}
