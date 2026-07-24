from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import Alert
from app.mitre.mapper import MitreMapper
from app.core.config import get_settings
from app.template_setup import templates

router = APIRouter()

@router.get("/mitre", response_class=HTMLResponse)
async def mitre_page(request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    mapper = MitreMapper(settings.mitre.attack_data_path)
    alerts = db.query(Alert).filter(Alert.mitre_technique_id.isnot(None)).all()
    alert_dicts = [{"mitre_technique": a.mitre_technique_id} for a in alerts]
    
    coverage = mapper.get_technique_coverage(alert_dicts)
    tactic_summary = mapper.get_tactic_summary(alert_dicts)
    tactics = mapper.get_all_tactics()
    
    techniques_by_tactic = {}
    for tactic in tactics:
        techniques_by_tactic[tactic] = mapper.get_techniques_by_tactic(tactic)
    
    return templates.TemplateResponse(request, "mitre.html", {
        "coverage": coverage,
        "tactic_summary": tactic_summary,
        "tactics": tactics,
        "techniques_by_tactic": techniques_by_tactic,
    })

@router.get("/api/mitre/coverage")
async def get_mitre_coverage(db: Session = Depends(get_db)):
    results = db.query(Alert.mitre_technique_id, Alert.mitre_tactic, func.count(Alert.id)).filter(
        Alert.mitre_technique_id.isnot(None)
    ).group_by(Alert.mitre_technique_id).all()
    
    return [
        {"technique": tech_id, "tactic": tactic, "count": cnt}
        for tech_id, tactic, cnt in results
    ]

@router.get("/api/mitre/technique/{technique_id}")
async def get_technique_details(technique_id: str, db: Session = Depends(get_db)):
    settings = get_settings()
    mapper = MitreMapper(settings.mitre.attack_data_path)
    tech_info = mapper.map_technique(technique_id)
    
    alerts = db.query(Alert).filter(Alert.mitre_technique_id == technique_id).all()
    
    return {
        "id": technique_id,
        "info": tech_info,
        "related_alerts": [
            {"id": a.id, "rule_name": a.rule_name, "severity": a.severity, "detected_at": a.detected_at.isoformat()}
            for a in alerts
        ],
    }
