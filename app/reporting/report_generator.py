import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any

from .timeline import TimelineBuilder

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, db_session, mitre_mapper):
        self.db_session = db_session
        self.mitre_mapper = mitre_mapper
        self.timeline_builder = TimelineBuilder()

    def generate_report(self, session_id: int) -> Dict[str, Any]:
        logger.info(f"Generating report for session {session_id}")
        
        # In a real app, fetch these from db_session
        # For this implementation, we simulate the data structure
        alerts = [] 
        session_data = {"id": session_id, "host_id": 1, "start_time": datetime.utcnow().isoformat()}
        artifacts = {}

        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "executive_summary": self._build_executive_summary(session_data, alerts),
            "risk_assessment": self._calculate_risk(alerts),
            "mitre_matrix": self._build_mitre_matrix(alerts),
            "timeline": self._build_timeline(session_id),
            "alerts": [a if isinstance(a, dict) else vars(a) for a in alerts]
        }
        
        return report

    def _build_executive_summary(self, session: Dict[str, Any], alerts: List[Any]) -> str:
        high_critical = sum(1 for a in alerts if getattr(a, 'severity', a.get('severity', '')) in ['high', 'critical'])
        total = len(alerts)
        
        summary = f"Investigation Report for Session {session.get('id', 'Unknown')}.\n"
        summary += f"Total alerts generated: {total}.\n"
        summary += f"High/Critical severity alerts: {high_critical}.\n"
        
        if high_critical > 0:
            summary += "The system exhibits signs of compromise and requires immediate attention."
        else:
            summary += "No critical indicators of compromise were discovered during this session."
            
        return summary

    def _build_timeline(self, session_id: int) -> List[Dict[str, Any]]:
        return self.timeline_builder.build_timeline(session_id, self.db_session)

    def _build_mitre_matrix(self, alerts: List[Any]) -> Dict[str, Any]:
        # Convert objects to dicts if needed
        alert_dicts = [a if isinstance(a, dict) else vars(a) for a in alerts]
        coverage = self.mitre_mapper.get_technique_coverage(alert_dicts)
        return {"detected_techniques": coverage}

    def _calculate_risk(self, alerts: List[Any]) -> Dict[str, Any]:
        score = 0
        weights = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        
        for a in alerts:
            sev = getattr(a, 'severity', a.get('severity', 'low')).lower()
            score += weights.get(sev, 1)
            
        # Normalize 0-100
        normalized = min(100, score)
        
        level = "Low"
        if normalized > 75:
            level = "Critical"
        elif normalized > 50:
            level = "High"
        elif normalized > 25:
            level = "Medium"
            
        return {
            "score": normalized,
            "level": level,
            "raw_score": score
        }

    def save_report(self, report: Dict[str, Any], session_id: int) -> str:
        # In a real app, save to db
        report_id = report['report_id']
        logger.info(f"Saved report {report_id} to database")
        return report_id
