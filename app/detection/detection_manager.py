import logging
from typing import List, Dict, Any
from .yara_engine import YaraEngine
from .sigma_engine import SigmaEngine
from .ioc_engine import IOCEngine
from .heuristic_engine import HeuristicEngine

logger = logging.getLogger(__name__)

# Dummy Alert class to simulate DB model import since we don't have the models defined here directly
class Alert:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class DetectionManager:
    def __init__(self, config: Dict[str, Any], db_session=None):
        self.config = config
        self.db_session = db_session
        
        detection_config = config.get('detection', config)
        rules_dir = detection_config.get('rules_dir', 'rules')
        
        self.yara_engine = YaraEngine(f"{rules_dir}/yara")
        self.sigma_engine = SigmaEngine(f"{rules_dir}/sigma")
        self.ioc_engine = IOCEngine(f"{rules_dir}/iocs")
        self.heuristic_engine = HeuristicEngine()

    def run_detection(self, session_id: int, artifacts: Dict[str, Any] = None) -> List[Any]:
        if artifacts is None and self.db_session is not None:
            try:
                from app.database.models import Process, NetworkConnection, RegistryKey, ScheduledTask, EventLog
                procs = self.db_session.query(Process).filter(Process.session_id == session_id).all()
                conns = self.db_session.query(NetworkConnection).filter(NetworkConnection.session_id == session_id).all()
                regs = self.db_session.query(RegistryKey).filter(RegistryKey.session_id == session_id).all()
                tasks = self.db_session.query(ScheduledTask).filter(ScheduledTask.session_id == session_id).all()
                evts = self.db_session.query(EventLog).filter(EventLog.session_id == session_id).all()
                artifacts = {
                    "files": [],
                    "processes": [{"name": p.name, "pid": p.pid, "cmdline": p.cmdline, "path": p.path, "username": p.username} for p in procs],
                    "network_connections": [{"local_ip": c.local_ip, "local_port": c.local_port, "remote_ip": c.remote_ip, "remote_port": c.remote_port, "protocol": c.protocol} for c in conns],
                    "registry_keys": [{"key_path": r.key_path, "value_name": r.value_name, "value_data": r.value_data, "hive": r.hive} for r in regs],
                    "scheduled_tasks": [{"name": t.name, "command": t.command, "author": t.author} for t in tasks],
                    "events": [{"source": e.source, "event_id": e.event_id_windows, "message": e.message, "channel": e.channel} for e in evts],
                }
            except Exception as e:
                logger.warning(f"Could not fetch artifacts from DB for session {session_id}: {e}")
                artifacts = {"files": [], "processes": [], "network_connections": [], "registry_keys": [], "scheduled_tasks": [], "events": []}
        elif artifacts is None:
            artifacts = {"files": [], "processes": [], "network_connections": [], "registry_keys": [], "scheduled_tasks": [], "events": []}
            
        all_alerts = []
        
        # Run IOC Detection
        logger.info(f"Running IOC detection for session {session_id}")
        ioc_alerts = self._run_ioc_detection(artifacts)
        all_alerts.extend(ioc_alerts)
        
        # Run Heuristic Detection
        logger.info(f"Running heuristic detection for session {session_id}")
        heuristic_alerts = self._run_heuristic_detection(artifacts)
        all_alerts.extend(heuristic_alerts)
        
        # Run Sigma Detection
        logger.info(f"Running Sigma detection for session {session_id}")
        sigma_alerts = self._run_sigma_detection(artifacts)
        all_alerts.extend(sigma_alerts)
        
        # YARA would typically run during collection or file analysis phase, but can run here if paths provided
        logger.info(f"Running YARA detection for session {session_id}")
        yara_alerts = self._run_yara_detection(artifacts)
        all_alerts.extend(yara_alerts)
        
        # Save to DB
        saved_alerts = self._save_alerts(session_id, all_alerts)
        return saved_alerts

    def _run_yara_detection(self, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        for file_info in artifacts.get("files", []):
            filepath = file_info.get("path")
            if filepath:
                matches = self.yara_engine.scan_file(filepath)
                for match in matches:
                    alerts.append({
                        "title": f"YARA Match: {match['rule']}",
                        "description": f"File {filepath} matched YARA rule {match['rule']}",
                        "severity": "high",
                        "source": "YaraEngine",
                        "mitre_technique": None,
                        "context": str(match['meta'])
                    })
        return alerts

    def _run_sigma_detection(self, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        for event in artifacts.get("events", []):
            matches = self.sigma_engine.evaluate_event(event)
            for match in matches:
                mitre_tech = match['mitre_tags'][0].replace('attack.', '') if match.get('mitre_tags') else None
                alerts.append({
                    "title": f"Sigma Match: {match['title']}",
                    "description": match['description'],
                    "severity": match['level'],
                    "source": "SigmaEngine",
                    "mitre_technique": mitre_tech,
                    "context": str(event)
                })
        return alerts

    def _run_ioc_detection(self, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        matches = self.ioc_engine.check_all(artifacts)
        for match in matches:
            alerts.append({
                "title": f"IOC Match: {match['ioc_type'].upper()}",
                "description": f"Found malicious {match['ioc_type']}: {match['value']} from source {match['source']}",
                "severity": match['severity'],
                "source": "IOCEngine",
                "mitre_technique": None,
                "context": match.get('context', '')
            })
        return alerts

    def _run_heuristic_detection(self, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        alerts.extend(self.heuristic_engine.analyze_processes(artifacts.get("processes", [])))
        alerts.extend(self.heuristic_engine.analyze_network(artifacts.get("network_connections", [])))
        alerts.extend(self.heuristic_engine.analyze_registry(artifacts.get("registry_keys", [])))
        alerts.extend(self.heuristic_engine.analyze_scheduled_tasks(artifacts.get("scheduled_tasks", [])))
        alerts.extend(self.heuristic_engine.analyze_events(artifacts.get("events", [])))
        
        for alert in alerts:
            alert['source'] = 'HeuristicEngine'
            
        return alerts

    def _save_alerts(self, session_id: int, alerts_data: List[Dict[str, Any]]) -> List[Any]:
        saved = []
        if not self.db_session:
            return [Alert(session_id=session_id, **a) for a in alerts_data]
            
        try:
            from app.database.models import Alert as AlertModel
            for alert_data in alerts_data:
                alert = AlertModel(
                    session_id=session_id,
                    rule_name=alert_data.get("title", alert_data.get("rule_name", "Unknown")),
                    rule_type=alert_data.get("source", alert_data.get("rule_type", "heuristic")),
                    severity=alert_data.get("severity", "low"),
                    description=alert_data.get("description", ""),
                    artifact_type="system",
                    artifact_id=0,
                    mitre_technique_id=alert_data.get("mitre_technique"),
                    mitre_tactic=alert_data.get("mitre_tactic"),
                    risk_score=0,
                    raw_evidence=str(alert_data.get("context", "")),
                )
                self.db_session.add(alert)
                saved.append(alert)
            self.db_session.commit()
        except Exception as e:
            logger.error(f"Error saving alerts for session {session_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
        return saved

    def get_detection_summary(self, session_id: int) -> Dict[str, Any]:
        return {
            "session_id": session_id,
            "total_alerts": 0,
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "by_source": {}
        }
