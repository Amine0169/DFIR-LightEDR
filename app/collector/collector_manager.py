import logging
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .process_collector import ProcessCollector
from .network_collector import NetworkCollector
from .service_collector import ServiceCollector
from .eventlog_collector import EventLogCollector
from .registry_collector import RegistryCollector
from .scheduled_tasks import ScheduledTaskCollector
from .linux_collector import LinuxCollector

from app.database.models import Host, ScanSession, Process, NetworkConnection, EventLog, RegistryKey, ScheduledTask
from app.collector.kape_targets import KAPE_TARGETS, get_target_names

logger = logging.getLogger("core.logger")

class CollectorManager:
    """Orchestrator for all artifact collectors."""
    
    def __init__(self, db_session: Any, config: Any):
        self.db = db_session
        self.config = config
        self.collectors = [
            ProcessCollector(),
            NetworkCollector(),
            ServiceCollector(),
            EventLogCollector(),
            RegistryCollector(),
            ScheduledTaskCollector(),
            LinuxCollector()
        ]
        
    def _get_or_create_host(self) -> Host:
        hostname = platform.node()
        host = self.db.query(Host).filter_by(hostname=hostname).first()
        if host:
            host.last_seen = datetime.now(timezone.utc)
            host.ip_address = self._get_local_ip()
        else:
            host = Host(
                hostname=hostname,
                os_type=platform.system(),
                os_version=platform.version(),
                ip_address=self._get_local_ip(),
                username=platform.node(),
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            self.db.add(host)
        self.db.commit()
        self.db.refresh(host)
        logger.info(f"Host: {host.hostname} (id={host.id})")
        return host

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _create_scan_session(self, host: Host) -> ScanSession:
        session = ScanSession(
            host_id=host.id,
            scan_type="full",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def _save_processes(self, session_id: int, data: List[Dict[str, Any]]) -> int:
        count = 0
        for item in data:
            created_at = None
            if item.get("create_time"):
                try:
                    created_at = datetime.fromisoformat(item["create_time"])
                except (ValueError, TypeError):
                    pass
            proc = Process(
                session_id=session_id,
                name=item.get("name", ""),
                pid=item.get("pid", 0),
                ppid=item.get("ppid"),
                path=item.get("exe"),
                cmdline=item.get("cmdline"),
                username=item.get("username"),
                hash_md5=item.get("md5"),
                hash_sha256=item.get("sha256"),
                created_at=created_at,
                is_suspicious=item.get("is_suspicious", False),
                suspicion_reason=item.get("suspicion_reason"),
            )
            self.db.add(proc)
            count += 1
        self.db.commit()
        logger.info(f"Saved {count} processes")
        return count
        
    def _save_network(self, session_id: int, data: List[Dict[str, Any]]) -> int:
        count = 0
        for item in data:
            conn = NetworkConnection(
                session_id=session_id,
                local_ip=item.get("local_address") or "0.0.0.0",
                local_port=item.get("local_port") or 0,
                remote_ip=item.get("remote_address") or "0.0.0.0",
                remote_port=item.get("remote_port") or 0,
                protocol=item.get("protocol", "TCP"),
                state=item.get("status", "UNKNOWN"),
                pid=item.get("pid"),
                process_name=item.get("process_name"),
            )
            self.db.add(conn)
            count += 1
        self.db.commit()
        logger.info(f"Saved {count} network connections")
        return count
        
    def _save_eventlogs(self, session_id: int, data: List[Dict[str, Any]]) -> int:
        count = 0
        for item in data:
            timestamp = None
            if item.get("time_created"):
                try:
                    timestamp = datetime.fromisoformat(item["time_created"].replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
            level = "info"
            if item.get("channel") in ("Security", "Microsoft-Windows-Sysmon/Operational"):
                level = "warning"
            evt = EventLog(
                session_id=session_id,
                source=item.get("provider", "unknown"),
                event_id_windows=int(item.get("event_id", 0)),
                level=level,
                channel=item.get("channel", ""),
                message=item.get("data", ""),
                timestamp=timestamp or datetime.now(timezone.utc),
            )
            self.db.add(evt)
            count += 1
        self.db.commit()
        logger.info(f"Saved {count} event logs")
        return count
        
    def _save_registry(self, session_id: int, data: List[Dict[str, Any]]) -> int:
        count = 0
        for item in data:
            rk = RegistryKey(
                session_id=session_id,
                hive=item.get("hive", ""),
                key_path=item.get("key_path", ""),
                value_name=item.get("value_name", ""),
                value_data=str(item.get("value_data", "")),
                value_type="REG_SZ",
                is_persistence=item.get("is_persistence", False),
            )
            self.db.add(rk)
            count += 1
        self.db.commit()
        logger.info(f"Saved {count} registry keys")
        return count
        
    def _save_scheduled_tasks(self, session_id: int, data: List[Dict[str, Any]]) -> int:
        count = 0
        for item in data:
            st = ScheduledTask(
                session_id=session_id,
                name=item.get("name", ""),
                path=item.get("path", ""),
                command=item.get("command", ""),
                arguments=item.get("arguments"),
                trigger_type="scheduled",
                status=item.get("status", ""),
                author=item.get("author"),
            )
            self.db.add(st)
            count += 1
        self.db.commit()
        logger.info(f"Saved {count} scheduled tasks")
        return count

    def run_collector(self, collector_name: str) -> List[Dict[str, Any]]:
        for c in self.collectors:
            if c.get_name() == collector_name:
                try:
                    logger.info(f"Running collector: {collector_name}")
                    return c.collect()
                except Exception as e:
                    logger.error(f"Collector {collector_name} failed: {str(e)}")
                    return []
        return []

    def _get_kape_targets_collected(self, collector_name: str, data: List[Dict[str, Any]]) -> List[str]:
        """Map collected data to KAPE targets."""
        targets = []
        for tname, tdef in KAPE_TARGETS.items():
            if collector_name in tdef.get("collectors", []):
                channel = tdef.get("channel")
                if channel:
                    if any(item.get("channel") == channel for item in data):
                        targets.append(tname)
                else:
                    targets.append(tname)
        return targets

    def run_full_scan(self) -> Dict[str, Any]:
        """Runs all enabled collectors and persists results to DB."""
        logger.info("Starting full scan...")
        host = self._get_or_create_host()
        session = self._create_scan_session(host)
        session_id = session.id
        
        results = {
            "session_id": session_id,
            "host_id": host.id,
            "start_time": session.started_at.isoformat(),
            "artifacts": {},
            "kape_targets": [],
        }
        total_artifacts = 0
        all_targets = set()
        
        for collector in self.collectors:
            name = collector.get_name()
            try:
                start_time = datetime.now(timezone.utc)
                data = collector.collect()
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                results["artifacts"][name] = {
                    "count": len(data),
                    "duration_seconds": duration,
                }
                logger.info(f"Collector {name} completed in {duration:.2f}s with {len(data)} artifacts.")
                
                # Route to specific save methods
                saved = 0
                if isinstance(collector, ProcessCollector):
                    saved = self._save_processes(session_id, data)
                elif isinstance(collector, NetworkCollector):
                    saved = self._save_network(session_id, data)
                elif isinstance(collector, EventLogCollector):
                    saved = self._save_eventlogs(session_id, data)
                elif isinstance(collector, RegistryCollector):
                    saved = self._save_registry(session_id, data)
                elif isinstance(collector, ScheduledTaskCollector):
                    saved = self._save_scheduled_tasks(session_id, data)
                elif isinstance(collector, ServiceCollector):
                    pass
                elif isinstance(collector, LinuxCollector):
                    pass
                    
                total_artifacts += saved
                all_targets.update(self._get_kape_targets_collected(name, data))
                    
            except Exception as e:
                logger.error(f"Collector {name} failed: {str(e)}")
                results["artifacts"][name] = {"error": str(e)}
        
        results["kape_targets"] = sorted(all_targets)
        session.total_artifacts = total_artifacts
        session.completed_at = datetime.now(timezone.utc)
        session.status = "completed"
        session.agent_version = "1.0.0"
        session.agent_concept = "Velociraptor-inspired local collector + KAPE-style modular targets"
        session.kape_targets = ",".join(sorted(all_targets)) if all_targets else None
        self.db.commit()
        
        results["end_time"] = session.completed_at.isoformat()
        results["total_artifacts"] = total_artifacts
        logger.info(f"Full scan completed: {total_artifacts} artifacts saved (session_id={session_id})")
        logger.info(f"KAPE targets collected: {results['kape_targets']}")
        return results
