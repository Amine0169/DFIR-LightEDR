from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Integer, Boolean, ForeignKey, DateTime, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Host(Base):
    __tablename__ = "hosts"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    hostname: Mapped[str] = mapped_column(String, index=True)
    os_type: Mapped[str] = mapped_column(String)
    os_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ip_address: Mapped[str] = mapped_column(String)
    mac_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    username: Mapped[str] = mapped_column(String)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    status: Mapped[str] = mapped_column(String, default="active")

    sessions: Mapped[List["ScanSession"]] = relationship(back_populates="host", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Host(hostname={self.hostname}, ip={self.ip_address})>"

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    scan_type: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="running")
    total_artifacts: Mapped[int] = mapped_column(Integer, default=0)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    agent_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    agent_concept: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    kape_targets: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    sysmon_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    sysmon_events: Mapped[int] = mapped_column(Integer, default=0)

    host: Mapped["Host"] = relationship(back_populates="sessions")
    processes: Mapped[List["Process"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    network_connections: Mapped[List["NetworkConnection"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    event_logs: Mapped[List["EventLog"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    registry_keys: Mapped[List["RegistryKey"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    scheduled_tasks: Mapped[List["ScheduledTask"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    alerts: Mapped[List["Alert"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship(back_populates="session", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<ScanSession(id={self.id}, host_id={self.host_id}, status={self.status})>"

class Process(Base):
    __tablename__ = "processes"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    name: Mapped[str] = mapped_column(String)
    pid: Mapped[int] = mapped_column(Integer)
    ppid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cmdline: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    hash_md5: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    hash_sha256: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    suspicion_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    session: Mapped["ScanSession"] = relationship(back_populates="processes")

    def __repr__(self) -> str:
        return f"<Process(name={self.name}, pid={self.pid})>"

class NetworkConnection(Base):
    __tablename__ = "network_connections"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    local_ip: Mapped[str] = mapped_column(String)
    local_port: Mapped[int] = mapped_column(Integer)
    remote_ip: Mapped[str] = mapped_column(String)
    remote_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    state: Mapped[str] = mapped_column(String)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    session: Mapped["ScanSession"] = relationship(back_populates="network_connections")

    def __repr__(self) -> str:
        return f"<NetworkConnection(local={self.local_ip}:{self.local_port}, remote={self.remote_ip}:{self.remote_port})>"

class EventLog(Base):
    __tablename__ = "event_logs"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    source: Mapped[str] = mapped_column(String)
    event_id_windows: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String)
    channel: Mapped[str] = mapped_column(String)
    message: Mapped[Text] = mapped_column(Text)
    raw_xml: Mapped[Optional[Text]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)

    session: Mapped["ScanSession"] = relationship(back_populates="event_logs")

    def __repr__(self) -> str:
        return f"<EventLog(event_id={self.event_id_windows}, source={self.source})>"

class RegistryKey(Base):
    __tablename__ = "registry_keys"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    hive: Mapped[str] = mapped_column(String)
    key_path: Mapped[str] = mapped_column(String)
    value_name: Mapped[str] = mapped_column(String)
    value_data: Mapped[Text] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String)
    last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_persistence: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped["ScanSession"] = relationship(back_populates="registry_keys")

    def __repr__(self) -> str:
        return f"<RegistryKey(hive={self.hive}, path={self.key_path})>"

class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    name: Mapped[str] = mapped_column(String)
    path: Mapped[str] = mapped_column(String)
    command: Mapped[str] = mapped_column(Text)
    arguments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    author: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_run: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    session: Mapped["ScanSession"] = relationship(back_populates="scheduled_tasks")

    def __repr__(self) -> str:
        return f"<ScheduledTask(name={self.name}, command={self.command})>"

class Alert(Base):
    __tablename__ = "alerts"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    rule_name: Mapped[str] = mapped_column(String)
    rule_type: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    description: Mapped[Text] = mapped_column(Text)
    artifact_type: Mapped[str] = mapped_column(String)
    artifact_id: Mapped[int] = mapped_column(Integer)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    raw_evidence: Mapped[Optional[Text]] = mapped_column(Text, nullable=True)

    session: Mapped["ScanSession"] = relationship(back_populates="alerts")
    ioc_matches: Mapped[List["IOCMatch"]] = relationship(back_populates="alert", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Alert(rule={self.rule_name}, severity={self.severity})>"

class IOCMatch(Base):
    __tablename__ = "ioc_matches"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"))
    ioc_type: Mapped[str] = mapped_column(String)
    ioc_value: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    matched_artifact: Mapped[str] = mapped_column(String)
    matched_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    alert: Mapped["Alert"] = relationship(back_populates="ioc_matches")

    def __repr__(self) -> str:
        return f"<IOCMatch(type={self.ioc_type}, value={self.ioc_value})>"

class Report(Base):
    __tablename__ = "reports"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    title: Mapped[str] = mapped_column(String)
    overall_risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String)
    total_alerts: Mapped[int] = mapped_column(Integer)
    total_critical: Mapped[int] = mapped_column(Integer, default=0)
    total_high: Mapped[int] = mapped_column(Integer, default=0)
    total_medium: Mapped[int] = mapped_column(Integer, default=0)
    total_low: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[Text] = mapped_column(Text)
    file_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    session: Mapped["ScanSession"] = relationship(back_populates="reports")

    def __repr__(self) -> str:
        return f"<Report(title={self.title}, risk_level={self.risk_level})>"
