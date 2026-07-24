"""
KAPE-style modular collection targets.
Inspired by Kroll Artifact Parser and Extractor (KAPE) methodology
for targeted forensic artifact collection.
"""

from typing import Any, Dict, List

# Each target defines a focused collection module, similar to KAPE .tkape files
KAPE_TARGETS: Dict[str, Dict[str, Any]] = {
    "Processes": {
        "collectors": ["process"],
        "category": "Live Response",
        "description": "Running processes with metadata (PID, PPID, command line, handles)",
        "kape_ref": "!LIVEPROC",
    },
    "Network": {
        "collectors": ["network"],
        "category": "Live Response",
        "description": "Active TCP/UDP connections with associated processes",
        "kape_ref": "!NETCONN",
    },
    "Services": {
        "collectors": ["service"],
        "category": "System Configuration",
        "description": "Installed services and their current state",
        "kape_ref": "!SERVICES",
    },
    "Persistence_Registry": {
        "collectors": ["registry"],
        "category": "Persistence Mechanisms",
        "description": "Registry autoruns (Run keys, Startup entries)",
        "kape_ref": "AutoRun",
    },
    "ScheduledTasks": {
        "collectors": ["scheduled_tasks"],
        "category": "Persistence Mechanisms",
        "description": "Scheduled tasks and their triggers/actions",
        "kape_ref": "ScheduledTasks",
    },
    "Sysmon_Events": {
        "collectors": ["eventlog"],
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "category": "Event Logs",
        "description": "Sysmon operational events (process creation, network, registry, file events)",
        "kape_ref": "SysmonLogs",
    },
    "Security_Events": {
        "collectors": ["eventlog"],
        "channel": "Security",
        "category": "Event Logs",
        "description": "Windows Security log (logons, privilege use, object access)",
        "kape_ref": "SecurityLogs",
    },
    "System_Events": {
        "collectors": ["eventlog"],
        "channel": "System",
        "category": "Event Logs",
        "description": "Windows System log (driver loads, service failures)",
        "kape_ref": "SystemLogs",
    },
    "Linux_Artifacts": {
        "collectors": ["linux"],
        "category": "System Configuration",
        "description": "Linux login history, system info, running processes",
        "kape_ref": "LinuxArtifacts",
    },
}

def get_targets_by_category() -> Dict[str, List[Dict[str, Any]]]:
    """Group targets by category (like KAPE groups)."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for name, target in KAPE_TARGETS.items():
        cat = target.get("category", "Other")
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append({"name": name, **target})
    return grouped

def get_target(target_name: str) -> Dict[str, Any]:
    """Get a single target definition."""
    return KAPE_TARGETS.get(target_name, {})

def get_target_names() -> List[str]:
    """Return all target names for the collector to run."""
    return list(KAPE_TARGETS.keys())
