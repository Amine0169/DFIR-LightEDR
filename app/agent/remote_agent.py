#!/usr/bin/env python3
"""
Remote DFIR Agent - deploys on Kali Linux, Windows 11, or Ubuntu VMs.
Collects artifacts and sends them to the central LightEDR server.
"""

import argparse
import json
import logging
import os
import platform
import socket
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("agent")

HAS_PSUTIL = False
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    logger.warning("psutil not installed. Run: pip install psutil")

def get_hostname() -> str:
    return platform.node()

def get_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

def check_sysmon() -> Dict[str, Any]:
    """Detect Sysmon installation and status (Windows only)."""
    result = {"installed": False, "version": None, "service_running": False, "events_available": 0}
    if platform.system() != "Windows":
        return result
    for svc in ("Sysmon64", "Sysmon"):
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{svc}")
            result["installed"] = True
            try:
                val, _ = winreg.QueryValueEx(key, "DisplayName")
                result["version"] = str(val)
            except Exception:
                result["version"] = svc
            winreg.CloseKey(key)
        except Exception:
            continue
        try:
            import subprocess
            r = subprocess.run(["sc", "query", svc], capture_output=True, text=True, timeout=5)
            result["service_running"] = "RUNNING" in r.stdout
        except Exception:
            pass
        break
    if result["installed"]:
        try:
            import subprocess
            r = subprocess.run(
                ["wevtutil", "gp", "Microsoft-Windows-Sysmon/Operational"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                result["events_available"] = -1  # log exists
        except Exception:
            pass
    return result

def collect_processes() -> List[Dict[str, Any]]:
    results = []
    if not HAS_PSUTIL:
        return results
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            pinfo = proc.info
            results.append({
                "pid": pinfo["pid"],
                "ppid": pinfo["ppid"],
                "name": pinfo["name"] or "",
                "exe": pinfo["exe"] or "",
                "cmdline": " ".join(pinfo["cmdline"]) if pinfo["cmdline"] else "",
                "username": pinfo["username"] or "",
                "create_time": datetime.fromtimestamp(pinfo["create_time"]).isoformat() if pinfo["create_time"] else "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return results

def collect_network() -> List[Dict[str, Any]]:
    results = []
    if not HAS_PSUTIL:
        return results
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = conn.laddr
            raddr = conn.raddr
            results.append({
                "local_address": f"{laddr.ip}" if laddr else "0.0.0.0",
                "local_port": laddr.port if laddr else 0,
                "remote_address": f"{raddr.ip}" if raddr else "0.0.0.0",
                "remote_port": raddr.port if raddr else 0,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "status": conn.status,
                "pid": conn.pid,
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    return results

def collect_linux() -> List[Dict[str, Any]]:
    results = []
    if platform.system() != "Linux":
        return results
    try:
        import subprocess
        r = subprocess.run(["last", "-n", "20"], capture_output=True, text=True, timeout=5)
        results.append({"source": "last_login", "data": r.stdout})
    except Exception:
        pass
    return results

def send_to_server(server_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        server_url + "/api/ingest",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        logger.error(f"Server error {e.code}: {e.read().decode()}")
        raise
    except urllib.error.URLError as e:
        logger.error(f"Connection failed: {e.reason}")
        raise

def run_scan(server_url: str, scan_type: str = "remote"):
    hostname = get_hostname()
    ip = get_ip()
    logger.info(f"Agent starting on {hostname} ({ip})")

    sysmon_status = check_sysmon()
    if sysmon_status["installed"]:
        logger.info(f"Sysmon detected: version={sysmon_status['version']}, running={sysmon_status['service_running']}, events={sysmon_status['events_available']}")

    payload = {
        "hostname": hostname,
        "os_type": platform.system(),
        "os_version": platform.version(),
        "ip_address": ip,
        "scan_type": scan_type,
        "sysmon_status": sysmon_status,
        "agent_version": "1.0.0",
        "agent_concept": "Velociraptor-inspired remote artifact collector",
        "kape_targets": [],
        "processes": collect_processes(),
        "network_connections": collect_network(),
        "event_logs": [],
        "registry_keys": [],
        "scheduled_tasks": [],
    }

    if platform.system() == "Windows":
        payload["event_logs"] = collect_windows_events()
        payload["registry_keys"] = collect_windows_registry()
        payload["kape_targets"] = ["Processes", "Network", "Persistence_Registry", "Sysmon_Events", "Security_Events"]

    linux_artifacts = collect_linux()
    if linux_artifacts:
        payload["scheduled_tasks"] = linux_artifacts
        payload["kape_targets"] = ["Processes", "Network", "Linux_Artifacts"]

    total = sum(len(v) for k, v in payload.items() if isinstance(v, list))
    logger.info(f"Collected {total} artifacts, sending to {server_url}...")

    result = send_to_server(server_url, payload)
    logger.info(f"Ingested: host_id={result.get('host_id')}, session_id={result.get('session_id')}, artifacts={result.get('total_artifacts')}")
    return result

def collect_windows_events() -> List[Dict[str, Any]]:
    results = []
    if platform.system() != "Windows":
        return results
    try:
        import win32evtlog
        hand = win32evtlog.OpenEventLog(None, "System")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for evt in events[:50]:
            results.append({
                "provider": str(evt.SourceName),
                "event_id": evt.EventID & 0xFFFF,
                "channel": "System",
                "data": str(evt.StringInserts) if evt.StringInserts else "",
                "time_created": evt.TimeGenerated.Format() if evt.TimeGenerated else "",
            })
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        logger.warning(f"Event log collection failed: {e}")
    return results

def collect_windows_registry() -> List[Dict[str, Any]]:
    results = []
    if platform.system() != "Windows":
        return results
    try:
        import winreg
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hkey, subkey in paths:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        results.append({
                            "hive": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            "key_path": subkey,
                            "value_name": name,
                            "value_data": str(value),
                            "is_persistence": True,
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Registry collection failed: {e}")
    return results

def main():
    parser = argparse.ArgumentParser(description="LightEDR Remote Agent")
    parser.add_argument("--server", default="http://192.168.100.30:8000", help="Central server URL")
    parser.add_argument("--interval", type=int, default=0, help="Polling interval in seconds (0 = one-shot)")
    parser.add_argument("--scan-type", default="remote", help="Scan type label")
    args = parser.parse_args()

    server = args.server.rstrip("/")
    logger.info(f"LightEDR Agent targeting {server}")

    if args.interval > 0:
        logger.info(f"Continuous mode: scanning every {args.interval}s")
        while True:
            try:
                run_scan(server, args.scan_type)
            except Exception as e:
                logger.error(f"Scan failed: {e}")
            time.sleep(args.interval)
    else:
        run_scan(server, args.scan_type)

if __name__ == "__main__":
    main()
