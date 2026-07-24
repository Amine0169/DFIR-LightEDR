import csv
import io
import subprocess
from typing import Any, Dict, List
from .base_collector import BaseCollector

class ScheduledTaskCollector(BaseCollector):
    """Collects scheduled tasks/cron jobs."""
    
    def get_name(self) -> str:
        return "Scheduled Tasks Collector"

    def _is_suspicious(self, name: str, path: str, command: str) -> tuple[bool, str]:
        cmd_lower = (command or "").lower()
        if "temp" in cmd_lower or "appdata" in cmd_lower or "/tmp" in cmd_lower:
            return True, "Task runs from temporary directory"
        if "powershell" in cmd_lower and ("-enc" in cmd_lower or "-encodedcommand" in cmd_lower):
            return True, "Task runs PowerShell with encoded command"
        return False, ""

    def _collect_windows(self) -> List[Dict[str, Any]]:
        tasks = []
        try:
            output = subprocess.check_output(["schtasks", "/query", "/fo", "CSV", "/v"], text=True, stderr=subprocess.DEVNULL)
            reader = csv.DictReader(io.StringIO(output))
            for row in reader:
                name = row.get("TaskName", "")
                command = row.get("Task To Run", "")
                is_sus, reason = self._is_suspicious(name, "", command)
                
                tasks.append({
                    "name": name,
                    "path": name,
                    "command": command,
                    "arguments": "",
                    "status": row.get("Status", ""),
                    "author": row.get("Author", ""),
                    "last_run": row.get("Last Run Time", ""),
                    "next_run": row.get("Next Run Time", ""),
                    "is_suspicious": is_sus,
                    "suspicion_reason": reason
                })
        except Exception:
            pass
        return tasks

    def _collect_linux(self) -> List[Dict[str, Any]]:
        tasks = []
        try:
            output = subprocess.check_output(["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if line.strip() and not line.startswith("#"):
                    is_sus, reason = self._is_suspicious("cron", "", line)
                    tasks.append({
                        "name": "crontab",
                        "path": "crontab",
                        "command": line,
                        "arguments": "",
                        "status": "active",
                        "author": "current_user",
                        "last_run": "",
                        "next_run": "",
                        "is_suspicious": is_sus,
                        "suspicion_reason": reason
                    })
        except Exception:
            pass
            
        try:
            # Additionally could read /etc/cron.* but skipping complex parsing for now
            pass
        except Exception:
            pass
            
        return tasks

    def collect(self) -> List[Dict[str, Any]]:
        if self.os_type == 'windows':
            self.artifacts = self._collect_windows()
        else:
            self.artifacts = self._collect_linux()
        return self.artifacts
