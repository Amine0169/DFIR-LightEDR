import subprocess
import psutil
from typing import Any, Dict, List
from .base_collector import BaseCollector

class ServiceCollector(BaseCollector):
    """Collects system services."""
    
    def get_name(self) -> str:
        return "Service Collector"
        
    def _is_suspicious(self, name: str, bin_path: str) -> tuple[bool, str]:
        path_lower = (bin_path or "").lower()
        if "temp" in path_lower or "appdata" in path_lower or "/tmp" in path_lower:
            return True, "Service binary in temporary/user directory"
        return False, ""

    def _collect_windows(self) -> List[Dict[str, Any]]:
        services = []
        try:
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    name = info.get('name', '')
                    display_name = info.get('display_name', '')
                    bin_path = info.get('binpath', '')
                    
                    is_sus, reason = self._is_suspicious(name, bin_path)
                    
                    services.append({
                        "name": name,
                        "display_name": display_name,
                        "status": info.get('status', ''),
                        "start_type": info.get('start_type', ''),
                        "binary_path": bin_path,
                        "pid": info.get('pid'),
                        "is_suspicious": is_sus,
                        "suspicion_reason": reason
                    })
                except psutil.AccessDenied:
                    continue
        except Exception:
            pass
        return services

    def _collect_linux(self) -> List[Dict[str, Any]]:
        services = []
        try:
            output = subprocess.check_output(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
                text=True
            )
            lines = output.splitlines()
            for line in lines[1:]:
                if not line.strip() or "LOAD" in line:
                    continue
                parts = line.split(maxsplit=4)
                if len(parts) >= 4:
                    name = parts[0]
                    status = parts[3]
                    is_sus, reason = self._is_suspicious(name, "")
                    services.append({
                        "name": name,
                        "display_name": name,
                        "status": status,
                        "start_type": "unknown",
                        "binary_path": "",
                        "pid": None,
                        "is_suspicious": is_sus,
                        "suspicion_reason": reason
                    })
        except Exception:
            pass
        return services

    def collect(self) -> List[Dict[str, Any]]:
        if self.os_type == 'windows':
            self.artifacts = self._collect_windows()
        else:
            self.artifacts = self._collect_linux()
        return self.artifacts
