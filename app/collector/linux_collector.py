import os
from typing import Any, Dict, List
from .base_collector import BaseCollector

class LinuxCollector(BaseCollector):
    """Collects Linux-specific artifacts."""
    
    def get_name(self) -> str:
        return "Linux Collector"

    def _collect_suspicious_files(self, dirs: List[str]) -> List[Dict[str, Any]]:
        files = []
        for d in dirs:
            if not os.path.exists(d):
                continue
            for root, _, filenames in os.walk(d):
                for fname in filenames:
                    path = os.path.join(root, fname)
                    if os.access(path, os.X_OK) and os.path.isfile(path):
                        files.append({
                            "artifact_type": "suspicious_file",
                            "path": path,
                            "reason": f"Executable file in {d}"
                        })
        return files

    def _check_passwd(self) -> List[Dict[str, Any]]:
        users = []
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) >= 3:
                        uid = parts[2]
                        name = parts[0]
                        if uid == "0" and name != "root":
                            users.append({
                                "artifact_type": "suspicious_user",
                                "username": name,
                                "reason": "UID 0 but not root"
                            })
        except Exception:
            pass
        return users

    def _check_ssh_keys(self) -> List[Dict[str, Any]]:
        keys = []
        auth_file = os.path.expanduser("~/.ssh/authorized_keys")
        try:
            if os.path.exists(auth_file):
                with open(auth_file, "r") as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            keys.append({
                                "artifact_type": "ssh_key",
                                "path": auth_file,
                                "key": line.strip()
                            })
        except Exception:
            pass
        return keys

    def collect(self) -> List[Dict[str, Any]]:
        if self.os_type != 'linux':
            return []
            
        self.artifacts = []
        self.artifacts.extend(self._collect_suspicious_files(["/tmp", "/dev/shm"]))
        self.artifacts.extend(self._check_passwd())
        self.artifacts.extend(self._check_ssh_keys())
        return self.artifacts
