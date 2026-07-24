import hashlib
import os
import psutil
from typing import Any, Dict, List, Optional
from datetime import datetime
from .base_collector import BaseCollector

class ProcessCollector(BaseCollector):
    """Collects information about running processes."""
    
    def get_name(self) -> str:
        return "Process Collector"
        
    def _hash_file(self, filepath: str) -> tuple[Optional[str], Optional[str]]:
        if not filepath or not os.path.exists(filepath):
            return None, None
            
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return None, None

    def _check_suspicious(self, name: str, exe: str, cmdline: List[str], ppid: int, parent_name: Optional[str]) -> tuple[bool, str]:
        name_lower = (name or "").lower()
        exe_lower = (exe or "").lower()
        cmd_lower = " ".join(cmdline).lower() if cmdline else ""
        
        if "powershell" in name_lower and ("-enc" in cmd_lower or "-encodedcommand" in cmd_lower or "bypass" in cmd_lower):
            return True, "PowerShell with suspicious arguments"
            
        if name_lower == "cmd.exe" and parent_name and parent_name.lower() not in ["explorer.exe", "cmd.exe", "powershell.exe"]:
            return True, f"cmd.exe spawned by unusual parent: {parent_name}"
            
        if exe_lower and ("temp" in exe_lower or "appdata" in exe_lower or "/tmp" in exe_lower):
            return True, "Process running from temporary directory"
            
        if ppid == 0 and name_lower not in ["system idle process", "system", "registry", "smss.exe", "sched", "init", "kthreadd"]:
            return True, "Process with no parent"
            
        if name_lower == "svchost.exe" and parent_name and parent_name.lower() != "services.exe":
            return True, "svchost.exe not spawned by services.exe"
            
        return False, ""
        
    def collect(self) -> List[Dict[str, Any]]:
        self.artifacts = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'status', 'memory_info', 'cpu_percent']):
            try:
                info = proc.info
                parent_name = None
                if info['ppid']:
                    try:
                        parent = psutil.Process(info['ppid'])
                        parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                is_suspicious, reason = self._check_suspicious(
                    info['name'], 
                    info['exe'], 
                    info['cmdline'], 
                    info['ppid'], 
                    parent_name
                )
                
                md5, sha256 = self._hash_file(info['exe'])
                
                create_time = None
                if info['create_time']:
                    create_time = datetime.fromtimestamp(info['create_time']).isoformat()
                
                proc_dict = {
                    "pid": info['pid'],
                    "ppid": info['ppid'],
                    "name": info['name'],
                    "exe": info['exe'],
                    "cmdline": " ".join(info['cmdline']) if info['cmdline'] else "",
                    "username": info['username'],
                    "create_time": create_time,
                    "status": info['status'],
                    "memory_usage": info['memory_info'].rss if info['memory_info'] else 0,
                    "cpu_percent": info['cpu_percent'],
                    "md5": md5,
                    "sha256": sha256,
                    "is_suspicious": is_suspicious,
                    "suspicion_reason": reason
                }
                self.artifacts.append(proc_dict)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return self.artifacts
