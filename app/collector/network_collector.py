import psutil
from typing import Any, Dict, List
from .base_collector import BaseCollector

class NetworkCollector(BaseCollector):
    """Collects active network connections."""
    
    def get_name(self) -> str:
        return "Network Collector"
        
    def _is_suspicious(self, conn: Any, proc_name: str) -> tuple[bool, str]:
        bad_ports = {4444, 5555, 8888, 1234, 31337}
        proc_name_lower = (proc_name or "").lower()
        
        if hasattr(conn, 'raddr') and conn.raddr and conn.raddr.port in bad_ports:
            return True, f"Connection to known suspicious port: {conn.raddr.port}"
            
        if hasattr(conn, 'laddr') and conn.laddr and conn.laddr.port in bad_ports:
            return True, f"Listening on known suspicious port: {conn.laddr.port}"
            
        suspicious_procs = {"powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
        if proc_name_lower in suspicious_procs and conn.status == "ESTABLISHED":
            if conn.raddr and conn.raddr.ip not in ("127.0.0.1", "::1"):
                return True, f"Suspicious process {proc_name} making external connection"
                
        return False, ""

    def collect(self) -> List[Dict[str, Any]]:
        self.artifacts = []
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return self.artifacts
            
        for conn in conns:
            proc_name = "Unknown"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            is_sus, reason = self._is_suspicious(conn, proc_name)
            
            conn_dict = {
                "local_address": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_address": conn.raddr.ip if conn.raddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": proc_name,
                "protocol": "TCP" if conn.type == 1 else "UDP" if conn.type == 2 else str(conn.type),
                "is_suspicious": is_sus,
                "suspicion_reason": reason
            }
            self.artifacts.append(conn_dict)
            
        return self.artifacts
