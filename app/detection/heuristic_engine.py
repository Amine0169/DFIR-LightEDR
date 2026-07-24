import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class HeuristicEngine:
    def __init__(self):
        pass

    def analyze_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        for proc in processes:
            name = proc.get('name', '').lower()
            cmdline = proc.get('command_line', '').lower()
            path = proc.get('path', '').lower()
            parent_name = proc.get('parent_name', '').lower()

            # Rule: PowerShell with -enc or -EncodedCommand
            if name in ['powershell.exe', 'pwsh.exe']:
                if re.search(r'-enc|-encodedcommand', cmdline, re.IGNORECASE):
                    alerts.append({
                        "title": "Suspicious PowerShell Execution",
                        "description": "PowerShell started with encoded command",
                        "severity": "high",
                        "mitre_technique": "T1059.001",
                        "context": f"PID: {proc.get('pid')}, Cmdline: {proc.get('command_line')}"
                    })

            # Rule: cmd.exe spawned by Office applications
            if name == 'cmd.exe':
                office_apps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
                if parent_name in office_apps:
                    alerts.append({
                        "title": "Suspicious Process Lineage (Office -> CMD)",
                        "description": "Command prompt spawned by an Office application, possible macro execution.",
                        "severity": "critical",
                        "mitre_technique": "T1204.002",
                        "context": f"PID: {proc.get('pid')}, Parent: {parent_name}"
                    })

            # Rule: Process running from unusual directories
            if path:
                unusual_paths = ['\\appdata\\local\\temp\\', '\\users\\public\\', '\\windows\\temp\\']
                for u_path in unusual_paths:
                    if u_path in path and name not in ['update.exe', 'installer.exe']:
                        alerts.append({
                            "title": "Execution from Suspicious Directory",
                            "description": f"Process {name} executing from {u_path}",
                            "severity": "medium",
                            "mitre_technique": "T1036",
                            "context": f"PID: {proc.get('pid')}, Path: {path}"
                        })

            # Rule: svchost.exe parent anomaly
            if name == 'svchost.exe':
                if parent_name and parent_name != 'services.exe':
                    alerts.append({
                        "title": "Suspicious svchost.exe Parent",
                        "description": f"svchost.exe was spawned by {parent_name} instead of services.exe",
                        "severity": "high",
                        "mitre_technique": "T1036.005",
                        "context": f"PID: {proc.get('pid')}, Parent: {parent_name}"
                    })

        return alerts

    def analyze_network(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        c2_ports = [4444, 5555, 8888, 1234, 31337]
        
        for conn in connections:
            remote_port = conn.get('remote_port')
            proc_name = conn.get('process_name', '').lower()
            
            # Rule: Known C2 ports
            if remote_port in c2_ports:
                alerts.append({
                    "title": "Connection to suspicious port",
                    "description": f"Process connected to common C2 port {remote_port}",
                    "severity": "high",
                    "mitre_technique": "T1071",
                    "context": f"Process: {proc_name}, Remote IP: {conn.get('remote_ip')}:{remote_port}"
                })
                
            # Rule: Suspicious processes communicating over network
            suspicious_net_procs = ['cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe']
            if proc_name in suspicious_net_procs:
                alerts.append({
                    "title": "Suspicious Network Communication by Built-in Tool",
                    "description": f"{proc_name} initiated a network connection",
                    "severity": "medium",
                    "mitre_technique": "T1105",
                    "context": f"Process: {proc_name}, Remote IP: {conn.get('remote_ip')}:{remote_port}"
                })
                
        return alerts

    def analyze_registry(self, registry_keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        for key in registry_keys:
            path = key.get('path', '').upper()
            
            # Rule: Persistence in Run keys
            if 'SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN' in path or \
               'SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE' in path:
                alerts.append({
                    "title": "Run Key Persistence Creation",
                    "description": "Registry Run key was modified for persistence",
                    "severity": "medium",
                    "mitre_technique": "T1547.001",
                    "context": f"Key: {path}, Value: {key.get('value')}"
                })
                
        return alerts

    def analyze_scheduled_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        for task in tasks:
            action = task.get('action', '').lower()
            
            if 'powershell' in action and ('-enc' in action or 'bypass' in action):
                alerts.append({
                    "title": "Suspicious Scheduled Task Action",
                    "description": "Scheduled task executes PowerShell with bypass or encoded arguments",
                    "severity": "high",
                    "mitre_technique": "T1053.005",
                    "context": f"Task Name: {task.get('name')}, Action: {action}"
                })
                
        return alerts

    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        for event in events:
            event_id = event.get('event_id')
            
            # Rule: New service installed (7045)
            if event_id == 7045:
                alerts.append({
                    "title": "New Service Installed",
                    "description": "A new service was installed on the system",
                    "severity": "low",
                    "mitre_technique": "T1543.003",
                    "context": f"Service Name: {event.get('service_name')}, Image Path: {event.get('image_path')}"
                })
                
            # Rule: Process injection indicators (8)
            if event_id == 8:
                alerts.append({
                    "title": "CreateRemoteThread Detected",
                    "description": "Potential process injection (CreateRemoteThread)",
                    "severity": "high",
                    "mitre_technique": "T1055",
                    "context": f"Source PID: {event.get('source_pid')}, Target PID: {event.get('target_pid')}"
                })
                
            # Rule: LSASS access (10)
            if event_id == 10:
                target_image = event.get('target_image', '').lower()
                if 'lsass.exe' in target_image:
                    alerts.append({
                        "title": "LSASS Memory Access",
                        "description": "A process accessed the memory of LSASS, potential credential dumping",
                        "severity": "high",
                        "mitre_technique": "T1003.001",
                        "context": f"Source Image: {event.get('source_image')}, Target: {target_image}"
                    })
                    
        return alerts
