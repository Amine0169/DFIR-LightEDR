import xml.etree.ElementTree as ET
import subprocess
from typing import Any, Dict, List
from .base_collector import BaseCollector

class EventLogCollector(BaseCollector):
    """Collects critical event logs."""
    
    def get_name(self) -> str:
        return "EventLog Collector"

    def _collect_windows(self) -> List[Dict[str, Any]]:
        events = []
        channels = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational"
        ]
        
        target_ids = {
            "Security": {"4624", "4625", "4648", "4672", "4688", "4697", "4720", "4732"},
            "System": {"7045", "7036"},
            "Microsoft-Windows-Sysmon/Operational": {"1", "3", "7", "8", "10", "11", "12", "13", "14", "22"}
        }

        for channel in channels:
            try:
                cmd = ["wevtutil", "qe", channel, "/f:xml", "/c:1000", "/rd:true"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
                root = ET.fromstring(f"<root>{output.decode('utf-8', errors='ignore')}</root>")
                
                ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                for event in root.findall("ns:Event", ns):
                    sys = event.find("ns:System", ns)
                    if sys is not None:
                        event_id = sys.find("ns:EventID", ns)
                        if event_id is not None:
                            eid = event_id.text
                            if channel in target_ids and eid not in target_ids[channel]:
                                continue
                            
                            provider = sys.find("ns:Provider", ns).attrib.get('Name', '') if sys.find("ns:Provider", ns) is not None else ""
                            time_created = sys.find("ns:TimeCreated", ns).attrib.get('SystemTime', '') if sys.find("ns:TimeCreated", ns) is not None else ""
                            
                            event_data = {}
                            ed = event.find("ns:EventData", ns)
                            if ed is not None:
                                for data in ed.findall("ns:Data", ns):
                                    name = data.attrib.get('Name', 'Unknown')
                                    event_data[name] = data.text
                            
                            events.append({
                                "channel": channel,
                                "event_id": eid,
                                "provider": provider,
                                "time_created": time_created,
                                "data": str(event_data)
                            })
            except Exception:
                continue
        return events

    def _collect_linux(self) -> List[Dict[str, Any]]:
        events = []
        log_files = ["/var/log/syslog", "/var/log/auth.log"]
        for log_file in log_files:
            try:
                cmd = ["tail", "-n", "1000", log_file]
                output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    events.append({
                        "channel": log_file,
                        "event_id": "N/A",
                        "provider": "syslog",
                        "time_created": "N/A", # Complex to parse arbitrary syslog easily
                        "data": line.strip()
                    })
            except Exception:
                continue
        return events

    def collect(self) -> List[Dict[str, Any]]:
        if self.os_type == 'windows':
            self.artifacts = self._collect_windows()
        else:
            self.artifacts = self._collect_linux()
        return self.artifacts
