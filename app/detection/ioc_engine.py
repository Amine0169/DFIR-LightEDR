import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class IOCEngine:
    def __init__(self, ioc_path: str):
        self.ioc_path = ioc_path
        self.hashes = set()
        self.ips = set()
        self.domains = set()
        self.sources = {}
        self.load_iocs()

    def load_iocs(self) -> None:
        if not os.path.exists(self.ioc_path):
            logger.warning(f"IOC path not found: {self.ioc_path}")
            return
            
        hash_file = os.path.join(self.ioc_path, 'hashes.txt')
        ip_file = os.path.join(self.ioc_path, 'ips.txt')
        domain_file = os.path.join(self.ioc_path, 'domains.txt')
        
        self._load_file(hash_file, self.hashes, "hash")
        self._load_file(ip_file, self.ips, "ip")
        self._load_file(domain_file, self.domains, "domain")
        
        logger.info(f"Loaded IOCs: {len(self.hashes)} hashes, {len(self.ips)} IPs, {len(self.domains)} domains")

    def _load_file(self, filepath: str, target_set: set, ioc_type: str) -> None:
        if not os.path.exists(filepath):
            return
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(',')
                    value = parts[0].strip()
                    target_set.add(value)
                    
                    if len(parts) > 1:
                        self.sources[value] = parts[1].strip()
                    else:
                        self.sources[value] = "Unknown"
        except Exception as e:
            logger.error(f"Error loading IOC file {filepath}: {e}")

    def check_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        if not hash_value:
            return None
        hash_value = hash_value.lower()
        if hash_value in self.hashes:
            return {
                "ioc_type": "hash",
                "value": hash_value,
                "source": self.sources.get(hash_value, "Unknown"),
                "severity": "high"
            }
        return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        if ip in self.ips:
            return {
                "ioc_type": "ip",
                "value": ip,
                "source": self.sources.get(ip, "Unknown"),
                "severity": "high"
            }
        return None

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        if not domain:
            return None
        domain = domain.lower()
        if domain in self.domains:
            return {
                "ioc_type": "domain",
                "value": domain,
                "source": self.sources.get(domain, "Unknown"),
                "severity": "high"
            }
        return None

    def check_all(self, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        
        # Check hashes
        for file_info in artifacts.get("files", []):
            for h in ["md5", "sha1", "sha256"]:
                if h in file_info and file_info[h]:
                    match = self.check_hash(file_info[h])
                    if match:
                        match["context"] = f"Found in file: {file_info.get('path', 'Unknown')}"
                        matches.append(match)
                        break # One hash match per file is enough
                        
        # Check IPs
        for conn in artifacts.get("network_connections", []):
            remote_ip = conn.get("remote_ip")
            if remote_ip:
                match = self.check_ip(remote_ip)
                if match:
                    match["context"] = f"Connected by process PID: {conn.get('pid', 'Unknown')}"
                    matches.append(match)
                    
        # Check Domains
        for dns in artifacts.get("dns_queries", []):
            domain = dns.get("domain")
            if domain:
                match = self.check_domain(domain)
                if match:
                    match["context"] = f"Queried by process PID: {dns.get('pid', 'Unknown')}"
                    matches.append(match)
                    
        return matches

    def add_ioc(self, ioc_type: str, value: str, source: str = "Manual API") -> bool:
        value = value.strip().lower() if ioc_type != "ip" else value.strip()
        
        if ioc_type == "hash":
            self.hashes.add(value)
        elif ioc_type == "ip":
            self.ips.add(value)
        elif ioc_type == "domain":
            self.domains.add(value)
        else:
            return False
            
        self.sources[value] = source
        return True

    def get_stats(self) -> Dict[str, int]:
        return {
            "hashes": len(self.hashes),
            "ips": len(self.ips),
            "domains": len(self.domains)
        }
