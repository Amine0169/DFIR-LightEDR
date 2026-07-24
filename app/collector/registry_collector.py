from typing import Any, Dict, List
from .base_collector import BaseCollector

class RegistryCollector(BaseCollector):
    """Collects Windows Registry persistence keys."""
    
    def get_name(self) -> str:
        return "Registry Collector"

    def _collect_windows(self) -> List[Dict[str, Any]]:
        import winreg
        results = []
        
        target_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", True),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", True),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", False),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", False)
        ]
        
        for hive, subkey_path, is_persistence in target_keys:
            try:
                with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if not is_persistence and name.lower() not in ["shell", "userinit"]:
                                i += 1
                                continue
                            
                            hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                            results.append({
                                "hive": hive_name,
                                "key_path": subkey_path,
                                "value_name": name,
                                "value_data": str(value),
                                "is_persistence": is_persistence
                            })
                            i += 1
                        except OSError:
                            break
            except Exception:
                continue
                
        return results

    def collect(self) -> List[Dict[str, Any]]:
        if self.os_type == 'windows':
            self.artifacts = self._collect_windows()
        else:
            self.artifacts = []
        return self.artifacts
