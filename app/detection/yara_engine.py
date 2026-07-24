import os
import glob
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logger.warning("YARA module not installed. YaraEngine will be disabled.")
    YARA_AVAILABLE = False


class YaraEngine:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self._load_rules()

    def _load_rules(self) -> None:
        if not YARA_AVAILABLE:
            return
            
        rule_files = {}
        
        path = Path(self.rules_path)
        if not path.exists() or not path.is_dir():
            logger.warning(f"YARA rules path not found: {self.rules_path}")
            return
            
        for ext in ('*.yar', '*.yara'):
            for file_path in path.rglob(ext):
                try:
                    # Test compile each rule to skip bad ones
                    yara.compile(filepath=str(file_path))
                    rule_files[str(file_path.name)] = str(file_path)
                except yara.SyntaxError as e:
                    logger.warning(f"YARA Syntax Error in {file_path}: {e}")
                except Exception as e:
                    logger.warning(f"Error loading YARA rule {file_path}: {e}")
                    
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                logger.info(f"Loaded {len(rule_files)} YARA rule files.")
            except Exception as e:
                logger.error(f"Failed to compile YARA rules namespace: {e}")

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        if not self.rules or not os.path.exists(filepath):
            return []
            
        matches = []
        try:
            # Set timeout to 30 seconds
            yara_matches = self.rules.match(filepath, timeout=30)
            for match in yara_matches:
                matches.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [{"offset": s[0], "identifier": s[1], "data": s[2]} for s in match.strings]
                })
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for file: {filepath}")
        except Exception as e:
            logger.error(f"YARA scan error on file {filepath}: {e}")
            
        return matches

    def scan_directory(self, dirpath: str, extensions: List[str]) -> List[Dict[str, Any]]:
        results = []
        if not self.rules or not os.path.exists(dirpath):
            return results
            
        path = Path(dirpath)
        for ext in extensions:
            for filepath in path.rglob(f"*{ext}"):
                if filepath.is_file():
                    matches = self.scan_file(str(filepath))
                    if matches:
                        results.append({
                            "file": str(filepath),
                            "matches": matches
                        })
        return results

    def scan_process_memory(self, pid: int) -> List[Dict[str, Any]]:
        if not self.rules:
            return []
            
        matches = []
        try:
            yara_matches = self.rules.match(pid=pid, timeout=30)
            for match in yara_matches:
                matches.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [{"offset": s[0], "identifier": s[1], "data": s[2]} for s in match.strings]
                })
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for process ID: {pid}")
        except Exception as e:
            logger.error(f"YARA process scan error for PID {pid}: {e}")
            
        return matches

    def get_loaded_rules_count(self) -> int:
        if not self.rules:
            return 0
        # In a typical python-yara rules object, it acts like an iterable or we can just count iterating over it
        try:
            return sum(1 for _ in self.rules)
        except Exception:
            return 0
