import platform
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List

class BaseCollector(ABC):
    """Abstract base class for all artifact collectors."""
    
    def __init__(self, session_id: int = None):
        self.session_id = session_id
        self.collected_at = datetime.utcnow()
        self.artifacts: List[Dict[str, Any]] = []
        self.os_type = self._detect_os()
    
    def _detect_os(self) -> str:
        return 'windows' if platform.system().lower() == 'windows' else 'linux'
    
    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collect artifacts and return as list of dicts."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Return collector name."""
        pass
    
    def to_summary(self) -> Dict[str, Any]:
        return {
            'collector': self.get_name(),
            'os': self.os_type,
            'collected_at': self.collected_at.isoformat(),
            'total_artifacts': len(self.artifacts)
        }
