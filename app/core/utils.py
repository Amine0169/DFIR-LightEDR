import hashlib
import platform
import socket
import os
import getpass
from datetime import datetime
from typing import Any

def get_os_type() -> str:
    return platform.system().lower()

def compute_file_hash(filepath: str, algo: str = 'sha256') -> str:
    if not os.path.isfile(filepath):
        return ""
    hash_func = getattr(hashlib, algo)()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return ""

def compute_md5(filepath: str) -> str:
    return compute_file_hash(filepath, algo='md5')

def safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return ""

def get_hostname() -> str:
    return socket.gethostname()

def get_ip_address() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_current_user() -> str:
    return getpass.getuser()

def format_timestamp(dt: datetime) -> str:
    return dt.isoformat()

def is_admin() -> bool:
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def bytes_to_human(n: int) -> str:
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return f'{value:.1f}{s}'
    return f"{n}B"
