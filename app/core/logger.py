import logging
import os
from rich.logging import RichHandler
from app.core.config import get_settings

def setup_logger(name: str, log_file: str) -> logging.Logger:
    settings = get_settings()
    
    logger = logging.getLogger(name)
    logger.setLevel(settings.logging.level)
    
    if logger.hasHandlers():
        return logger

    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(settings.logging.level)
    file_formatter = logging.Formatter(settings.logging.format)
    file_handler.setFormatter(file_formatter)
    
    console_handler = RichHandler(rich_tracebacks=True, markup=True)
    console_handler.setLevel(settings.logging.level)
    console_formatter = logging.Formatter("%(message)s", datefmt="[%X]")
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    settings = get_settings()
    return setup_logger(name, settings.logging.file)
