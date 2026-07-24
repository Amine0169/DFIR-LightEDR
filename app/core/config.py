import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List, Optional

class AppConfig(BaseModel):
    name: str
    version: str
    debug: bool
    host: str
    port: int

class DatabaseConfig(BaseModel):
    url: str
    echo: bool

class CollectorConfig(BaseModel):
    interval_seconds: int
    enabled_collectors: List[str]

class DetectionConfig(BaseModel):
    yara_rules_path: str
    sigma_rules_path: str
    ioc_path: str
    rules_dir: str = "rules"

class LoggingConfig(BaseModel):
    level: str
    file: str
    format: str

class MitreConfig(BaseModel):
    attack_data_path: str

class RemoteAgentConfig(BaseModel):
    hostname: str
    ip: str
    os: str
    description: Optional[str] = None

class RemoteConfig(BaseModel):
    enabled: bool = True
    listen_port: int = 8000
    allow_origins: List[str] = ["*"]
    agents: List[RemoteAgentConfig] = []

class Settings(BaseSettings):
    app: AppConfig
    database: DatabaseConfig
    collector: CollectorConfig
    detection: DetectionConfig
    logging: LoggingConfig
    mitre: MitreConfig
    remote: Optional[RemoteConfig] = None

@lru_cache()
def get_settings() -> Settings:
    with open("config.yaml", "r") as f:
        config_dict = yaml.safe_load(f)
    return Settings(**config_dict)
