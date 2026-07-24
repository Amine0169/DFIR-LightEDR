import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import dashboard, alerts, hosts, investigations, mitre, reports, ingest
from app.database.database import init_db

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LightEDR",
    description="Digital Forensics & Incident Response Framework",
    version="1.0.0"
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Include routers
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(hosts.router)
app.include_router(investigations.router)
app.include_router(mitre.router)
app.include_router(reports.router)
app.include_router(ingest.router)

@app.on_event("startup")
async def startup_event():
    init_db()
    # Apply schema migrations for new columns (development-friendly)
    from app.database.database import engine as _engine
    from sqlalchemy import text as _text
    try:
        with _engine.connect() as conn:
            for table, cols in [
                ("scan_sessions", [("agent_version", "VARCHAR"), ("agent_concept", "VARCHAR"),
                                   ("kape_targets", "VARCHAR"), ("sysmon_detected", "BOOLEAN"),
                                   ("sysmon_events", "INTEGER")]),
                ("hosts", [("sysmon_detected", "BOOLEAN")]),
            ]:
                for col, col_type in cols:
                    try:
                        conn.execute(_text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass
    except Exception:
        pass
    logger.info("LightEDR Application Started")

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# Global exception handlers can be added here
