import argparse
import sys
import uvicorn
from rich.console import Console
from rich.table import Table
from app.main import app
from app.core.config import get_settings
from app.database.database import SessionLocal, init_db
from app.collector.collector_manager import CollectorManager
from app.detection.detection_manager import DetectionManager

console = Console()

BANNER = r"""
[bold cyan]
  _      _       _     _  ______ _____  _____  
 | |    (_)     | |   | ||  ____|  __ \|  __ \ 
 | |     _  __ _| |__ | || |__  | |  | | |__) |
 | |    | |/ _` | '_ \| ||  __| | |  | |  _  / 
 | |____| | (_| | | | | || |____| |__| | | \ \ 
 |______|_|\__, |_| |_|_||______|_____/|_|  \_\
            __/ |                              
           |___/                               
[/bold cyan]
[bold green]LightEDR - Digital Forensics & Incident Response[/bold green]
Version: 1.0.0
"""

def run_scan():
    console.print("[bold blue]Running full scan...[/bold blue]")
    settings = get_settings()
    db = SessionLocal()
    try:
        init_db()
        collector_mgr = CollectorManager(db, settings)
        detection_mgr = DetectionManager(settings.model_dump(), db)
        
        result = collector_mgr.run_full_scan()
        session_id = result["session_id"]
        
        console.print(f"[green]Artifacts collected (session_id={session_id})[/green]")
        
        table = Table(title="Collection Results")
        table.add_column("Collector", style="cyan")
        table.add_column("Artifacts", style="magenta")
        table.add_column("Duration", style="green")
        
        for name, info in result["artifacts"].items():
            count = info.get("count", 0)
            dur = info.get("duration_seconds", 0)
            table.add_row(name, str(count), f"{dur:.2f}s")
        
        table.add_row("[bold]TOTAL[/bold]", f"[bold]{result['total_artifacts']}[/bold]", "", style="bold")
        console.print(table)
        
        # Run detection
        console.print("[bold blue]Running detection engines...[/bold blue]")
        alerts = detection_mgr.run_detection(session_id)
        console.print(f"[yellow]Alerts generated: {len(alerts)}[/yellow]")
        
        console.print("[bold green]Scan completed![/bold green]")
        return result
    finally:
        db.close()

def main():
    parser = argparse.ArgumentParser(description="LightEDR Framework")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--init-db", action="store_true", help="Initialize the database")
    parser.add_argument("--scan", action="store_true", help="Run a scan without starting the server")
    
    args = parser.parse_args()
    
    console.print(BANNER)
    
    if args.init_db:
        console.print("[yellow]Initializing database...[/yellow]")
        init_db()
        console.print("[green]Database initialized successfully![/green]")
        return
        
    if args.scan:
        run_scan()
        return
        
    console.print(f"[bold]Starting server on http://{args.host}:{args.port}[/bold]")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.debug)

if __name__ == "__main__":
    main()
