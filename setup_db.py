from app.database.database import Base, engine, init_db
from app.database import models
from rich.console import Console

console = Console()

def main():
    console.print("[bold blue]Initializing LightEDR Database...[/bold blue]")
    try:
        init_db()
        console.print("[bold green]Successfully created all database tables![/bold green]")
        console.print(f"Database engine: {engine.url}")
    except Exception as e:
        console.print(f"[bold red]Error initializing database: {e}[/bold red]")

if __name__ == "__main__":
    main()
