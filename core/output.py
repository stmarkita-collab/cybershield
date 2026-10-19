"""Rich output helpers — pretty terminal UI."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
import json

console = Console()


def banner():
    """Show app banner."""
    console.print(Panel.fit(
        "[bold cyan]🛡️  CyberShield CLI v5.0[/bold cyan]\n"
        "[dim]Professional Cybersecurity Toolkit[/dim]",
        border_style="cyan",
    ))


def section(title: str):
    console.print(f"\n[bold yellow]▶ {title}[/bold yellow]")


def success(msg: str):
    console.print(f"[bold green]✅ {msg}[/bold green]")


def error(msg: str):
    console.print(f"[bold red]❌ {msg}[/bold red]")


def warn(msg: str):
    console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]")


def info(msg: str):
    console.print(f"[cyan]ℹ️  {msg}[/cyan]")


def print_json(data):
    console.print(Syntax(json.dumps(data, indent=2, default=str),
                         "json", theme="monokai", line_numbers=False))


def print_markdown(md: str):
    console.print(Markdown(md))


def result_table(title: str, columns: list, rows: list,
                 severity_col: str = None):
    """Print table with optional severity coloring."""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    for col in columns:
        table.add_column(col)

    for row in rows:
        styled_row = []
        for i, cell in enumerate(row):
            cell_str = str(cell)
            if severity_col and columns[i] == severity_col:
                color = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                    "INFO": "dim",
                }.get(cell_str.upper(), "white")
                styled_row.append(f"[{color}]{cell_str}[/{color}]")
            else:
                styled_row.append(cell_str)
        table.add_row(*styled_row)

    console.print(table)


def metric_row(metrics: dict):
    """Show metrics inline."""
    line = " │ ".join(
        f"[cyan]{k}[/cyan]: [bold]{v}[/bold]" for k, v in metrics.items()
    )
    console.print(line)


def progress_context(description: str, total: int):
    """Return Rich progress context manager."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
  )
