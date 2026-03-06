"""
Rich TUI Console — real-time scan dashboard using `rich` library.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
}

PHASE_EMOJI = {
    "init": "⏳",
    "recon": "🔍",
    "strategy": "🧠",
    "scan": "⚡",
    "validate": "✅",
    "complete": "🏁",
}


class ScanConsole:
    """Rich-based live scan dashboard."""

    def __init__(self):
        self.console = Console()
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console,
        )
        self._live: Optional[Live] = None
        self._findings: List[Dict[str, str]] = []
        self._phase = "init"
        self._target = ""
        self._score = 0.0
        self._thoughts: List[str] = []
        self._module_tasks: Dict[str, TaskID] = {}
        self._stats: Dict[str, Any] = {}

    def start(self, target: str) -> None:
        self._target = target
        self._live = Live(self._build_layout(), console=self.console, refresh_per_second=4)
        self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.stop()

    def update_phase(self, phase: str) -> None:
        self._phase = phase
        self._refresh()

    def update_score(self, score: float) -> None:
        self._score = score
        self._refresh()

    def add_finding(self, title: str, severity: str, url: str, module: str) -> None:
        self._findings.append({
            "title": title, "severity": severity, "url": url, "module": module,
        })
        self._refresh()

    def add_thought(self, thought: str) -> None:
        self._thoughts.append(thought)
        if len(self._thoughts) > 8:
            self._thoughts = self._thoughts[-8:]
        self._refresh()

    def start_module(self, name: str, total: int = 100) -> None:
        task_id = self._progress.add_task(f"[cyan]{name}", total=total)
        self._module_tasks[name] = task_id
        self._refresh()

    def update_module(self, name: str, advance: int = 1) -> None:
        if name in self._module_tasks:
            self._progress.update(self._module_tasks[name], advance=advance)
            self._refresh()

    def complete_module(self, name: str) -> None:
        if name in self._module_tasks:
            self._progress.update(self._module_tasks[name], completed=100)
            self._refresh()

    def update_stats(self, stats: Dict[str, Any]) -> None:
        self._stats = stats
        self._refresh()

    # ── Layout builders ───────────────────────────────────────

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._build_header(), size=5, name="header"),
            Layout(name="body", ratio=1),
            Layout(self._build_footer(), size=3, name="footer"),
        )
        layout["body"].split_row(
            Layout(self._build_findings_table(), ratio=2, name="findings"),
            Layout(self._build_sidebar(), ratio=1, name="sidebar"),
        )
        return layout

    def _build_header(self) -> Panel:
        emoji = PHASE_EMOJI.get(self._phase, "⚙️")
        score_color = "green" if self._score >= 0 else "red"
        header = Text.from_markup(
            f"[bold white]🔍 Bug Bounty Agent[/]  │  "
            f"[dim]Target:[/] [bold cyan]{self._target}[/]  │  "
            f"[dim]Phase:[/] {emoji} [bold]{self._phase.upper()}[/]  │  "
            f"[dim]Score:[/] [{score_color}]{self._score:+.1f}[/]"
        )
        return Panel(header, title="[bold]Autonomous Scanner[/]", border_style="blue")

    def _build_findings_table(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_lines=False)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Title", ratio=2)
        table.add_column("Module", width=14)
        table.add_column("URL", ratio=1)

        for i, f in enumerate(self._findings[-15:], 1):
            sev = f["severity"]
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                str(i), f"[{color}]{sev.upper()}[/]",
                f["title"], f["module"],
                f["url"][:50] + "..." if len(f["url"]) > 50 else f["url"],
            )
        return Panel(table, title="[bold]Findings[/]", border_style="green")

    def _build_sidebar(self) -> Panel:
        parts = []

        # Agent thoughts
        if self._thoughts:
            parts.append("[bold]🧠 Agent Reasoning:[/]")
            for t in self._thoughts[-5:]:
                parts.append(f"  [dim]›[/] {t}")
            parts.append("")

        # Stats
        if self._stats:
            parts.append("[bold]📊 Stats:[/]")
            for k, v in self._stats.items():
                parts.append(f"  {k}: [bold]{v}[/]")
            parts.append("")

        # Module progress
        if self._module_tasks:
            parts.append("[bold]⚡ Modules:[/]")
            parts.append("")

        content = "\n".join(parts) if parts else "[dim]Waiting for data...[/]"
        return Panel(content, title="[bold]Status[/]", border_style="yellow")

    def _build_footer(self) -> Panel:
        return Panel(self._progress, border_style="dim")

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._build_layout())


# ── Static helpers (no live display) ──────────────────────────

def print_banner(target: str, scope: list, modules: int, ai: bool, output: str) -> None:
    console = Console()
    console.print()
    console.print(Panel.fit(
        f"[bold white]🔍 Autonomous Bug Bounty Agent[/]\n\n"
        f"  [dim]Target :[/] [bold cyan]{target}[/]\n"
        f"  [dim]Scope  :[/] {', '.join(scope)}\n"
        f"  [dim]Modules:[/] {modules or 'all'}\n"
        f"  [dim]AI     :[/] {'[green]Enabled ✓[/]' if ai else '[red]Disabled[/]'}\n"
        f"  [dim]Output :[/] {output}",
        title="[bold blue]Scanner Config[/]",
        border_style="blue",
    ))
    console.print()


def print_results(stats: Dict, confirmed: list, score: float) -> None:
    console = Console()

    # Stats table
    table = Table(title="Scan Results", box=box.ROUNDED, border_style="green")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    for k, v in stats.items():
        table.add_row(str(k), str(v))
    table.add_row("Reward Score", f"{score:+.1f}")
    console.print(table)

    # Confirmed findings
    if confirmed:
        console.print(f"\n[bold red]🚨 Confirmed Findings ({len(confirmed)}):[/]")
        for f in confirmed:
            color = SEVERITY_COLORS.get(f.severity, "white")
            console.print(f"  [{color}][{f.severity.upper():8}][/] {f.title}")
            console.print(f"  [dim]           URL: {f.url}[/]")
