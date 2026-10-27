"""Presentation formatters for Rich terminal output and structured JSON."""

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from rich.panel import Panel
from rich.table import Table

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus


def format_scan_result_row(result: ScanResult) -> List[str]:
    """Format a single ScanResult for tabular output."""
    if result.status == ScanStatus.CLEAN:
        status_styled = "[bold green]CLEAN[/bold green]"
    elif result.status == ScanStatus.INFECTED:
        status_styled = "[bold red]INFECTED[/bold red]"
    elif result.status == ScanStatus.ERROR:
        status_styled = "[bold yellow]ERROR[/bold yellow]"
    else:
        status_styled = f"[cyan]{result.status.value}[/cyan]"

    threat_str = "-"
    if result.threat:
        threat_str = f"[bold red]{result.threat.threat_name}[/bold red] ({result.threat.severity.value})"

    hash_preview = f"{result.file_hash[:12]}..." if result.file_hash else "-"
    duration = f"{result.scan_duration_ms:.1f}ms"

    return [
        str(result.file_path),
        status_styled,
        threat_str,
        hash_preview,
        duration,
    ]


def format_scan_summary_table(results: Iterable[ScanResult]) -> Table:
    """Build a Rich Table presenting scan results."""
    table = Table(title="[bold blue]PulseGuard Scan Report[/bold blue]")
    table.add_column("Target Path", style="dim", overflow="fold")
    table.add_column("Status", justify="center")
    table.add_column("Threat / Rule", justify="left")
    table.add_column("SHA-256", justify="center", style="dim")
    table.add_column("Time", justify="right")

    for result in results:
        table.add_row(*format_scan_result_row(result))

    return table


def format_quarantine_table(records: List[QuarantineRecord]) -> Table:
    """Build a Rich Table displaying quarantine vault contents."""
    table = Table(title="[bold magenta]PulseGuard Quarantine Vault[/bold magenta]")
    table.add_column("Record ID", style="cyan", no_wrap=True)
    table.add_column("Original Path", overflow="fold")
    table.add_column("Threat Name", style="red bold")
    table.add_column("Severity", justify="center")
    table.add_column("Quarantined At", style="dim")
    table.add_column("Status", justify="center")

    for record in records:
        status_str = "[dim strike]Restored[/dim strike]" if record.is_restored else "[bold green]Isolated[/bold green]"
        table.add_row(
            record.record_id,
            str(record.original_path),
            record.threat.threat_name,
            record.threat.severity.value,
            record.quarantined_at.strftime("%Y-%m-%d %H:%M:%S"),
            status_str,
        )

    return table


def format_status_panel(
    active_signatures: int,
    quarantine_count: int,
    vault_path: Path,
    is_watcher_running: bool = False,
) -> Panel:
    """Build a Rich Panel displaying overall antivirus status."""
    watcher_state = "[bold green]ACTIVE[/bold green]" if is_watcher_running else "[dim]STOPPED[/dim]"
    text = (
        f"[bold]Engine Status:[/bold] [bold green]ONLINE[/bold green]\n"
        f"[bold]Signatures Loaded:[/bold] [cyan]{active_signatures}[/cyan]\n"
        f"[bold]Real-Time Watcher:[/bold] {watcher_state}\n"
        f"[bold]Quarantined Files:[/bold] [magenta]{quarantine_count}[/magenta]\n"
        f"[bold]Vault Location:[/bold] [dim]{vault_path}[/dim]"
    )
    return Panel(text, title="[bold blue]PulseGuard Antivirus Status[/bold blue]", border_style="blue")


def scan_results_to_json(results: Iterable[ScanResult]) -> str:
    """Serialize scan results to JSON."""
    records: List[Dict[str, Any]] = []
    for res in results:
        threat_dict = None
        if res.threat:
            threat_dict = {
                "name": res.threat.threat_name,
                "type": res.threat.threat_type,
                "severity": res.threat.severity.value,
                "rule_matched": res.threat.rule_matched,
                "file_hash": res.threat.file_hash,
            }
        records.append({
            "file_path": str(res.file_path),
            "status": res.status.value,
            "is_infected": res.is_infected,
            "file_hash": res.file_hash,
            "timestamp": res.timestamp.isoformat(),
            "scan_duration_ms": res.scan_duration_ms,
            "threat": threat_dict,
            "error_message": res.error_message,
        })
    return json.dumps(records, indent=2)
