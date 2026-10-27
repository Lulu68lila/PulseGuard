"""PulseGuard CLI main entrypoint."""

import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus
from pulseguard.engine.scanner import ScannerEngine, load_signatures, scan_directory, scan_file
from pulseguard.engine.signatures import SignatureDatabase
from pulseguard.quarantine.manager import (
    QuarantineError,
    QuarantineManager,
    delete_quarantine,
    list_quarantine,
    quarantine_file,
    restore_file,
)
from pulseguard.reporting.formatter import (
    format_quarantine_table,
    format_scan_summary_table,
    format_status_panel,
    scan_results_to_json,
)
from pulseguard.service.runner import PulseGuardService

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="PulseGuard")
def cli() -> None:
    """PulseGuard — Endpoint Antivirus Engine & Real-Time Protection."""


@cli.command("scan")
@click.argument("target_path", type=click.Path(exists=True, path_type=Path))
@click.option("--recursive", "-r", is_flag=True, default=True, help="Scan directories recursively.")
@click.option("--quarantine", "-q", is_flag=True, default=False, help="Automatically quarantine infected files.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results in JSON format.")
def scan_cmd(target_path: Path, recursive: bool, quarantine: bool, json_output: bool) -> None:
    """Scan a file or directory for known viruses and heuristic threats."""
    results: List[ScanResult] = []

    if target_path.is_file():
        res = scan_file(target_path)
        results.append(res)
    else:
        results = list(scan_directory(target_path, recursive=recursive))

    infected_count = sum(1 for r in results if r.is_infected)
    quarantined_records: List[QuarantineRecord] = []

    if quarantine and infected_count > 0:
        for r in results:
            if r.is_infected and r.threat and r.file_path.exists():
                try:
                    q_rec = quarantine_file(r.file_path, r.threat)
                    quarantined_records.append(q_rec)
                except Exception as exc:
                    console.print(f"[bold red]Failed to quarantine {r.file_path}: {exc}[/bold red]")

    if json_output:
        click.echo(scan_results_to_json(results))
    else:
        console.print(format_scan_summary_table(results))
        if quarantined_records:
            console.print(
                f"[bold green]Successfully quarantined {len(quarantined_records)} threat(s) to vault.[/bold green]"
            )

    if infected_count > 0:
        sys.exit(1)


@cli.command("watch")
@click.argument("watch_path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
@click.option("--quarantine", "-q", is_flag=True, default=False, help="Automatically quarantine threats detected live.")
def watch_cmd(watch_path: Path, quarantine: bool) -> None:
    """Launch real-time filesystem monitoring on a directory."""
    console.print(f"[bold blue]PulseGuard Real-Time Protection active on:[/bold blue] [cyan]{watch_path}[/cyan]")
    console.print("[dim]Press Ctrl+C to stop monitoring...[/dim]\n")

    def on_live_event(result: ScanResult, q_record: Optional[QuarantineRecord]) -> None:
        if result.is_infected:
            console.print(
                f"[bold red][ALERT][/bold red] Threat detected: [bold]{result.file_path}[/bold] "
                f"({result.threat.threat_name if result.threat else 'Unknown'})"
            )
            if q_record:
                console.print(f"  [magenta]-> Isolated into vault ID: {q_record.record_id}[/magenta]")
        elif result.status == ScanStatus.CLEAN:
            console.print(f"[green][OK][/green] Scanned: {result.file_path} (Clean)")
        elif result.status == ScanStatus.ERROR:
            console.print(f"[yellow][WARN][/yellow] Could not scan {result.file_path}: {result.error_message}")

    service = PulseGuardService(
        watch_paths=[watch_path],
        auto_quarantine=quarantine,
        on_event_callback=on_live_event,
    )

    try:
        service.start(block=True)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped by user.[/bold yellow]")


@cli.group("quarantine")
def quarantine_group() -> None:
    """Manage quarantined files and vault storage."""


@quarantine_group.command("list")
def quarantine_list_cmd() -> None:
    """List all quarantined files in the vault."""
    records = list_quarantine()
    if not records:
        console.print("[dim]The quarantine vault is empty.[/dim]")
    else:
        console.print(format_quarantine_table(records))


@quarantine_group.command("restore")
@click.argument("record_id")
@click.option("--dest", "-d", type=click.Path(path_type=Path), default=None, help="Custom restoration destination path.")
def quarantine_restore_cmd(record_id: str, dest: Optional[Path]) -> None:
    """Restore a quarantined file to its original or designated location."""
    try:
        restored_path = restore_file(record_id, destination=dest)
        console.print(
            f"[bold green]Successfully restored record {record_id} to:[/bold green] [cyan]{restored_path}[/cyan]"
        )
    except QuarantineError as exc:
        console.print(f"[bold red]Restoration error:[/bold red] {exc}")
        sys.exit(2)


@quarantine_group.command("delete")
@click.argument("record_id")
def quarantine_delete_cmd(record_id: str) -> None:
    """Permanently shred and delete a quarantined file."""
    try:
        success = delete_quarantine(record_id)
        if success:
            console.print(f"[bold green]Record {record_id} permanently shredded and deleted.[/bold green]")
        else:
            console.print(f"[bold yellow]Record {record_id} not found in catalog.[/bold yellow]")
            sys.exit(2)
    except QuarantineError as exc:
        console.print(f"[bold red]Deletion error:[/bold red] {exc}")
        sys.exit(2)


@cli.command("status")
def status_cmd() -> None:
    """Display antivirus engine health, signature count, and vault statistics."""
    db = SignatureDatabase(include_defaults=True)
    records = list_quarantine()
    mgr = QuarantineManager()
    console.print(
        format_status_panel(
            active_signatures=db.total_hash_signatures + db.total_byte_patterns,
            quarantine_count=len(records),
            vault_path=mgr.vault_dir,
            is_watcher_running=False,
        )
    )


if __name__ == "__main__":
    cli()
