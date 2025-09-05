"""
Boxi CLI interface using Typer.

Provides command-line interface for running pentest automation.
"""

import ipaddress
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from boxi import __version__
from boxi.config import get_settings
from boxi.logging_config import setup_logging
from boxi.orchestrator import create_orchestrator
from boxi.runtime import RunContext, set_current_context

app = typer.Typer(
    name="boxi",
    help="Human-in-the-loop CTF/pentest CLI for authorized security testing",
    add_completion=False,
)

console = Console()


@app.command()
def run(
    target: str = typer.Argument(..., help="Target IP address or CIDR range"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show planned actions without executing"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress non-critical output"),
    interactive: bool = typer.Option(True, "--interactive/--non-interactive", help="Enable interactive mode"),
    max_iterations: int = typer.Option(20, "--max-iterations", help="Maximum pipeline iterations"),
) -> None:
    """Run boxi against a target."""
    
    # Validate target
    if not _validate_target(target):
        console.print(f"[red]Invalid target: {target}[/red]")
        raise typer.Exit(1)
    
    # Set up logging
    settings = get_settings()
    log_file = settings.logs_dir / f"boxi_{target.replace('.', '_').replace('/', '_')}.log"
    setup_logging(
        level="DEBUG" if verbose else "INFO",
        log_file=log_file,
        verbose=verbose,
        quiet=quiet
    )
    
    console.print(f"[bold blue]🎯 Starting boxi against {target}[/bold blue]")
    
    if dry_run:
        console.print("[yellow]DRY RUN MODE - No actions will be executed[/yellow]")
    
    # Create run context
    context = RunContext(target)
    set_current_context(context)
    
    # Create orchestrator
    orchestrator = create_orchestrator(context)
    
    if dry_run:
        # Show execution plan
        plan = orchestrator.run_pipeline(max_iterations=max_iterations, dry_run=True)
        _display_execution_plan(plan)
        return
    
    # Start interactive mode if requested
    if interactive:
        _run_interactive_mode(orchestrator, max_iterations)
    else:
        # Run non-interactive pipeline
        result = orchestrator.run_pipeline(max_iterations=max_iterations)
        _display_results(result, context)


@app.command()
def report(
    target: Optional[str] = typer.Argument(None, help="Target to generate report for"),
    format: str = typer.Option("markdown", "--format", help="Report format (markdown, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a report from run results."""
    
    if not target:
        # List available targets
        _list_available_targets()
        return
    
    # Load context for target
    try:
        context = RunContext(target)
        
        if format.lower() == "json":
            report_content = _generate_json_report(context)
        else:
            report_content = _generate_markdown_report(context)
        
        if output:
            output.write_text(report_content)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(report_content)
    
    except Exception as e:
        console.print(f"[red]Failed to generate report: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def inject(
    creds: Optional[str] = typer.Option(None, "--creds", help="Inject credentials (username:password)"),
    ignore: Optional[str] = typer.Option(None, "--ignore", help="Add ignore pattern"),
    hint: Optional[str] = typer.Option(None, "--hint", help="Add hint for orchestrator"),
) -> None:
    """Inject information into the current run."""
    
    from boxi.runtime import get_current_context
    
    context = get_current_context()
    if not context:
        console.print("[red]No active run context[/red]")
        raise typer.Exit(1)
    
    if creds:
        if ":" not in creds:
            console.print("[red]Credentials must be in format username:password[/red]")
            raise typer.Exit(1)
        
        username, password = creds.split(":", 1)
        context.inject_credentials(username, password)
        console.print(f"[green]Injected credentials for {username}[/green]")
    
    if ignore:
        context.inject_ignore_pattern(ignore)
        console.print(f"[green]Added ignore pattern: {ignore}[/green]")
    
    if hint:
        context.inject_hint(hint)
        console.print(f"[green]Added hint: {hint}[/green]")
    
    if not any([creds, ignore, hint]):
        console.print("[yellow]No injection specified. Use --help for options.[/yellow]")


@app.command()
def tools() -> None:
    """Show detected external tools and their versions."""
    
    from boxi.utils.process import check_tool_available, get_tool_version
    
    tools_to_check = [
        "nmap", "smbclient", "smbmap", "evil-winrm", "hashcat", "john",
        "tesseract", "pdftotext", "pdftoppm"
    ]
    
    table = Table(title="External Tool Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Available", style="green")
    table.add_column("Version", style="dim")
    
    for tool in tools_to_check:
        available = check_tool_available(tool)
        version = get_tool_version(tool) if available else "N/A"
        
        status = "✓" if available else "✗"
        status_style = "green" if available else "red"
        
        table.add_row(
            tool,
            f"[{status_style}]{status}[/{status_style}]",
            version or "Unknown"
        )
    
    console.print(table)


@app.command("self-update")
def self_update() -> None:
    """Update boxi to the latest version."""
    
    console.print("[yellow]Attempting to update boxi...[/yellow]")
    
    try:
        # Try pip install -U
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-U", "boxi"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            console.print("[green]✓ boxi updated successfully![/green]")
            console.print("Run 'boxi --version' to see the new version")
        else:
            console.print("[red]✗ Update failed[/red]")
            console.print("Try running manually: pip install -U boxi")
    
    except Exception as e:
        console.print(f"[red]Update failed: {e}[/red]")
        console.print("Try running manually: pip install -U boxi")


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
) -> None:
    """Boxi - Human-in-the-loop CTF/pentest CLI."""
    
    if version:
        console.print(f"boxi version {__version__}")
        raise typer.Exit()


def _validate_target(target: str) -> bool:
    """Validate target IP or CIDR."""
    try:
        # Try as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    try:
        # Try as CIDR network
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Try as hostname (basic validation)
    if target.replace(".", "").replace("-", "").isalnum():
        return True
    
    return False


def _run_interactive_mode(orchestrator, max_iterations: int) -> None:
    """Run boxi in interactive mode with user input."""
    
    console.print(Panel(
        "[bold]Interactive Mode[/bold]\n\n"
        "Commands:\n"
        "  [cyan]start[/cyan] - Start/resume the pipeline\n"
        "  [cyan]pause[/cyan] - Pause the pipeline\n"
        "  [cyan]stop[/cyan] - Stop the pipeline\n"
        "  [cyan]status[/cyan] - Show current status\n"
        "  [cyan]plan[/cyan] - Show execution plan\n"
        "  [cyan]inject creds username:password[/cyan] - Inject credentials\n"
        "  [cyan]inject hint TEXT[/cyan] - Add hint\n"
        "  [cyan]report[/cyan] - Generate report\n"
        "  [cyan]quit[/cyan] - Exit",
        title="🎮 Boxi Interactive Console"
    ))
    
    # Start pipeline in background
    pipeline_thread = None
    
    try:
        while True:
            command = Prompt.ask("[bold cyan]boxi>[/bold cyan]", default="status").strip().lower()
            
            if command == "quit" or command == "exit":
                if pipeline_thread and pipeline_thread.is_alive():
                    orchestrator.stop()
                    pipeline_thread.join(timeout=5)
                break
            
            elif command == "start":
                if pipeline_thread and pipeline_thread.is_alive():
                    console.print("[yellow]Pipeline already running[/yellow]")
                    orchestrator.resume()
                else:
                    console.print("[green]Starting pipeline...[/green]")
                    pipeline_thread = threading.Thread(
                        target=lambda: orchestrator.run_pipeline(max_iterations=max_iterations)
                    )
                    pipeline_thread.daemon = True
                    pipeline_thread.start()
            
            elif command == "pause":
                orchestrator.pause()
                console.print("[yellow]Pipeline paused[/yellow]")
            
            elif command == "stop":
                orchestrator.stop()
                if pipeline_thread:
                    pipeline_thread.join(timeout=5)
                console.print("[red]Pipeline stopped[/red]")
            
            elif command == "status":
                _display_status(orchestrator)
            
            elif command == "plan":
                plan = orchestrator._plan_execution()
                _display_execution_plan(plan)
            
            elif command.startswith("inject"):
                _handle_inject_command(command, orchestrator.context)
            
            elif command == "report":
                report = _generate_markdown_report(orchestrator.context)
                console.print(report)
            
            else:
                console.print(f"[red]Unknown command: {command}[/red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        if pipeline_thread and pipeline_thread.is_alive():
            orchestrator.stop()
            pipeline_thread.join(timeout=5)


def _handle_inject_command(command: str, context: RunContext) -> None:
    """Handle inject commands in interactive mode."""
    parts = command.split(maxsplit=2)
    
    if len(parts) < 3:
        console.print("[red]Usage: inject creds username:password OR inject hint TEXT[/red]")
        return
    
    inject_type = parts[1]
    data = parts[2]
    
    if inject_type == "creds":
        if ":" not in data:
            console.print("[red]Credentials must be in format username:password[/red]")
            return
        
        username, password = data.split(":", 1)
        context.inject_credentials(username, password)
        console.print(f"[green]Injected credentials for {username}[/green]")
    
    elif inject_type == "hint":
        context.inject_hint(data)
        console.print(f"[green]Added hint: {data}[/green]")
    
    else:
        console.print(f"[red]Unknown injection type: {inject_type}[/red]")


def _display_status(orchestrator) -> None:
    """Display current orchestrator status."""
    status = orchestrator.get_status()
    
    table = Table(title="Pipeline Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Running", "✓" if status['running'] else "✗")
    table.add_row("Paused", "✓" if status['paused'] else "✗")
    table.add_row("Completed Stages", str(len(status['completed_stages'])))
    table.add_row("Failed Stages", str(len(status['failed_stages'])))
    table.add_row("Services Found", str(status['artifacts']['services']))
    table.add_row("Credentials Found", str(status['artifacts']['credentials']))
    table.add_row("Files Downloaded", str(status['artifacts']['files']))
    table.add_row("Hashes Found", str(status['artifacts']['hashes']))
    
    console.print(table)


def _display_execution_plan(plan: dict) -> None:
    """Display the execution plan."""
    console.print("[bold]Execution Plan[/bold]")
    
    if plan['planned_stages']:
        table = Table(title="Planned Stages")
        table.add_column("Stage", style="green")
        table.add_column("Priority", style="cyan")
        table.add_column("Requirements", style="dim")
        
        for stage in plan['planned_stages']:
            requirements = []
            requirements.extend(stage.get('requires_artifacts', []))
            requirements.extend(stage.get('requires_completed', []))
            
            table.add_row(
                stage['name'],
                str(stage['priority']),
                ", ".join(requirements) if requirements else "None"
            )
        
        console.print(table)
    else:
        console.print("[yellow]No stages planned for execution[/yellow]")
    
    if plan['blocked_stages']:
        console.print("\n[bold]Blocked Stages[/bold]")
        for stage in plan['blocked_stages']:
            console.print(f"• {stage['name']}: {', '.join(stage['reasons'])}")


def _display_results(result: dict, context: RunContext) -> None:
    """Display pipeline execution results."""
    if result['success']:
        console.print(f"[green]✓ Pipeline completed in {result['duration']:.2f}s[/green]")
        console.print(f"Ran {len(result['stages_run'])} stages: {', '.join(result['stages_run'])}")
        
        artifacts = result['artifacts_found']
        console.print(f"\nArtifacts found:")
        console.print(f"• Services: {artifacts['services']}")
        console.print(f"• Credentials: {artifacts['credentials']}")
        console.print(f"• Files: {artifacts['files']}")
        console.print(f"• Hashes: {artifacts['hashes']}")
    else:
        console.print(f"[red]✗ Pipeline failed: {result.get('error', 'Unknown error')}[/red]")


def _list_available_targets() -> None:
    """List available targets for reporting."""
    settings = get_settings()
    runs_dir = settings.runs_dir
    
    if not runs_dir.exists():
        console.print("[yellow]No runs found[/yellow]")
        return
    
    console.print("[bold]Available targets for reporting:[/bold]")
    
    for run_dir in runs_dir.iterdir():
        if run_dir.is_dir():
            console.print(f"• {run_dir.name}")


def _generate_markdown_report(context: RunContext) -> str:
    """Generate a markdown report."""
    from datetime import datetime
    
    report = f"""# Boxi Penetration Test Report

**Target:** {context.target}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Status:** {context.state.status}

## Executive Summary

This report contains the results of an automated penetration test against {context.target} using boxi.

## Discovered Services

"""
    
    services = context.get_artifacts_by_type(context.state.services.__class__)
    if services:
        report += "| Host | Port | Protocol | Service | State |\n"
        report += "|------|------|----------|---------|-------|\n"
        
        for service in services:
            report += f"| {service.target_host} | {service.port} | {service.protocol} | "
            report += f"{service.service_name or 'Unknown'} | {service.state.value} |\n"
    else:
        report += "No services discovered.\n"
    
    report += "\n## Discovered Credentials\n\n"
    
    credentials = context.get_artifacts_by_type(context.state.credentials.__class__)
    if credentials:
        report += "| Username | Source | Score |\n"
        report += "|----------|--------|-------|\n"
        
        for cred in credentials:
            report += f"| {cred.username} | {cred.source} | {cred.score:.2f} |\n"
    else:
        report += "No credentials discovered.\n"
    
    report += "\n## Files Downloaded\n\n"
    
    files = context.get_artifacts_by_type(context.state.files.__class__)
    if files:
        report += "| Filename | Source | Size |\n"
        report += "|----------|--------|------|\n"
        
        for file in files:
            size_str = f"{file.size} bytes" if file.size else "Unknown"
            report += f"| {file.name} | {file.source} | {size_str} |\n"
    else:
        report += "No files downloaded.\n"
    
    report += "\n## Password Hashes\n\n"
    
    hashes = context.get_artifacts_by_type(context.state.hashes.__class__)
    if hashes:
        report += "| Username | Algorithm | Status | Source |\n"
        report += "|----------|-----------|--------|--------|\n"
        
        for hash_obj in hashes:
            status = "Cracked" if hash_obj.cracked_password else "Uncracked"
            report += f"| {hash_obj.username} | {hash_obj.algorithm.value} | {status} | {hash_obj.source} |\n"
    else:
        report += "No password hashes found.\n"
    
    report += "\n## Completed Stages\n\n"
    
    if context.state.completed_stages:
        for stage in context.state.completed_stages:
            report += f"- {stage}\n"
    else:
        report += "No stages completed.\n"
    
    return report


def _generate_json_report(context: RunContext) -> str:
    """Generate a JSON report."""
    report_data = {
        'target': context.target,
        'status': context.state.status,
        'start_time': context.state.start_time.isoformat(),
        'end_time': context.state.end_time.isoformat() if context.state.end_time else None,
        'services': [s.model_dump() for s in context.state.services],
        'credentials': [c.model_dump() for c in context.state.credentials],
        'files': [f.model_dump() for f in context.state.files],
        'hashes': [h.model_dump() for h in context.state.hashes],
        'flags': [f.model_dump() for f in context.state.flags],
        'completed_stages': context.state.completed_stages,
        'failed_stages': context.state.failed_stages,
    }
    
    return json.dumps(report_data, indent=2, default=str)


if __name__ == "__main__":
    app()
