"""
Boxi CLI interface - Interactive penetration testing console.

Provides an msfconsole-style interactive interface for pentest automation.
"""

import ipaddress
import shlex
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from boxi import __version__
from boxi.config import get_settings
from boxi.core.logging import setup_logging, get_logger
from boxi.core.database import Database

app = typer.Typer(
    name="boxi",
    help="Interactive penetration testing CLI for authorized security testing",
    add_completion=False,
    rich_markup_mode=None,
)

rich_console = Console()
logger = get_logger(__name__)


@app.command()
def console(
    target: Optional[str] = typer.Argument(None, help="Target IP address, hostname, or CIDR range"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress non-critical output"),
) -> None:
    """Start interactive boxi console."""
    
    # Set up logging
    settings = get_settings()
    setup_logging(
        level="DEBUG" if verbose else "INFO",
        log_file=settings.logs_dir / "boxi_console.log",
        verbose=verbose,
        quiet=quiet
    )
    
    if target:
        # Validate target
        if not _validate_target(target):
            rich_console.print(f"[red]Invalid target: {target}[/red]")
            raise typer.Exit(1)
        
        _start_interactive_console(target)
    else:
        _start_interactive_console()


@app.command()
def version() -> None:
    """Show version information."""
    rich_console.print(f"boxi version {__version__}")


@app.callback()
def main() -> None:
    """Boxi - Interactive penetration testing CLI."""
    pass


def _validate_target(target: str) -> bool:
    """Validate target IP, hostname, or CIDR range."""
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
    
    # Basic hostname validation
    if target.replace(".", "").replace("-", "").isalnum():
        return True
    
    return False


def _start_interactive_console(target: Optional[str] = None) -> None:
    """Start the interactive boxi console."""
    
    # Initialize console state
    console_state = {
        'target': target,
        'run_id': None,
        'db': Database(get_settings().workspace_root / "boxi.db"),
        'running': False,
        'session_data': {}
    }
    
    _show_banner()
    
    if target:
        rich_console.print(f"[green]Target set: {target}[/green]")
        rich_console.print("Type [cyan]run[/cyan] to start assessment or [cyan]help[/cyan] for commands")
    else:
        rich_console.print("Type [cyan]use <target>[/cyan] to set a target or [cyan]help[/cyan] for commands")
    
    # Main interactive loop
    try:
        while True:
            try:
                # Build prompt
                prompt_text = _build_prompt(console_state)
                
                # Get user input
                user_input = Prompt.ask(prompt_text).strip()
                
                if not user_input:
                    continue
                
                # Parse and execute command
                _execute_console_command(user_input, console_state)
                
            except KeyboardInterrupt:
                rich_console.print("\n[yellow]Use 'exit' to quit[/yellow]")
                continue
            except EOFError:
                break
                
    except KeyboardInterrupt:
        rich_console.print("\n[yellow]Exiting boxi console[/yellow]")


def _show_banner() -> None:
    """Show the boxi console banner."""
    banner = Panel(
        f"[bold blue]🎯 Boxi Interactive Console[/bold blue]\n"
        f"[dim]Version {__version__}[/dim]\n\n"
        "[yellow]⚠️  Authorized use only - Ensure you have permission to test target systems[/yellow]",
        title="Welcome to Boxi",
        border_style="blue"
    )
    rich_console.print(banner)


def _build_prompt(state: dict) -> str:
    """Build the interactive prompt."""
    if state['target']:
        if state['running']:
            return f"[bold green]boxi[/bold green]([bold cyan]{state['target']}[/bold cyan]) > "
        else:
            return f"[bold blue]boxi[/bold blue]([bold cyan]{state['target']}[/bold cyan]) > "
    else:
        return "[bold red]boxi[/bold red] > "


def _execute_console_command(command: str, state: dict) -> None:
    """Execute a console command."""
    try:
        # Parse command
        parts = shlex.split(command)
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Route to command handlers
        if cmd in ['exit', 'quit']:
            rich_console.print("[yellow]Goodbye![/yellow]")
            sys.exit(0)
        
        elif cmd == 'help':
            _show_help()
        
        elif cmd == 'use':
            _cmd_use(args, state)
        
        elif cmd == 'info':
            _cmd_info(args, state)
        
        elif cmd == 'run':
            _cmd_run(args, state)
        
        elif cmd == 'stop':
            _cmd_stop(args, state)
        
        elif cmd == 'status':
            _cmd_status(args, state)
        
        elif cmd == 'creds':
            _cmd_creds(args, state)
        
        elif cmd == 'ignore':
            _cmd_ignore(args, state)
        
        elif cmd == 'hint':
            _cmd_hint(args, state)
        
        elif cmd == 'show':
            _cmd_show(args, state)
        
        elif cmd == 'clear':
            rich_console.clear()
        
        else:
            rich_console.print(f"[red]Unknown command: {cmd}[/red]")
            rich_console.print("Type [cyan]help[/cyan] for available commands")
    
    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")


def _show_help() -> None:
    """Show available commands."""
    help_table = Table(title="Available Commands")
    help_table.add_column("Command", style="cyan")
    help_table.add_column("Description", style="white")
    
    commands = [
        ("use <target>", "Set target IP, hostname, or CIDR range"),
        ("info", "Show current target information"),
        ("run", "Start assessment against current target"),
        ("stop", "Stop current assessment"),
        ("status", "Show assessment status and progress"),
        ("creds <user:pass>", "Add credentials for testing"),
        ("ignore <pattern>", "Add ignore pattern for files/directories"),
        ("hint <text>", "Add hint to guide assessment"),
        ("show <type>", "Show discovered artifacts (services, creds, files)"),
        ("clear", "Clear console screen"),
        ("help", "Show this help message"),
        ("exit/quit", "Exit boxi console"),
    ]
    
    for cmd, desc in commands:
        help_table.add_row(cmd, desc)
    
    rich_console.print(help_table)


def _cmd_use(args: List[str], state: dict) -> None:
    """Set target command."""
    if not args:
        rich_console.print("[red]Usage: use <target>[/red]")
        return
    
    target = args[0]
    if not _validate_target(target):
        rich_console.print(f"[red]Invalid target: {target}[/red]")
        return
    
    state['target'] = target
    state['run_id'] = None  # Reset run
    rich_console.print(f"[green]Target set: {target}[/green]")


def _cmd_info(args: List[str], state: dict) -> None:
    """Show target info command."""
    if not state['target']:
        rich_console.print("[red]No target set. Use 'use <target>' first[/red]")
        return
    
    rich_console.print(f"[bold]Current Target:[/bold] {state['target']}")
    
    # Show run info if exists
    if state['run_id']:
        run_data = state['db'].get_run(state['run_id'])
        if run_data:
            rich_console.print(f"[bold]Active Run:[/bold] {state['run_id']} ({run_data['status']})")


def _cmd_run(args: List[str], state: dict) -> None:
    """Start assessment command."""
    if not state['target']:
        rich_console.print("[red]No target set. Use 'use <target>' first[/red]")
        return
    
    if state['running']:
        rich_console.print("[yellow]Assessment already running. Use 'stop' to halt.[/yellow]")
        return
    
    # Create new run
    run_id = state['db'].create_run(state['target'], {"version": __version__})
    state['run_id'] = run_id
    state['running'] = True
    
    rich_console.print(f"[green]Started assessment {run_id} against {state['target']}[/green]")
    rich_console.print("[yellow]Assessment execution not fully implemented yet[/yellow]")


def _cmd_stop(args: List[str], state: dict) -> None:
    """Stop assessment command."""
    if not state['running']:
        rich_console.print("[yellow]No assessment currently running[/yellow]")
        return
    
    state['running'] = False
    if state['run_id']:
        state['db'].update_run_status(state['run_id'], 'stopped')
    
    rich_console.print("[yellow]Assessment stopped[/yellow]")


def _cmd_status(args: List[str], state: dict) -> None:
    """Show status command."""
    if not state['run_id']:
        rich_console.print("[yellow]No active assessment[/yellow]")
        return
    
    run_data = state['db'].get_run(state['run_id'])
    if run_data:
        _show_run_status(state['db'], run_data)


def _cmd_creds(args: List[str], state: dict) -> None:
    """Add credentials command."""
    if not args:
        rich_console.print("[red]Usage: creds <username:password>[/red]")
        return
    
    cred_str = args[0]
    if ':' not in cred_str:
        rich_console.print("[red]Credentials must be in format username:password[/red]")
        return
    
    username, password = cred_str.split(':', 1)
    
    # Store in session data for now
    state['session_data'].setdefault('credentials', []).append({
        'username': username,
        'password': password
    })
    
    rich_console.print(f"[green]Added credentials for {username}[/green]")


def _cmd_ignore(args: List[str], state: dict) -> None:
    """Add ignore pattern command."""
    if not args:
        rich_console.print("[red]Usage: ignore <pattern>[/red]")
        return
    
    pattern = args[0]
    state['session_data'].setdefault('ignore_patterns', []).append(pattern)
    rich_console.print(f"[green]Added ignore pattern: {pattern}[/green]")


def _cmd_hint(args: List[str], state: dict) -> None:
    """Add hint command."""
    if not args:
        rich_console.print("[red]Usage: hint <hint text>[/red]")
        return
    
    hint = ' '.join(args)
    state['session_data'].setdefault('hints', []).append(hint)
    rich_console.print(f"[green]Added hint: {hint}[/green]")


def _cmd_show(args: List[str], state: dict) -> None:
    """Show artifacts command."""
    if not args:
        rich_console.print("[red]Usage: show <type>[/red]")
        rich_console.print("Available types: services, creds, files, hints, ignore")
        return
    
    show_type = args[0].lower()
    
    if show_type in ['creds', 'credentials']:
        creds = state['session_data'].get('credentials', [])
        if creds:
            table = Table(title="Stored Credentials")
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="dim")
            
            for cred in creds:
                table.add_row(cred['username'], "*" * len(cred['password']))
            
            rich_console.print(table)
        else:
            rich_console.print("[yellow]No credentials stored[/yellow]")
    
    elif show_type == 'hints':
        hints = state['session_data'].get('hints', [])
        if hints:
            rich_console.print("[bold]Stored Hints:[/bold]")
            for i, hint in enumerate(hints, 1):
                rich_console.print(f"{i}. {hint}")
        else:
            rich_console.print("[yellow]No hints stored[/yellow]")
    
    elif show_type == 'ignore':
        patterns = state['session_data'].get('ignore_patterns', [])
        if patterns:
            rich_console.print("[bold]Ignore Patterns:[/bold]")
            for pattern in patterns:
                rich_console.print(f"- {pattern}")
        else:
            rich_console.print("[yellow]No ignore patterns set[/yellow]")
    
    else:
        rich_console.print(f"[red]Unknown type: {show_type}[/red]")


def _show_run_status(db: Database, run_data: dict) -> None:
    """Show status for a specific run."""
    table = Table(title=f"Assessment {run_data['id']} Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Target", run_data['target'])
    table.add_row("Status", run_data['status'])
    table.add_row("Start Time", str(run_data['start_time']))
    
    # Get artifact counts
    artifacts = db.get_artifacts(run_data['id'])
    artifact_counts = {}
    for artifact in artifacts:
        artifact_type = artifact['artifact_type']
        artifact_counts[artifact_type] = artifact_counts.get(artifact_type, 0) + 1
    
    for artifact_type, count in artifact_counts.items():
        table.add_row(f"{artifact_type.title()}s Found", str(count))
    
    rich_console.print(table)


if __name__ == "__main__":
    app()