"""
Boxi CLI interface - Interactive penetration testing rich_console.

Provides an msfrich_console-style interactive interface for pentest automation.
"""

import ipaddress
import shlex
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.panel import Panel
from rich.prompt import Prompt

from boxi import __version__
from boxi.console import console as rich_console
from boxi.core.logging import setup_logging, get_logger
from boxi.core.database import Database
from boxi.commands.commands import get_command, register_command
from boxi.config import BoxiSettings
from boxi.commands.core import (
    ExitCommand,
    UseCommand,
    RunCommand,
    StopCommand,
    ClearCommand,
    HelpCommand,
)

app = typer.Typer(
    name="boxi",
    help="Interactive penetration testing CLI for authorized security testing",
    add_completion=False,
    rich_markup_mode=None,
)

logger = get_logger(__name__)
settings = BoxiSettings()


@app.command()
def console(
    target: Optional[str] = typer.Argument(
        None, help="Target IP address, hostname, or CIDR range"
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Enable verbose output"
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="Suppress non-critical output"
    ),
) -> None:
    """Start interactive boxi rich_console."""

    setup_logging(
        level="DEBUG" if verbose else "INFO",
        log_file=settings.logs_dir / "boxi_rich_console.log",
        verbose=verbose,
        quiet=quiet,
    )

    if target:
        # Validate target
        if not _is_valid_target(target):
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
    _start_interactive_console()


def _is_valid_target(target: str) -> bool:
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
        "target": target,
        "run_id": None,
        "db": Database(settings.workspace_root / "boxi.db"),
        "running": False,
    }

    # Register all commands
    commands = [
        ExitCommand(),
        UseCommand(),
        RunCommand(),
        StopCommand(),
        ClearCommand(),
        HelpCommand(),
    ]

    for command in commands:
        register_command(command)

    _show_banner()

    if target:
        rich_console.print(f"[green]Target set: {target}[/green]")
        rich_console.print(
            "Type [cyan]run[/cyan] to start assessment or [cyan]help[/cyan] for commands"
        )
    else:
        rich_console.print(
            "Type [cyan]use <target>[/cyan] to set a target or [cyan]help[/cyan] for commands"
        )

    # Main interactive loop
    try:
        while True:
            try:
                # Build prompt
                prompt_text = _build_prompt(console_state)

                # Get user input
                user_input = Prompt.ask(prompt_text).strip()

                # if user presses spacebar, show status

                if not user_input:
                    continue

                # Parse and execute command
                _execute_console_command(user_input, console_state)
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
        border_style="blue",
    )
    rich_console.print(banner)


def _build_prompt(state: dict) -> str:
    """Build the interactive prompt."""
    if state["target"]:
        if state["running"]:
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

        cmd_name = parts[0].lower()
        args = parts[1:]

        # Get command from registry
        command_obj = get_command(cmd_name)
        if not command_obj:
            rich_console.print(f"[red]Unknown command: {cmd_name}[/red]")
            rich_console.print("Type [cyan]help[/cyan] for available commands")
            return

        # Execute command
        result = command_obj.execute(args, state)

        # Handle result
        if result.message:
            rich_console.print(result.message)

        if result.should_exit:
            sys.exit(0)

    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    app()
