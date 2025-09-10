"""
Core boxi console commands.
"""

import sys
from typing import List, Dict, Any

from .commands import BaseCommand, CommandResult
from boxi.core.database import Database
from boxi import __version__


class ExitCommand(BaseCommand):
    """Exit the boxi console."""

    @property
    def name(self) -> str:
        return "exit"

    @property
    def description(self) -> str:
        return "Exit boxi console"

    @property
    def aliases(self) -> List[str]:
        return ["quit"]

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        self.console.print("[yellow]Goodbye![/yellow]")
        return CommandResult(success=True, should_exit=True)


class UseCommand(BaseCommand):
    """Set target for assessment."""

    @property
    def name(self) -> str:
        return "use"

    @property
    def description(self) -> str:
        return "Set target IP, hostname, or CIDR range"

    @property
    def usage(self) -> str:
        return "use <target>"

    def validate_args(self, args: List[str]) -> bool:
        return len(args) == 1

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        if not self.validate_args(args):
            return CommandResult(
                success=False, message="[red]Usage: use <target>[/red]"
            )

        target = args[0]
        if not self._validate_target(target):
            return CommandResult(
                success=False, message=f"[red]Invalid target: {target}[/red]"
            )

        state["target"] = target
        state["run_id"] = None  # Reset run

        return CommandResult(
            success=True, message=f"[green]Target set: {target}[/green]"
        )

    def _validate_target(self, target: str) -> bool:
        """Validate target IP, hostname, or CIDR range."""
        import ipaddress

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


class RunCommand(BaseCommand):
    """Start assessment against current target."""

    @property
    def name(self) -> str:
        return "run"

    @property
    def description(self) -> str:
        return "Start assessment against current target"

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        if not state.get("target"):
            return CommandResult(
                success=False,
                message="[red]No target set. Use 'use <target>' first[/red]",
            )

        if state.get("running"):
            return CommandResult(
                success=False,
                message="[yellow]Assessment already running. Use 'stop' to halt.[/yellow]",
            )

        # Create new run
        db: Database = state["db"]
        run_id = db.create_run(state["target"], {"version": __version__})
        state["run_id"] = run_id
        state["running"] = True

        return CommandResult(
            success=True,
            message=f"[green]Started assessment {run_id} against {state['target']}[/green]\n"
            f"[yellow]Assessment execution not fully implemented yet[/yellow]",
        )


class StopCommand(BaseCommand):
    """Stop current assessment."""

    @property
    def name(self) -> str:
        return "stop"

    @property
    def description(self) -> str:
        return "Stop current assessment"

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        if not state.get("running"):
            return CommandResult(
                success=False,
                message="[yellow]No assessment currently running[/yellow]",
            )

        state["running"] = False
        if state.get("run_id"):
            db: Database = state["db"]
            db.update_run_status(state["run_id"], "stopped")

        return CommandResult(
            success=True, message="[yellow]Assessment stopped[/yellow]"
        )


class ClearCommand(BaseCommand):
    """Clear console screen."""

    @property
    def name(self) -> str:
        return "clear"

    @property
    def description(self) -> str:
        return "Clear console screen"

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        self.console.clear()
        return CommandResult(success=True)


class HelpCommand(BaseCommand):
    """Show available commands."""

    @property
    def name(self) -> str:
        return "help"

    @property
    def description(self) -> str:
        return "Show this help message"

    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        from rich.table import Table
        from .commands import get_all_commands

        help_table = Table(title="Available Commands")
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="white")

        commands = get_all_commands()
        for cmd in sorted(commands, key=lambda x: x.name):
            display_name = cmd.usage if cmd.usage else cmd.name
            help_table.add_row(display_name, cmd.description)

        self.console.print(help_table)
        return CommandResult(success=True)
