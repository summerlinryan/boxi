"""
Command registry and base classes for boxi CLI commands.

Provides an extensible system for defining and registering console commands.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass

from rich.console import Console


@dataclass
class CommandResult:
    """Result of command execution."""
    success: bool
    message: Optional[str] = None
    should_exit: bool = False


class BaseCommand(ABC):
    """Base class for all boxi console commands."""
    
    def __init__(self, console: Console):
        self.console = console
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Command name as typed by user."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Short description for help text."""
        pass
    
    @property
    def usage(self) -> Optional[str]:
        """Usage string. If None, uses just the command name."""
        return None
    
    @property
    def aliases(self) -> List[str]:
        """Alternative names for this command."""
        return []
    
    @abstractmethod
    def execute(self, args: List[str], state: Dict[str, Any]) -> CommandResult:
        """Execute the command with given arguments and console state."""
        pass
    
    def validate_args(self, args: List[str]) -> bool:
        """Validate arguments. Override for custom validation."""
        return True


class CommandRegistry:
    """Registry for managing console commands."""
    
    def __init__(self):
        self._commands: Dict[str, BaseCommand] = {}
        self._aliases: Dict[str, str] = {}
    
    def register(self, command: BaseCommand) -> None:
        """Register a command in the registry."""
        self._commands[command.name] = command
        
        # Register aliases
        for alias in command.aliases:
            self._aliases[alias] = command.name
    
    def get_command(self, name: str) -> Optional[BaseCommand]:
        """Get command by name or alias."""
        # Check if it's an alias first
        if name in self._aliases:
            name = self._aliases[name]
        
        return self._commands.get(name)
    
    def list_commands(self) -> List[BaseCommand]:
        """Get all registered commands."""
        return list(self._commands.values())
    
    def get_command_names(self) -> List[str]:
        """Get all command names (including aliases)."""
        names = list(self._commands.keys())
        names.extend(self._aliases.keys())
        return sorted(names)


# Global registry instance
_registry = CommandRegistry()


def register_command(command: BaseCommand) -> None:
    """Register a command globally."""
    _registry.register(command)


def get_command(name: str) -> Optional[BaseCommand]:
    """Get a command by name."""
    return _registry.get_command(name)


def get_all_commands() -> List[BaseCommand]:
    """Get all registered commands."""
    return _registry.list_commands()
