import logging
from typing import Dict, Any, Type, TypeVar, Optional

logger = logging.getLogger("Container")
T = TypeVar('T')

class ServiceContainer:
    """Lightweight Dependency Injection Container for service registration."""
    
    _instance: Optional['ServiceContainer'] = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._services = {}
        return cls._instance

    def register(self, interface: Type[T], implementation: Any) -> None:
        """Register an implementation for an interface."""
        self._services[interface] = implementation
        logger.debug(f"Registered service: {interface.__name__} -> {type(implementation).__name__}")

    def resolve(self, interface: Type[T]) -> T:
        """Resolve an implementation for a registered interface."""
        if interface not in self._services:
            raise KeyError(f"Service {interface.__name__} is not registered in the container.")
        return self._services[interface]

    def has(self, interface: Type[Any]) -> bool:
        """Check if an interface is registered."""
        return interface in self._services

    def clear(self) -> None:
        """Clear all registered services."""
        self._services.clear()
        logger.debug("Cleared service container.")
