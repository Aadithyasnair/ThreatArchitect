import logging
from collections import defaultdict
from typing import Callable, Any, Dict, List

logger = logging.getLogger("EventBus")

class EventBus:
    """A lightweight publisher-subscriber event bus for decoupled communication."""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._listeners = defaultdict(list)
        return cls._instance

    def subscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Register a callback for a specific event type."""
        if callback not in self._listeners[event_type]:
            self._listeners[event_type].append(callback)
            logger.debug(f"Subscribed callback to event: {event_type}")

    def unsubscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Deregister a callback from an event type."""
        if callback in self._listeners[event_type]:
            self._listeners[event_type].remove(callback)
            logger.debug(f"Unsubscribed callback from event: {event_type}")

    def publish(self, event_type: str, data: Any = None) -> None:
        """Trigger all callbacks registered for the event type."""
        logger.debug(f"Publishing event {event_type} with data: {data}")
        # Iterate over a copy of the list to prevent modification during execution
        for callback in list(self._listeners[event_type]):
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Error handling event {event_type} in {callback.__name__ if hasattr(callback, '__name__') else str(callback)}: {e}")
