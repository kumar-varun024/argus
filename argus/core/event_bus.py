from collections import defaultdict
from typing import Callable


class EventBus:
    def __init__(self):
        self._listeners = defaultdict(list)

    def subscribe(self, event_name: str, callback: Callable):
        """Register a listener for an event."""
        self._listeners[event_name].append(callback)

    def publish(self, event_name: str, data=None):
        """Notify all listeners of an event."""
        if event_name not in self._listeners:
            return

        for callback in self._listeners[event_name]:
            callback(data)
