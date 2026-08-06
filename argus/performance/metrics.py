from typing import Dict, Any, List
import threading
import time

class MetricsRegistry:
    """Centralized metrics tracker for performance monitoring."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MetricsRegistry, cls).__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self):
        self.counters: Dict[str, int] = {}
        self.timers: Dict[str, List[float]] = {}
        self.gauges: Dict[str, float] = {}

    def increment(self, metric: str, amount: int = 1):
        with self._lock:
            if metric not in self.counters:
                self.counters[metric] = 0
            self.counters[metric] += amount

    def record_time(self, metric: str, duration: float):
        with self._lock:
            if metric not in self.timers:
                self.timers[metric] = []
            self.timers[metric].append(duration)

    def set_gauge(self, metric: str, value: float):
        with self._lock:
            self.gauges[metric] = value

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            summary = {
                "counters": self.counters.copy(),
                "gauges": self.gauges.copy(),
                "averages": {}
            }
            for k, v in self.timers.items():
                if v:
                    summary["averages"][k] = sum(v) / len(v)
                else:
                    summary["averages"][k] = 0.0
            return summary

    def clear(self):
        with self._lock:
            self.counters.clear()
            self.timers.clear()
            self.gauges.clear()

metrics = MetricsRegistry()
