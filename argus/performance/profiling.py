import time
import functools
import tracemalloc
from typing import Callable, Any
from argus.performance.metrics import metrics

class Profiler:
    """Context manager for profiling code blocks."""
    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        self.start_time = time.perf_counter()
        tracemalloc.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.perf_counter() - self.start_time
        metrics.record_time(f"{self.name}_time", duration)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # We record peak memory as a gauge for simplicity, though gauges usually track current.
        # Alternatively, track maximum observed peak memory across calls.
        metrics.set_gauge(f"{self.name}_peak_memory_bytes", peak)

def profile(name: str = None) -> Callable:
    """Decorator to profile a function's execution time and memory."""
    def decorator(func: Callable) -> Callable:
        metric_name = name or func.__name__
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            with Profiler(metric_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator
