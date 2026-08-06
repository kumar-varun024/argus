import concurrent.futures
from typing import Callable, Iterable, Any, List
from argus.performance.metrics import metrics
from argus.performance.profiling import Profiler

class ParallelExecutor:
    """Executes tasks in parallel using a ThreadPoolExecutor to share memory (mission state)."""
    
    def __init__(self, max_workers: int = None):
        # We use ThreadPoolExecutor because Mission objects are heavily nested, 
        # complex, and might not serialize well across Process boundaries (IPC overhead).
        self.max_workers = max_workers

    def map_tasks(self, func: Callable, items: Iterable[Any]) -> List[Any]:
        """
        Executes a function across an iterable of items in parallel.
        Ensures deterministic output by preserving the input order in the output.
        """
        items_list = list(items)
        if not items_list:
            return []

        results = [None] * len(items_list)
        
        with Profiler(f"parallel_{func.__name__}"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit tasks with their index to preserve ordering determinism
                future_to_index = {
                    executor.submit(func, item): i for i, item in enumerate(items_list)
                }
                
                for future in concurrent.futures.as_completed(future_to_index):
                    idx = future_to_index[future]
                    try:
                        results[idx] = future.result()
                    except Exception as exc:
                        # Log or handle exceptions. Re-raising for determinism.
                        raise RuntimeError(f"Task {idx} generated an exception: {exc}") from exc
                        
        metrics.increment("parallel_batches_executed")
        return results

# Default executor instance
executor = ParallelExecutor()
