from typing import List, Callable, Any, Dict
from argus.performance.parallel import executor
from argus.performance.metrics import metrics

class TaskNode:
    def __init__(self, task_id: str, func: Callable, args: tuple = (), kwargs: dict = None):
        self.task_id = task_id
        self.func = func
        self.args = args
        self.kwargs = kwargs or {}
        self.dependencies: List[str] = []

class TaskScheduler:
    """Schedules and executes tasks based on their dependencies."""
    def __init__(self):
        self.tasks: Dict[str, TaskNode] = {}

    def add_task(self, task_id: str, func: Callable, args: tuple = (), kwargs: dict = None, depends_on: List[str] = None):
        node = TaskNode(task_id, func, args, kwargs)
        if depends_on:
            node.dependencies.extend(depends_on)
        self.tasks[task_id] = node

    def execute(self) -> Dict[str, Any]:
        """Execute tasks resolving dependencies (simple topological sort approach)."""
        results = {}
        completed = set()
        pending = set(self.tasks.keys())
        
        while pending:
            # Find tasks with all dependencies met
            ready = []
            for t_id in pending:
                if all(dep in completed for dep in self.tasks[t_id].dependencies):
                    ready.append(t_id)
            
            if not ready:
                raise RuntimeError("Circular dependency detected in scheduler.")
            
            # Execute ready tasks sequentially in the scheduler, but we could wrap 
            # independent tasks in the parallel executor. For simplicity, we just 
            # run them. In an advanced version, we would `executor.map_tasks` over ready tasks.
            
            def run_task(task_id: str):
                t = self.tasks[task_id]
                return task_id, t.func(*t.args, **t.kwargs)

            # Map the ready tasks in parallel
            batch_results = executor.map_tasks(run_task, ready)
            
            for t_id, res in batch_results:
                results[t_id] = res
                completed.add(t_id)
                pending.remove(t_id)
                
            metrics.increment("scheduler_batches_run")
            
        return results

scheduler = TaskScheduler()
