from enum import Enum

class ExecutionStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    BLOCKED = "Blocked"
