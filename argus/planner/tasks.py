from dataclasses import dataclass


@dataclass
class Task:
    name: str
    description: str
    enabled: bool = True
    completed: bool = False
