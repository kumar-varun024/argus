from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


@dataclass
class Mission:
    target: str

    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)

    status: str = "created"
    phase: str = "planning"

    def start(self):
        self.status = "running"

    def finish(self):
        self.status = "completed"
