from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from argus.evidence import EvidenceStore
from argus.facts import FactStore


@dataclass
class Mission:

    target: str

    id: str = field(default_factory=lambda: str(uuid4()))

    status: str = "created"

    phase: str = "planning"

    scope: list[str] = field(default_factory=list)

    subdomains: list[str] = field(default_factory=list)

    live_hosts: list[dict] = field(default_factory=list)

    technologies: list[str] = field(default_factory=list)

    endpoints: list[dict] = field(default_factory=list)

    parameters: list[str] = field(default_factory=list)

    javascript: list[dict] = field(default_factory=list)

    apis: list[str] = field(default_factory=list)

    cookies: list[str] = field(default_factory=list)

    tokens: list[str] = field(default_factory=list)

    findings: list[dict] = field(default_factory=list)

    evidence: EvidenceStore = field(default_factory=EvidenceStore)

    facts: FactStore = field(default_factory=FactStore)

    reports: list[str] = field(default_factory=list)

    notes: list[str] = field(default_factory=list)

    hypotheses: list = field(default_factory=list)

    def start(self):

        self.status = "running"

        self.phase = "recon"

    def finish(self):

        self.status = "completed"

        self.phase = "finished"
