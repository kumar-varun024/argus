"""Mission state enum and per-domain sub-state dataclasses.

Extracted from :mod:`argus.runtime.mission` so the mission model file stays
within the size limit. These are pure, dependency-light value types (stdlib
only), so importing this module can never cause an import cycle with the wider
runtime. ``argus.runtime.mission`` re-imports every name defined here, so the
historical ``from argus.runtime.mission import MissionState, GraphQLState,
JavaScriptState`` paths keep working unchanged.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MissionState(str, Enum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    PLANNING = "PLANNING"
    RESEARCHING = "RESEARCHING"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CORRELATING = "CORRELATING"
    BUILDING_INVESTIGATIONS = "BUILDING_INVESTIGATIONS"
    GENERATING_HYPOTHESES = "GENERATING_HYPOTHESES"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


@dataclass
class GraphQLState:
    endpoints: list = field(default_factory=list)
    schemas: list = field(default_factory=list)
    types: dict = field(default_factory=dict)
    operations: list = field(default_factory=list)
    enums: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)
    unions: list = field(default_factory=list)
    relationships: list = field(default_factory=list)
    workflows: list = field(default_factory=list)
    business_objects: list = field(default_factory=list)
    crud: list = field(default_factory=list)
    relationship_graph: Any = None
    investigations: list = field(default_factory=list)
    priority_queue: list = field(default_factory=list)
    reasoning: list = field(default_factory=list)


@dataclass
class JavaScriptState:
    files: list = field(default_factory=list)
    manifests: list = field(default_factory=list)
    sourcemaps: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    investigations: list = field(default_factory=list)
    ast: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    websocket: list = field(default_factory=list)
    processed_hashes: set = field(default_factory=set)
