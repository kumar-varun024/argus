"""business_logic: Data models, enums, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from argus.collectors.toolkit.enums import Severity


BusinessLogicSeverity = Severity

Severity = BusinessLogicSeverity

class BusinessLogicTechnique(str, Enum):
    """Enumeration of business logic vulnerability detection techniques."""
    PRICE_TAMPERING = "price_tampering"
    WORKFLOW_STEP_SKIP = "workflow_step_skip"
    MASS_ASSIGNMENT = "mass_assignment"
    COUPON_STACKING = "coupon_stacking"
    DIFFERENTIAL_STATE_VERIFICATION = "differential_state_verification"

BusinessLogicTechnique.PRICE_QUANTITY_TAMPERING = BusinessLogicTechnique.PRICE_TAMPERING  # type: ignore[attr-defined]

BusinessLogicTechnique.STATE_TRANSITION_SKIP = BusinessLogicTechnique.WORKFLOW_STEP_SKIP  # type: ignore[attr-defined]

BusinessLogicTechnique.DIFFERENTIAL_STATE_VIOLATION = BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION  # type: ignore[attr-defined]

class BusinessLogicMutationStrategy(str, Enum):
    """Enumeration of business logic mutation and sequence manipulation strategies."""
    BOUNDARY_NEGATIVE_INJECTION = "boundary_negative_injection"
    TYPE_JUGGLING_SCHEMA_TAMPERING = "type_juggling_schema_tampering"
    OUT_OF_SEQUENCE_DISPATCH = "out_of_sequence_dispatch"
    VERB_CONTENT_TYPE_INVERSION = "verb_content_type_inversion"
    PARAMETER_POLLUTION_DUPLICATE = "parameter_pollution_duplicate"

BusinessLogicMutationStrategy.NEGATIVE_BOUNDARY_VALUE = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION  # type: ignore[attr-defined]

BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA = BusinessLogicMutationStrategy.TYPE_JUGGLING_SCHEMA_TAMPERING  # type: ignore[attr-defined]

BusinessLogicMutationStrategy.HTTP_VERB_CONTENT_TYPE = BusinessLogicMutationStrategy.VERB_CONTENT_TYPE_INVERSION  # type: ignore[attr-defined]

BusinessLogicMutationStrategy.PARAMETER_POLLUTION = BusinessLogicMutationStrategy.PARAMETER_POLLUTION_DUPLICATE  # type: ignore[attr-defined]

@dataclass
class WorkflowStep:
    """Represents a single step in a multi-step business workflow."""
    name: str
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    params: Optional[Dict[str, Any]] = None
    extract_fields: Dict[str, str] = field(default_factory=dict)
    required_state: Dict[str, str] = field(default_factory=dict)
    expected_status: int = 200

@dataclass
class WorkflowSequence:
    """Represents a multi-step workflow sequence for state transition probing."""
    name: str
    steps: List[WorkflowStep] = field(default_factory=list)
    target_step_index: int = 0
    skip_step_indices: List[int] = field(default_factory=list)
    state_baseline: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BusinessLogicProbeResponse:
    """Represents an HTTP response captured during business logic probing."""
    step_name: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Any] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    endpoint_url: str = ""
    raw_response: Optional[Any] = None

@dataclass
class BusinessLogicProbe:
    """Represents a single discrete business logic probe."""
    name: str
    endpoint_url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    params: Optional[Dict[str, Any]] = None
    technique: Union[BusinessLogicTechnique, str] = BusinessLogicTechnique.PRICE_TAMPERING
    mutation_strategy: Union[BusinessLogicMutationStrategy, str] = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION
    expected_status: int = 200
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BusinessLogicResult:
    """Represents the outcome of a business logic validation probe."""
    technique: str
    strategy: str = ""
    severity: str = "high"
    confidence: float = 0.95
    payload: Any = None
    matched_signature: str = ""
    evidence_snippet: str = ""
    endpoint_url: str = ""
    parameter: Optional[str] = None
    parameter_type: str = "business_logic_param"
    status_code: int = 200
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "business-logic"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-840"
    cvss_score: float = 8.5
    pre_state: Any = None
    post_state: Any = None
    state_delta: Any = None
    workflow_trace: List[str] = field(default_factory=list)
    mutation_strategy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.strategy and self.mutation_strategy:
            self.strategy = self.mutation_strategy
        elif not self.mutation_strategy and self.strategy:
            self.mutation_strategy = self.strategy
        elif not self.strategy and not self.mutation_strategy:
            self.strategy = BusinessLogicMutationStrategy.BOUNDARY_NEGATIVE_INJECTION.value
            self.mutation_strategy = self.strategy

        if not self.vulnerability_type:
            self.vulnerability_type = self.technique
        if not self.metadata:
            self.metadata = {
                "technique": self.technique,
                "strategy": self.strategy,
                "mutation_strategy": self.mutation_strategy,
                "matched_signature": self.matched_signature,
                "url": self.endpoint_url,
                "parameter": self.parameter,
                "cwe_id": self.cwe_id,
                "cvss_score": self.cvss_score,
            }
