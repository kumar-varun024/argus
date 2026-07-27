from dataclasses import dataclass, field


@dataclass(slots=True)
class APIEndpoint:

    method: str

    path: str

    resource: str

    operation: str

    object_identifier: bool = False

    business_object: str = ""

    risk_score: int = 0

    priority: str = "LOW"

    confidence: float = 0.0

    tags: list[str] = field(default_factory=list)

    evidence: list[str] = field(default_factory=list)

    reasoning: list[str] = field(default_factory=list)

    manual_checks: list[str] = field(default_factory=list)
