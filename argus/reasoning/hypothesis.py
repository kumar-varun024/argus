from dataclasses import dataclass, field


@dataclass(slots=True)
class Hypothesis:

    title: str

    description: str

    confidence: float

    severity: str

    evidence: list[str] = field(default_factory=list)

    reasoning: list[str] = field(default_factory=list)

    next_actions: list[str] = field(default_factory=list)

    mitre: list[str] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)
