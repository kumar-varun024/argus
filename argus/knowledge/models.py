from dataclasses import dataclass, field


@dataclass(slots=True)
class KnowledgeRule:

    name: str

    requires: list[str]

    hypothesis: str

    description: str

    severity: str

    investigation: list[str] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)
