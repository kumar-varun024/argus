from dataclasses import dataclass, field


@dataclass
class AuthenticationModel:
    authentication_type: str = "Unknown"
    token_type: str = "Unknown"

    confidence: int = 0

    observations: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)

    research_questions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
