from dataclasses import dataclass


@dataclass(slots=True)
class Evidence:

    category: str

    value: str

    source: str

    confidence: float = 1.0

    severity: str = "info"

    description: str = ""
