from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Identity:
    name: str
    roles: List[str] = field(default_factory=list)
    provider: str = "Local"

class IdentityAnalyzer:
    def extract_identities(self, evidence: List[dict]) -> List[Identity]:
        identities = []
        for ev in evidence:
            if ev.get("type") == "identity":
                identities.append(Identity(name=ev.get("name", "Unknown")))
        return identities
