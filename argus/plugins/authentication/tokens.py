from dataclasses import dataclass
from typing import List

@dataclass
class Token:
    type: str # JWT, Opaque
    has_refresh: bool = False
    location: str = "Header"

class TokenAnalyzer:
    def analyze(self, tokens: List[str]) -> List[Token]:
        results = []
        for t in tokens:
            if t.startswith("ey"):
                results.append(Token(type="JWT"))
            else:
                results.append(Token(type="Opaque"))
        return results
