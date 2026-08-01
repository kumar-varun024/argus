from typing import List

class OAuthAnalyzer:
    def analyze(self, endpoints: List[dict]) -> bool:
        for ep in endpoints:
            path = ep.get("path", "").lower()
            if "oauth" in path or "authorize" in path or "callback" in path:
                return True
        return False
