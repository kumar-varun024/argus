from typing import List

class MFAAnalyzer:
    def analyze(self, endpoints: List[dict]) -> bool:
        for ep in endpoints:
            path = ep.get("path", "").lower()
            if "mfa" in path or "2fa" in path or "otp" in path or "totp" in path:
                return True
        return False
