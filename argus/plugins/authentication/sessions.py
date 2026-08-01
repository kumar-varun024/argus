from dataclasses import dataclass
from typing import List

@dataclass
class Session:
    mechanism: str # e.g., Cookie, JWT, Bearer
    secure_flag: bool = False
    http_only: bool = False
    name: str = ""

class SessionAnalyzer:
    def analyze(self, cookies: List[str], headers: List[str]) -> List[Session]:
        sessions = []
        for cookie in cookies:
            if "session" in cookie.lower() or "auth" in cookie.lower():
                s = Session(
                    mechanism="Cookie",
                    name=cookie.split("=")[0],
                    secure_flag="Secure" in cookie,
                    http_only="HttpOnly" in cookie
                )
                sessions.append(s)
        return sessions
