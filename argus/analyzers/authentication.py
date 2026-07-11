import re

from argus.evidence import Evidence


class AuthenticationAnalyzer:

    JWT_PATTERNS = [
        r"Bearer",
        r"access_token",
        r"refresh_token",
        r"id_token",
        r"jsonwebtoken",
        r"jwt",
    ]

    OAUTH_PATTERNS = [
        r"/oauth",
        r"/authorize",
        r"/token",
        r"/callback",
        r"/openid",
    ]

    COOKIE_PATTERNS = [
        r"Set-Cookie",
        r"HttpOnly",
        r"SameSite",
        r"Secure",
        r"X-CSRF",
        r"csrf",
    ]

    def analyze(self, mission):

        print("\nAuthentication Intelligence...")

        text = []

        for api in mission.apis:
            text.append(api)

        for js in mission.javascript:
            text.append(js["url"])

        for endpoint in mission.endpoints:
            text.append(endpoint["url"])

        corpus = "\n".join(text)

        discovered = set()

        self._match_patterns(
            corpus,
            self.JWT_PATTERNS,
            "jwt",
            discovered,
            mission,
        )

        self._match_patterns(
            corpus,
            self.OAUTH_PATTERNS,
            "oauth",
            discovered,
            mission,
        )

        self._match_patterns(
            corpus,
            self.COOKIE_PATTERNS,
            "session",
            discovered,
            mission,
        )

        print(f"✓ Authentication Indicators: {len(discovered)}")

    def _match_patterns(
        self,
        corpus,
        patterns,
        category,
        discovered,
        mission,
    ):

        corpus = corpus.lower()

        for pattern in patterns:

            if re.search(pattern.lower(), corpus):

                if pattern in discovered:
                    continue

                discovered.add(pattern)

                mission.evidence.add(
                    Evidence(
                        category=category,
                        value=pattern,
                        source="authentication",
                    )
                )
