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

        auth = mission.authentication

        text = []

        text.extend(mission.apis)

        for js in mission.javascript:
            text.append(js["url"])

        for endpoint in mission.endpoints:
            text.append(endpoint["url"])

        corpus = "\n".join(text).lower()

        jwt_found = self._contains(corpus, self.JWT_PATTERNS)
        oauth_found = self._contains(corpus, self.OAUTH_PATTERNS)
        cookie_found = self._contains(corpus, self.COOKIE_PATTERNS)

        if jwt_found:
            auth.token_type = "Bearer JWT"
            auth.observations.append("JWT indicators detected")

            mission.evidence.add(
                Evidence(
                    category="authentication",
                    value="JWT",
                    source="AuthenticationAnalyzer",
                )
            )

        if oauth_found:
            auth.authentication_type = "OAuth2"
            auth.observations.append("OAuth endpoints detected")

            mission.evidence.add(
                Evidence(
                    category="authentication",
                    value="OAuth2",
                    source="AuthenticationAnalyzer",
                )
            )

        if cookie_found:
            auth.observations.append("Session or security cookie indicators detected")

            mission.evidence.add(
                Evidence(
                    category="authentication",
                    value="Session Cookies",
                    source="AuthenticationAnalyzer",
                )
            )

        confidence = 0

        if oauth_found:
            confidence += 40

        if jwt_found:
            confidence += 40

        if cookie_found:
            confidence += 20

        auth.confidence = confidence

        if oauth_found and jwt_found:

            auth.reasoning.append(
                "OAuth-related endpoints together with JWT indicators "
                "suggest centralized bearer-token authentication."
            )

        elif jwt_found:

            auth.reasoning.append("JWT indicators suggest token-based authentication.")

        elif cookie_found:

            auth.reasoning.append("Session cookies indicate stateful authentication.")

        auth.research_questions = [
            "Is authorization enforced consistently across all authenticated endpoints?",
            "Does logout immediately invalidate the session or token?",
            "Are refresh tokens rotated after use?",
            "Are administrative endpoints protected differently?",
            "Can one user's identifiers be substituted with another user's identifiers?",
        ]

        auth.missing_evidence = [
            "Capture login request",
            "Capture logout request",
            "Observe token storage",
            "Capture refresh token flow",
            "Inspect cookie attributes",
        ]

    def _contains(self, corpus, patterns):

        for pattern in patterns:

            if re.search(pattern.lower(), corpus):
                return True

        return False
