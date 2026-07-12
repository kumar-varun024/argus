import re
from dataclasses import dataclass, field


@dataclass
class JavaScriptAnalysisResult:

    apis: list[str] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    jwt: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


class JavaScriptAnalyzer:

    API_PATTERNS = [
        re.compile(r'["\'](/api[^"\']*)["\']'),
        re.compile(r'["\']https?://[^"\']+/api[^"\']*["\']'),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']'),
    ]

    ROUTE_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-/]{2,})["\']')

    GRAPHQL_PATTERNS = [
        re.compile(r"graphql", re.I),
        re.compile(r"__typename"),
        re.compile(r"\bquery\b"),
        re.compile(r"\bmutation\b"),
        re.compile(r"\bsubscription\b"),
        re.compile(r"Apollo", re.I),
        re.compile(r"Relay", re.I),
        re.compile(r"urql", re.I),
    ]

    WEBSOCKET_PATTERN = re.compile(r'wss?://[^"\']+')

    SOURCE_MAP_PATTERN = re.compile(r"//# sourceMappingURL=(.+)")

    JWT_PATTERNS = [
        re.compile(r"Bearer"),
        re.compile(r"access_token"),
        re.compile(r"refresh_token"),
        re.compile(r"Authorization"),
    ]

    SECRET_PATTERNS = [
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        re.compile(r"sk_live_[0-9A-Za-z]+"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ]

    def analyze(self, javascript: str):

        result = JavaScriptAnalysisResult()

        for pattern in self.API_PATTERNS:
            result.apis.extend(pattern.findall(javascript))

        result.routes.extend(self.ROUTE_PATTERN.findall(javascript))

        result.websockets.extend(self.WEBSOCKET_PATTERN.findall(javascript))

        result.source_maps.extend(self.SOURCE_MAP_PATTERN.findall(javascript))

        for pattern in self.GRAPHQL_PATTERNS:
            if pattern.search(javascript):
                result.graphql.append(pattern.pattern)

        for pattern in self.JWT_PATTERNS:
            if pattern.search(javascript):
                result.jwt.append(pattern.pattern)

        for pattern in self.SECRET_PATTERNS:
            result.secrets.extend(pattern.findall(javascript))

        result.apis = sorted(set(result.apis))
        result.routes = sorted(set(result.routes))
        result.websockets = sorted(set(result.websockets))
        result.source_maps = sorted(set(result.source_maps))
        result.graphql = sorted(set(result.graphql))
        result.jwt = sorted(set(result.jwt))
        result.secrets = sorted(set(result.secrets))

        return result
