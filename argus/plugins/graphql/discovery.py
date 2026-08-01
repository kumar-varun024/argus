import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse

from argus.plugins.graphql.models import GraphQLEndpoint
from argus.evidence.model import Evidence

logger = logging.getLogger(__name__)

class GraphQLDiscovery:
    """Discovers GraphQL endpoints from multiple evidence sources."""

    def __init__(self):
        self.common_paths = [
            "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", 
            "/query", "/gql", "/graphql/"
        ]

    def discover(self, mission) -> List[GraphQLEndpoint]:
        logger.info("GraphQLDiscovery: Starting endpoint discovery...")
        endpoints: Dict[str, GraphQLEndpoint] = {}

        # 1. Check HTTP Endpoints
        for ep in getattr(mission, "endpoints", []):
            url = ep.get("url", "")
            if not url:
                continue

            parsed = urlparse(url)
            path = parsed.path

            is_common = any(path.endswith(p) for p in self.common_paths)
            if is_common or "graphql" in path.lower():
                self._add_or_update(
                    endpoints,
                    url=url,
                    method=ep.get("method", "POST"),
                    source="HTTP Request",
                    confidence=0.7,
                    evidence=Evidence(category="HTTP Endpoint", value=url, source="mission.endpoints")
                )

        # 2. Check API Intelligence
        for api_ep in getattr(mission, "api_intelligence", []):
            if "graphql" in str(api_ep.business_object).lower() or "graphql" in str(api_ep.path).lower():
                self._add_or_update(
                    endpoints,
                    url=api_ep.path,
                    method=api_ep.method,
                    source="API Intelligence",
                    confidence=0.8,
                    evidence=Evidence(category="API Intelligence", value=api_ep.path, source="mission.api_intelligence")
                )

        # 3. Check Evidence Store (for HTTP responses, JS, OpenAPI, Frameworks)
        if hasattr(mission, "evidence"):
            evidence_store = mission.evidence
            
            # Determine if evidence store is an iterable or has a method to get all. 
            evidence_list = []
            if hasattr(evidence_store, "get_all"):
                evidence_list = evidence_store.get_all()
            elif hasattr(evidence_store, "all"):
                evidence_list = evidence_store.all()
            elif hasattr(evidence_store, "_evidence"):
                evidence_list = evidence_store._evidence
            elif isinstance(evidence_store, list):
                evidence_list = evidence_store
            elif hasattr(evidence_store, "__iter__"):
                evidence_list = list(evidence_store)

            for ev in evidence_list:
                val_lower = str(ev.value).lower()
                source_url = ev.source if ev.source.startswith("http") or ev.source.startswith("/") else f"/{ev.source}"
                
                # Content-Type
                if "application/graphql" in val_lower:
                    self._add_or_update(
                        endpoints, url=source_url, method="POST",
                        source="HTTP Response", confidence=0.9, evidence=ev
                    )
                
                # GraphQL Payloads
                if any(k in val_lower for k in ["\"query\":", "\"mutation\":", "\"subscription\":", "operationname", "persistedquery"]):
                    confidence = 0.95 if "persistedquery" in val_lower else 0.9
                    self._add_or_update(
                        endpoints, url=source_url, method="POST",
                        source="HTTP Request", confidence=confidence, evidence=ev
                    )

                # Response payload
                if "\"data\":" in val_lower and ("__typename" in val_lower or "\"errors\":" in val_lower or "\"extensions\":" in val_lower):
                    self._add_or_update(
                        endpoints, url=source_url, method="POST",
                        source="HTTP Response", confidence=0.9, evidence=ev
                    )

                # JS Intelligence / OpenAPI (based on category/source)
                if ev.category.lower() in ["javascript", "openapi", "javascript intelligence"]:
                    if "graphql" in val_lower:
                        self._add_or_update(
                            endpoints, url=source_url, method="POST",
                            source=ev.category, confidence=0.75, evidence=ev
                        )

                # Framework fingerprints
                framework = self._guess_framework(val_lower)
                if framework:
                    self._add_or_update(
                        endpoints, url=source_url, method="POST",
                        source="Framework Fingerprint", confidence=0.85, 
                        evidence=ev, framework_hint=framework
                    )

        # Deduplicate and finalize
        for ep in endpoints.values():
            # Boost confidence for multiple evidence sources
            if len(ep.evidence) > 1:
                ep.confidence = min(1.0, ep.confidence + (len(ep.evidence) * 0.05))
            
            # Normalize method flags
            if ep.method.upper() == "GET":
                ep.supports_get = True
            elif ep.method.upper() == "POST":
                ep.supports_post = True

        discovered = list(endpoints.values())
        logger.info(f"GraphQLDiscovery: Discovered {len(discovered)} endpoints.")
        return discovered

    def _add_or_update(self, endpoints: Dict[str, GraphQLEndpoint], url: str, method: str, source: str, confidence: float, evidence: Evidence, framework_hint: Optional[str] = None):
        if url not in endpoints:
            endpoints[url] = GraphQLEndpoint(
                url=url,
                method=method,
                source=source,
                confidence=confidence,
                evidence=[evidence]
            )
            if framework_hint:
                endpoints[url].framework_hint = framework_hint
        else:
            ep = endpoints[url]
            # Avoid duplicate evidence
            if not any(e.value == evidence.value for e in ep.evidence):
                ep.evidence.append(evidence)
                
            if confidence > ep.confidence:
                ep.confidence = confidence
                ep.source = source
                
            if framework_hint and not ep.framework_hint:
                ep.framework_hint = framework_hint
            
            if method.upper() == "GET":
                ep.supports_get = True
            if method.upper() == "POST":
                ep.supports_post = True

    def _guess_framework(self, text: str) -> Optional[str]:
        frameworks = {
            "apollo": "Apollo",
            "relay": "Relay",
            "hasura": "Hasura",
            "graphene": "Graphene",
            "graphql-yoga": "Yoga",
            "mercurius": "Mercurius",
            "hot chocolate": "Hot Chocolate",
            "strawberry": "Strawberry"
        }
        for k, v in frameworks.items():
            if k in text:
                return v
        return None
