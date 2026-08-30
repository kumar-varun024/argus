from typing import Optional, Set
from argus.correlation.observation import Observation
from argus.graph.graph import KnowledgeGraph

def _extract_graph_nodes(obs: Observation, graph: Optional[KnowledgeGraph] = None) -> Set[str]:
    """Extract and resolve entity references from an observation to graph node IDs."""
    nodes: Set[str] = set()
    raw_values: Set[str] = set()

    for gn in (getattr(obs, 'graph_nodes', None) or []):
        if gn:
            raw_values.add(str(gn))

    for ep in (getattr(obs, 'endpoints', None) or []):
        if isinstance(ep, str):
            raw_values.add(ep)
        elif isinstance(ep, dict):
            if "url" in ep and ep["url"]:
                raw_values.add(str(ep["url"]))
            if "path" in ep and ep["path"]:
                raw_values.add(str(ep["path"]))

    for u in (getattr(obs, 'urls', None) or []):
        if u:
            raw_values.add(str(u))

    for t in (getattr(obs, 'technology', None) or []):
        if t:
            raw_values.add(str(t))

    for ev in (getattr(obs, 'evidence', None) or []):
        if hasattr(ev, 'value') and ev.value:
            raw_values.add(str(ev.value))
            cat = getattr(ev, 'category', None)
            if cat:
                raw_values.add(f"{cat}:{ev.value}")
        elif isinstance(ev, str):
            raw_values.add(ev)

    if graph is not None and hasattr(graph, 'nodes'):
        for val in raw_values:
            if val in graph.nodes:
                nodes.add(val)
            else:
                # Try canonical prefixes
                for prefix in ("target:", "subdomain:", "live_host:", "technology:", "endpoint:", "vulnerability:"):
                    prefixed = f"{prefix}{val}"
                    if prefixed in graph.nodes:
                        nodes.add(prefixed)

                # Search by node value or metadata
                for nid, n in graph.nodes.items():
                    if n.value == val or str(n.value).rstrip('/') == str(val).rstrip('/'):
                        nodes.add(nid)
                    elif str(val).startswith("http") and (n.type in ("live_host", "endpoint") and (str(n.value) in str(val) or str(val) in str(n.value))):
                        nodes.add(nid)
                    elif n.metadata and (n.metadata.get("url") == val or n.metadata.get("host") == val or n.metadata.get("hostname") == val or n.metadata.get("name") == val):
                        nodes.add(nid)
    else:
        nodes.update(raw_values)

    return nodes

def match_shared_business_objects(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.business_objects or not obs2.business_objects:
        return False
    return bool(set(obs1.business_objects) & set(obs2.business_objects))

def match_shared_workflows(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.workflows or not obs2.workflows:
        return False
    return bool(set(obs1.workflows) & set(obs2.workflows))

def match_shared_api_operations(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.api_operations or not obs2.api_operations:
        return False
    return bool(set(obs1.api_operations) & set(obs2.api_operations))

def match_shared_technologies(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.technology or not obs2.technology:
        return False
    return bool(set(obs1.technology) & set(obs2.technology))

def match_shared_authentication_context(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.authentication_context or not obs2.authentication_context:
        return False
    return bool(set(obs1.authentication_context) & set(obs2.authentication_context))

def match_shared_authorization_context(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.authorization_context or not obs2.authorization_context:
        return False
    return bool(set(obs1.authorization_context) & set(obs2.authorization_context))

def match_shared_graph_nodes(obs1: Observation, obs2: Observation, graph: Optional[KnowledgeGraph] = None) -> bool:
    gn1 = getattr(obs1, 'graph_nodes', None) or []
    gn2 = getattr(obs2, 'graph_nodes', None) or []
    if gn1 and gn2 and bool(set(gn1) & set(gn2)):
        return True

    nodes1 = _extract_graph_nodes(obs1, graph)
    nodes2 = _extract_graph_nodes(obs2, graph)
    if not nodes1 or not nodes2:
        return False

    if bool(nodes1 & nodes2):
        return True

    if graph is not None and hasattr(graph, 'nodes'):
        for n1 in nodes1:
            for n2 in nodes2:
                if n1 in graph.nodes and n2 in graph.nodes:
                    if hasattr(graph, 'in_same_host_subgraph') and graph.in_same_host_subgraph(n1, n2):
                        return True
                    if hasattr(graph, 'are_connected') and graph.are_connected(n1, n2, max_depth=2):
                        return True
    return False

def match_graph_neighborhood(obs1: Observation, obs2: Observation, graph: Optional[KnowledgeGraph] = None, max_hops: int = 2) -> bool:
    if graph is None or not hasattr(graph, 'nodes'):
        return False

    nodes1 = _extract_graph_nodes(obs1, graph)
    nodes2 = _extract_graph_nodes(obs2, graph)
    if not nodes1 or not nodes2:
        return False

    for n1 in nodes1:
        for n2 in nodes2:
            if n1 in graph.nodes and n2 in graph.nodes:
                if hasattr(graph, 'are_connected') and graph.are_connected(n1, n2, max_depth=max_hops):
                    return True
                if hasattr(graph, 'in_same_host_subgraph') and graph.in_same_host_subgraph(n1, n2):
                    return True
    return False

def match_shared_tags(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.tags or not obs2.tags:
        return False
    return bool(set(obs1.tags) & set(obs2.tags))

def match_shared_graphql_types(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.graphql_types or not obs2.graphql_types:
        return False
    return bool(set(obs1.graphql_types) & set(obs2.graphql_types))

def match_shared_endpoints(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.endpoints or not obs2.endpoints:
        return False
    return bool(set(obs1.endpoints) & set(obs2.endpoints))

def match_shared_urls(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.urls or not obs2.urls:
        return False
    return bool(set(obs1.urls) & set(obs2.urls))

def match_shared_evidence(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.evidence or not obs2.evidence:
        return False
    try:
        ev1 = set(str(e) for e in obs1.evidence)
        ev2 = set(str(e) for e in obs2.evidence)
        return bool(ev1 & ev2)
    except Exception:
        return False

# Expose a default list of rule functions
DEFAULT_RULES = [
    ("match_shared_business_objects", match_shared_business_objects),
    ("match_shared_workflows", match_shared_workflows),
    ("match_shared_api_operations", match_shared_api_operations),
    ("match_shared_technologies", match_shared_technologies),
    ("match_shared_authentication_context", match_shared_authentication_context),
    ("match_shared_authorization_context", match_shared_authorization_context),
    ("match_shared_graph_nodes", match_shared_graph_nodes),
    ("match_graph_neighborhood", match_graph_neighborhood),
    ("match_shared_tags", match_shared_tags),
    ("match_shared_graphql_types", match_shared_graphql_types),
    ("match_shared_endpoints", match_shared_endpoints),
    ("match_shared_urls", match_shared_urls),
    ("match_shared_evidence", match_shared_evidence),
]
