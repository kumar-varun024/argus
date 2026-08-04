from argus.correlation.observation import Observation

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

def match_shared_graph_nodes(obs1: Observation, obs2: Observation) -> bool:
    if not obs1.graph_nodes or not obs2.graph_nodes:
        return False
    return bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))

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
    ("match_shared_tags", match_shared_tags),
    ("match_shared_graphql_types", match_shared_graphql_types),
    ("match_shared_endpoints", match_shared_endpoints),
    ("match_shared_urls", match_shared_urls),
    ("match_shared_evidence", match_shared_evidence),
]
