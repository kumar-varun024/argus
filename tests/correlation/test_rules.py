import pytest
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.rules import (
    match_shared_business_objects,
    match_shared_workflows,
    match_shared_api_operations,
    match_shared_technologies,
    match_shared_authentication_context,
    match_shared_authorization_context,
    match_shared_graph_nodes,
    match_shared_tags,
    match_shared_graphql_types,
    match_shared_endpoints,
    match_shared_urls,
    match_shared_evidence
)

def create_obs(**kwargs) -> Observation:
    defaults = {
        "source": "test",
        "category": ObservationCategory.API,
        "title": "test",
        "description": "test",
        "confidence": 1.0,
        "priority": ObservationPriority.LOW
    }
    defaults.update(kwargs)
    return Observation(**defaults)

def test_match_shared_business_objects():
    obs1 = create_obs(business_objects=["User", "Org"])
    obs2 = create_obs(business_objects=["Org", "Team"])
    obs3 = create_obs(business_objects=["Project"])
    
    assert match_shared_business_objects(obs1, obs2) is True
    assert match_shared_business_objects(obs1, obs3) is False
    assert match_shared_business_objects(obs1, create_obs()) is False

def test_match_shared_tags():
    obs1 = create_obs(tags=["vuln:sqli", "high_risk"])
    obs2 = create_obs(tags=["vuln:sqli"])
    assert match_shared_tags(obs1, obs2) is True
    assert match_shared_tags(obs1, create_obs(tags=["other"])) is False

def test_match_shared_graphql_types():
    obs1 = create_obs(graphql_types=["UserType"])
    obs2 = create_obs(graphql_types=["UserType", "OrgType"])
    assert match_shared_graphql_types(obs1, obs2) is True
    assert match_shared_graphql_types(obs1, create_obs(graphql_types=["OtherType"])) is False

def test_match_shared_endpoints():
    obs1 = create_obs(endpoints=["/api/v1/users"])
    obs2 = create_obs(endpoints=["/api/v1/users"])
    assert match_shared_endpoints(obs1, obs2) is True
    assert match_shared_endpoints(obs1, create_obs(endpoints=["/api/v1/orgs"])) is False

def test_match_shared_urls():
    obs1 = create_obs(urls=["https://example.com/login"])
    obs2 = create_obs(urls=["https://example.com/login"])
    assert match_shared_urls(obs1, obs2) is True
    assert match_shared_urls(obs1, create_obs(urls=["https://example.com/logout"])) is False

def test_match_shared_evidence():
    obs1 = create_obs(evidence=["test_token"])
    obs2 = create_obs(evidence=["test_token", "other_token"])
    assert match_shared_evidence(obs1, obs2) is True
    assert match_shared_evidence(obs1, create_obs(evidence=["different"])) is False
