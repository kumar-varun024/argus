import pytest
from argus.plugins.graphql.agent import GraphQLSpecialist

def test_graphql_specialist_initialization():
    specialist = GraphQLSpecialist()
    assert specialist is not None

def test_graphql_specialist_discover():
    specialist = GraphQLSpecialist()
    from argus.runtime.mission import Mission
    mission = Mission(target="test")
    specialist.discover(mission)
    assert True
