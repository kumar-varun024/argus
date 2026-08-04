import pytest
import uuid
from argus.correlation.graph import CorrelationGraph

def test_correlation_graph():
    graph = CorrelationGraph()
    obs1_id = uuid.uuid4()
    obs2_id = uuid.uuid4()
    corr_id = uuid.uuid4()
    
    graph.add_observation(obs1_id)
    graph.add_observation(obs2_id)
    graph.add_correlation(corr_id)
    
    graph.link_observations(obs1_id, obs2_id, "shared_bo")
    graph.link_observation_to_correlation(obs1_id, corr_id)
    graph.link_observation_to_correlation(obs2_id, corr_id)
    
    related = graph.get_related_observations(obs1_id)
    assert len(related) == 1
    assert related[0]["id"] == str(obs2_id)
    assert related[0]["rule"] == "shared_bo"
    
    corrs = graph.get_correlations_for_observation(obs1_id)
    assert len(corrs) == 1
    assert corrs[0] == str(corr_id)
