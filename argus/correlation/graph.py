import networkx as nx
import uuid
from typing import List, Dict, Any

class CorrelationGraph:
    """
    Directed graph representing relationships between Observations and Correlations.
    Observations are linked to other Observations via rules, and to Correlations when grouped.
    """
    
    def __init__(self):
        self._graph = nx.DiGraph()
        
    def add_observation(self, obs_id: uuid.UUID, **attrs):
        self._graph.add_node(str(obs_id), type="Observation", **attrs)
        
    def add_correlation(self, corr_id: uuid.UUID, **attrs):
        self._graph.add_node(str(corr_id), type="Correlation", **attrs)
        
    def link_observations(self, obs_id1: uuid.UUID, obs_id2: uuid.UUID, rule_name: str):
        """Link two observations that matched on a specific rule."""
        self._graph.add_edge(str(obs_id1), str(obs_id2), type="Matched", rule=rule_name)
        
    def link_observation_to_correlation(self, obs_id: uuid.UUID, corr_id: uuid.UUID):
        """Link an observation to its parent correlation."""
        self._graph.add_edge(str(obs_id), str(corr_id), type="PartOf")
        
    def get_correlations_for_observation(self, obs_id: uuid.UUID) -> List[str]:
        """Traverse graph to find which correlations contain this observation."""
        obs_node = str(obs_id)
        if not self._graph.has_node(obs_node):
            return []
            
        correlations = []
        for successor in self._graph.successors(obs_node):
            if self._graph.nodes[successor].get("type") == "Correlation":
                correlations.append(successor)
        return correlations

    def get_related_observations(self, obs_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Get observations directly matched with this observation."""
        obs_node = str(obs_id)
        if not self._graph.has_node(obs_node):
            return []
            
        related = []
        # Get successors
        for successor in self._graph.successors(obs_node):
            edge_data = self._graph.get_edge_data(obs_node, successor)
            if edge_data and edge_data.get("type") == "Matched":
                related.append({"id": successor, "rule": edge_data.get("rule")})
                
        # Get predecessors
        for predecessor in self._graph.predecessors(obs_node):
            edge_data = self._graph.get_edge_data(predecessor, obs_node)
            if edge_data and edge_data.get("type") == "Matched":
                related.append({"id": predecessor, "rule": edge_data.get("rule")})
                
        return related
        
    def to_dict(self) -> dict:
        return nx.node_link_data(self._graph)
