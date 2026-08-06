from argus.explain.models import ExplanationGraph, GraphNode, GraphEdge
from argus.investigation.models import Investigation
from argus.runtime.mission import Mission

class ExplanationGraphBuilder:
    """Builds a graph representing the provenance of an investigation."""
    
    def __init__(self, mission: Mission):
        self.mission = mission

    def build_graph(self, investigation: Investigation) -> ExplanationGraph:
        graph = ExplanationGraph()
        
        # Add Investigation Node
        inv_node = GraphNode(
            id=str(investigation.id),
            label=f"Investigation: {investigation.title}",
            node_type="Investigation",
            properties={"priority": investigation.priority, "confidence": investigation.confidence}
        )
        graph.nodes.append(inv_node)
        
        # Add Business Objects
        for bo in investigation.business_objects:
            bo_node = GraphNode(
                id=f"bo_{bo}",
                label=f"Business Object: {bo}",
                node_type="BusinessObject"
            )
            graph.nodes.append(bo_node)
            graph.edges.append(GraphEdge(source=str(investigation.id), target=bo_node.id, relationship="INVOLVES"))
        
        # Add Workflows
        for wf in investigation.workflows:
            wf_node = GraphNode(
                id=f"wf_{wf}",
                label=f"Workflow: {wf}",
                node_type="Workflow"
            )
            graph.nodes.append(wf_node)
            graph.edges.append(GraphEdge(source=str(investigation.id), target=wf_node.id, relationship="INVOLVES"))

        seen_corrs = set()
        seen_obs = set()
        
        # Helper to safely add node
        def _add_node_if_missing(node: GraphNode):
            if not any(n.id == node.id for n in graph.nodes):
                graph.nodes.append(node)
                
        # Helper to safely add edge
        def _add_edge_if_missing(edge: GraphEdge):
            if not any(e.source == edge.source and e.target == edge.target and e.relationship == edge.relationship for e in graph.edges):
                graph.edges.append(edge)

        # Add Evidence Bundles
        for bundle_id in investigation.evidence_bundles:
            bundle = self.mission.evidence_bundles.find(bundle_id)
            if not bundle:
                continue
                
            bundle_node = GraphNode(
                id=str(bundle.id),
                label=f"Evidence Bundle: {bundle.title}",
                node_type="EvidenceBundle",
                properties={"strength": bundle.strength}
            )
            _add_node_if_missing(bundle_node)
            _add_edge_if_missing(GraphEdge(source=str(bundle.id), target=str(investigation.id), relationship="SUPPORTS"))
            
            # Add Correlations
            for corr_id in bundle.correlations:
                if corr_id not in seen_corrs:
                    seen_corrs.add(corr_id)
                    corr = self.mission.correlations.find(corr_id)
                    if corr:
                        corr_node = GraphNode(
                            id=str(corr.id),
                            label=f"Correlation",
                            node_type="Correlation"
                        )
                        _add_node_if_missing(corr_node)
                        _add_edge_if_missing(GraphEdge(source=str(corr.id), target=str(bundle.id), relationship="PART_OF"))
                        
                        # Tie obs to corr
                        for obs_id in corr.observations:
                            if obs_id not in seen_obs:
                                seen_obs.add(obs_id)
                                obs = self.mission.observations.find(obs_id)
                                if obs:
                                    obs_node = GraphNode(
                                        id=str(obs.id),
                                        label=f"Observation: {obs.title}",
                                        node_type="Observation",
                                        properties={"source": obs.source}
                                    )
                                    _add_node_if_missing(obs_node)
                                    
                            _add_edge_if_missing(GraphEdge(source=str(obs_id), target=str(corr.id), relationship="SUPPORTS"))

            # Add Observations directly to bundle if any
            for obs_id in bundle.observations:
                if obs_id not in seen_obs:
                    seen_obs.add(obs_id)
                    obs = self.mission.observations.find(obs_id)
                    if obs:
                        obs_node = GraphNode(
                            id=str(obs.id),
                            label=f"Observation: {obs.title}",
                            node_type="Observation",
                            properties={"source": obs.source}
                        )
                        _add_node_if_missing(obs_node)
                        
                _add_edge_if_missing(GraphEdge(source=str(obs_id), target=str(bundle.id), relationship="PART_OF"))

        return graph
