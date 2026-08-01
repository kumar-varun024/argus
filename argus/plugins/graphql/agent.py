import logging
from typing import Dict, Any, List
from argus.plugins.interfaces import ControlledMission
from argus.plugins.graphql.discovery import GraphQLDiscovery
from argus.plugins.graphql.models import Observation
from argus.graph.node import Node

logger = logging.getLogger(__name__)

class GraphQLSpecialist:
    """Specialist agent for discovering and modeling GraphQL APIs."""
    
    def __init__(self):
        self.discovery = GraphQLDiscovery()
        from argus.plugins.graphql.schema import GraphQLSchemaAnalyzer
        self.schema_analyzer = GraphQLSchemaAnalyzer()
        from argus.plugins.graphql.business import BusinessKnowledgeAnalyzer
        self.business_analyzer = BusinessKnowledgeAnalyzer()

    def discover(self, mission: ControlledMission):
        logger.info("GraphQLSpecialist: Discovering endpoints...")
        
        # Discover endpoints
        endpoints = self.discovery.discover(mission)
        
        # Ensure GraphQL state is initialized
        if not hasattr(mission, "graphql"):
            from argus.runtime.mission import GraphQLState
            mission.graphql = GraphQLState()
            
        # Deduplicate and store
        existing_urls = {ep.url for ep in mission.graphql.endpoints}
        
        for ep in endpoints:
            if ep.url not in existing_urls:
                mission.graphql.endpoints.append(ep)
                
                # Add to Knowledge Graph (if available)
                if hasattr(mission, "graph") and mission.graph:
                    node = Node(
                        id=f"graphql_endpoint_{ep.id}",
                        type="Endpoint",
                        value=ep.url,
                        metadata={
                            "method": ep.method,
                            "source": ep.source,
                            "confidence": ep.confidence,
                            "framework": ep.framework_hint
                        }
                    )
                    mission.graph.add(node)
                
                # Generate Observation
                obs_text = f"GraphQL endpoint discovered at {ep.url}"
                if ep.framework_hint:
                    obs_text += f" (Possible {ep.framework_hint} server)"
                
                obs = Observation(
                    description=obs_text,
                    confidence=ep.confidence,
                    evidence=ep.evidence
                )
                
                if not hasattr(mission, "findings"):
                    mission.findings = []
                mission.findings.append(obs)
                
                logger.info(obs_text)
            else:
                logger.debug(f"GraphQLSpecialist: Duplicate endpoint skipped {ep.url}")
                
        # 4. Schema Discovery & Inference
        self.schema_analyzer.analyze(mission)
        
        # 5. Business Logic Discovery
        self.business_analyzer.analyze(mission)

    def collect_context(self, mission: ControlledMission):
        logger.info("GraphQLSpecialist: Collecting context...")

    def analyze(self, mission: ControlledMission):
        logger.info("GraphQLSpecialist: Analyzing mission data...")

    def generate_observations(self, mission: ControlledMission):
        logger.info("GraphQLSpecialist: Generating observations...")
        # Observations are generated concurrently with discovery in discover()

    def generate_investigations(self, mission: ControlledMission):
        logger.info("GraphQLSpecialist: Generating investigations...")
        # Placeholder for PR3

    def explain(self, identifier: str) -> str:
        logger.info(f"GraphQLSpecialist: Explaining {identifier}...")
        return "Explanation placeholder."

    def confidence(self) -> float:
        logger.info("GraphQLSpecialist: Calculating confidence score...")
        return 0.0
