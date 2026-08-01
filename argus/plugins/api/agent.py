import logging
import hashlib
from typing import Dict, Any
from argus.plugins.interfaces import ControlledMission
from argus.plugins.api.schemas import SchemaParser
from argus.plugins.api.relationships import RelationshipInferencer
from argus.plugins.api.operations import OperationAnalyzer
from argus.plugins.api.versions import VersionDetector
from argus.plugins.api.heuristics import API_HEURISTIC_REGISTRY
from argus.plugins.api.confidence import APIConfidenceScorer

logger = logging.getLogger(__name__)

class APIIntelligenceSpecialist:
    """Specialist agent for identifying API resources and relationships."""
    
    def __init__(self):
        self.schema_parser = SchemaParser()
        self.relationship_inferencer = RelationshipInferencer()
        self.operation_analyzer = OperationAnalyzer()
        self.version_detector = VersionDetector()
        self.heuristics = API_HEURISTIC_REGISTRY
        self.scorer = APIConfidenceScorer()
        
    def analyze(self, mission: ControlledMission):
        logger.info(f"API Intelligence Specialist starting analysis for Mission {mission.target}")
        
        # Read raw endpoints
        endpoints = mission._mission.endpoints if hasattr(mission._mission, 'endpoints') else []
        
        # Extract schema and build model
        resources = self.schema_parser.parse_endpoints(endpoints)
        relationships = self.relationship_inferencer.infer(list(resources.values()))
        operations = self.operation_analyzer.extract_operations(endpoints, resources)
        versions = self.version_detector.detect_versions(list(resources.values()))
        
        context = {
            "resources": resources,
            "relationships": relationships,
            "operations": operations,
            "versions": versions
        }
        
        investigations = []
        
        for heuristic in self.heuristics:
            logger.info(f"Running heuristic {heuristic.__class__.__name__}")
            results = heuristic.run(context)
            
            for inv in results:
                inv.confidence = self.scorer.score(inv, context)
                
                if inv.confidence > 80:
                    inv.priority = "High"
                elif inv.confidence > 50:
                    inv.priority = "Medium"
                else:
                    inv.priority = "Low"
                    
                investigations.append(inv)
                
        # Deduplicate
        seen_hashes = set()
        deduped = []
        for inv in investigations:
            hash_str = f"{inv.title}|{inv.category}|{','.join(sorted(inv.affected_objects))}"
            inv_hash = hashlib.sha256(hash_str.encode()).hexdigest()
            if inv_hash not in seen_hashes:
                seen_hashes.add(inv_hash)
                deduped.append(inv)
                
        # Store back into mission safely
        mission._mission.api_inventory.extend(deduped)
        mission._mission.resources.update(resources)
        mission._mission.operations.extend(operations)
        mission._mission.relationships.extend(relationships)
        
        logger.info(f"API Intelligence Specialist finished. Generated {len(deduped)} investigations.")
