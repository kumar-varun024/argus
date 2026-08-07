from typing import List, Dict
from argus.benchmark.ground_truth.models import GroundTruth, ComparisonResult, MatchStatus
from argus.benchmark.ground_truth.matcher import GroundTruthMatcher
from argus.runtime.mission import Mission

class GroundTruthComparer:
    """Orchestrates matching across all domains between Ground Truth and Mission output."""
    
    @staticmethod
    def compare(gt: GroundTruth, mission: Mission) -> ComparisonResult:
        result = ComparisonResult(
            dataset_id=gt.dataset,
            mission_id=mission.id
        )
        
        # We extract actual string representations from the mission
        actuals = {
            "technologies": mission.technologies,
            "frameworks": getattr(mission, "frameworks", []),
            "endpoints": getattr(mission, "endpoints", []),
            "graphql_types": getattr(mission, "graphql_types", []),
            "business_objects": [bo.get('name') if isinstance(bo, dict) else str(bo) for bo in mission.business_objects],
            "relationships": getattr(mission, "relationships", []),
            "workflows": getattr(mission, "workflows", []),
            "authentication_flows": getattr(mission, "authentication_flows", []),
            "authorization_boundaries": getattr(mission, "authorization_boundaries", []),
            "investigation_areas": getattr(mission, "investigation_areas", []),
            "observations": [obs.title for obs in mission.observations.get_all()] if hasattr(mission.observations, "get_all") else [],
            "correlations": [corr.title for corr in mission.correlations.get_all()] if hasattr(mission.correlations, "get_all") else [],
            "evidence_bundles": [bundle.title for bundle in mission.evidence_bundles.get_all()] if hasattr(mission.evidence_bundles, "get_all") else []
        }
        
        categories = {
            "Technologies": (gt.expected_technologies, actuals["technologies"]),
            "Frameworks": (gt.expected_frameworks, actuals["frameworks"]),
            "Endpoints": (gt.expected_endpoints, actuals["endpoints"]),
            "GraphQL Types": (gt.expected_graphql_types, actuals["graphql_types"]),
            "Business Objects": (gt.expected_business_objects, actuals["business_objects"]),
            "Relationships": (gt.expected_relationships, actuals["relationships"]),
            "Workflows": (gt.expected_workflows, actuals["workflows"]),
            "Authentication Flows": (gt.expected_authentication_flows, actuals["authentication_flows"]),
            "Authorization Boundaries": (gt.expected_authorization_boundaries, actuals["authorization_boundaries"]),
            "Investigation Areas": (gt.expected_investigation_areas, actuals["investigation_areas"]),
            "Observations": (gt.expected_observations, actuals["observations"]),
            "Correlations": (gt.expected_correlations, actuals["correlations"]),
            "Evidence Bundles": (gt.expected_evidence_bundles, actuals["evidence_bundles"])
        }
        
        for cat_name, (expected_list, actual_list) in categories.items():
            result.total_expected += len(expected_list)
            
            # Match expectations
            for exp in expected_list:
                match = GroundTruthMatcher.match_item(cat_name, exp, actual_list)
                if match.status == MatchStatus.MATCHED:
                    result.matches.append(match)
                    result.total_matched += 1
                elif match.status == MatchStatus.PARTIALLY_MATCHED:
                    result.matches.append(match)
                    result.total_partially_matched += 1
                else:
                    result.misses.append(match)
                    
            # Identify unexpected findings
            unexpected = GroundTruthMatcher.identify_unexpected(cat_name, expected_list, actual_list)
            result.unexpected_findings.extend(unexpected)
            
        return result
