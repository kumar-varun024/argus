import logging
from argus.runtime.mission import Mission
from argus.benchmark.models import Benchmark
from argus.benchmark.ground_truth.engine import GroundTruthEngine
from argus.benchmark.ground_truth.models import GroundTruth, ComparisonResult

logger = logging.getLogger(__name__)

class ComparisonRunner:
    """Wraps the GroundTruthEngine for the Evaluation Pipeline."""
    
    @classmethod
    def compare(cls, benchmark: Benchmark, mission: Mission) -> ComparisonResult:
        logger.info(f"Comparing mission {mission.id} against ground truth for {benchmark.id}")
        gt_engine = GroundTruthEngine()
        
        # Convert BenchmarkGroundTruth to the full GroundTruth representation
        full_gt = GroundTruth(
            id=benchmark.id,
            dataset=benchmark.id,
            version="1.0",
            expected_technologies=benchmark.ground_truth.expected_technologies,
            expected_business_objects=benchmark.ground_truth.expected_business_objects,
            expected_workflows=benchmark.ground_truth.expected_workflows,
            expected_investigation_areas=benchmark.ground_truth.expected_investigation_areas,
            expected_endpoints=benchmark.ground_truth.expected_routes + benchmark.ground_truth.expected_api_endpoints,
            expected_graphql_types=benchmark.ground_truth.expected_graphql_types,
            expected_observations=benchmark.ground_truth.expected_investigations + benchmark.ground_truth.expected_hypotheses,
            expected_correlations=benchmark.ground_truth.expected_correlations,
            expected_evidence_bundles=benchmark.ground_truth.expected_evidence
        )
        gt_engine.registry.register(full_gt)
        
        mission.dataset_id = benchmark.id
        return gt_engine.evaluate(mission)
