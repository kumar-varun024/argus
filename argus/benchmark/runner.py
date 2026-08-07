import time
import logging
from typing import Set, List
from argus.runtime.mission import Mission, MissionState
from argus.runtime.controller import MissionController
from argus.runtime.checkpoint import MissionCheckpointer
from argus.benchmark.models import Benchmark, BenchmarkResult, BenchmarkMetrics
from argus.benchmark.mission_loader import MissionLoader
from argus.benchmark.dataset_loader import DatasetLoader

logger = logging.getLogger(__name__)

class BenchmarkRunner:
    """Executes a benchmark and evaluates the results against ground truth."""
    
    def __init__(self):
        self.checkpointer = MissionCheckpointer()
        self.controller = MissionController(self.checkpointer)
        
    def _calculate_recall(self, expected: List[str], actual: List[str]) -> float:
        """Calculates recall: (true positives) / (true positives + false negatives)"""
        if not expected:
            return 1.0 # If nothing was expected, we achieve perfect recall
            
        expected_set = set(expected)
        actual_set = set(actual)
        
        # Simple string matching for now. Future extensions can use semantic similarity.
        matched = expected_set.intersection(actual_set)
        return len(matched) / len(expected_set)

    def run(self, benchmark: Benchmark) -> BenchmarkResult:
        """Runs the benchmark mission and collects metrics."""
        logger.info(f"Preparing to run benchmark: {benchmark.id}")
        
        # 1. Setup environment
        mission = MissionLoader.load_mission(benchmark)
        DatasetLoader.load_dataset(benchmark, mission)
        
        # 2. Execute
        start_time = time.time()
        self.controller.start(mission)
        
        # Wait for completion (Timeout or Terminal State)
        timeout = 60 # 60 seconds timeout for test benchmarks
        start_wait = time.time()
        
        while mission.status not in (MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED, MissionState.WAITING_FOR_APPROVAL):
            if time.time() - start_wait > timeout:
                self.controller.cancel(mission)
                logger.error(f"Benchmark {benchmark.id} timed out.")
                break
            time.sleep(1)
            
        execution_time_ms = (time.time() - start_time) * 1000
        
        # 3. Ground Truth Evaluation
        from argus.benchmark.ground_truth.engine import GroundTruthEngine
        
        gt_engine = GroundTruthEngine()
        # If there's a loaded ground truth dataset matching the benchmark
        # Ensure it's passed or loaded into the engine's registry.
        # For simplicity, we create a temporary GroundTruth if the engine registry is empty 
        # or rely on the engine's fallback logic if we register it here.
        # Actually, let's just convert the Benchmark's basic ground_truth to a full GroundTruth object
        from argus.benchmark.ground_truth.models import GroundTruth
        
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
        
        mission.dataset_id = benchmark.id # tag the mission
        comparison_result = gt_engine.evaluate(mission)
        
        actual_business_objects = [bo.get('name') if isinstance(bo, dict) else str(bo) for bo in getattr(mission, "business_objects", [])]
        actual_correlations = [corr.title for corr in mission.correlations.get_all()] if hasattr(mission, "correlations") and hasattr(mission.correlations, "get_all") else []
        actual_evidence = [bundle.title for bundle in mission.evidence_bundles.get_all()] if hasattr(mission, "evidence_bundles") and hasattr(mission.evidence_bundles, "get_all") else []
        actual_observations = [obs.title for obs in mission.observations.get_all()] if hasattr(mission, "observations") and hasattr(mission.observations, "get_all") else []

        metrics = BenchmarkMetrics(
            total_execution_time_ms=execution_time_ms,
            technology_recall=self._calculate_recall(benchmark.ground_truth.expected_technologies, getattr(mission, "technologies", [])),
            business_object_recall=self._calculate_recall(benchmark.ground_truth.expected_business_objects, actual_business_objects),
            correlation_recall=self._calculate_recall(benchmark.ground_truth.expected_correlations, actual_correlations),
            evidence_recall=self._calculate_recall(benchmark.ground_truth.expected_evidence, actual_evidence),
            investigation_recall=self._calculate_recall(benchmark.ground_truth.expected_investigations, actual_observations),
            hypothesis_recall=self._calculate_recall(benchmark.ground_truth.expected_hypotheses, actual_observations)
        )
        
        result = BenchmarkResult(
            benchmark_id=benchmark.id,
            mission_id=mission.id,
            metrics=metrics,
            runtime_history=getattr(mission, "state_transitions", []),
            raw_outputs={
                "status": mission.status.value
            },
            ground_truth_comparison=comparison_result
        )
        
        logger.info(f"Benchmark {benchmark.id} finished with status {mission.status.value}.")
        return result
