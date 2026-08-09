import time
import uuid
import logging
from typing import Optional

from argus.benchmark.models import Benchmark
from argus.runtime.mission import Mission, MissionState
from argus.runtime.controller import MissionController
from argus.runtime.checkpoint import MissionCheckpointer
from argus.benchmark.mission_loader import MissionLoader
from argus.benchmark.dataset_loader import DatasetLoader
from argus.benchmark.runner.artifacts import ArtifactCollector
from argus.benchmark.runner.comparison import ComparisonRunner
from argus.benchmark.metrics.engine import MetricsEngine
from argus.benchmark.runner.models import EvaluationResult

logger = logging.getLogger(__name__)

class EvaluationPipeline:
    """End-to-end evaluation pipeline for a benchmark."""
    
    def __init__(self):
        self.checkpointer = MissionCheckpointer()
        self.controller = MissionController(self.checkpointer)
        self.metrics_engine = MetricsEngine()

    def run(self, benchmark: Benchmark, dry_run: bool = False) -> EvaluationResult:
        logger.info(f"Starting Evaluation Pipeline for benchmark {benchmark.id}")
        
        # 1. Loading
        mission = MissionLoader.load_mission(benchmark)
        DatasetLoader.load_dataset(benchmark, mission)
        
        start_time = time.time()
        
        if dry_run:
            logger.info("Dry-run enabled. Bypassing execution.")
            mission.status = MissionState.COMPLETED
            execution_time_ms = 0.0
        else:
            # 2. Execution
            self.controller.start(mission)
            
            # 3. Wait for completion
            timeout = 60 # Configurable in reality
            start_wait = time.time()
            
            while mission.status not in (MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED, MissionState.WAITING_FOR_APPROVAL):
                if time.time() - start_wait > timeout:
                    self.controller.cancel(mission)
                    logger.error(f"Benchmark {benchmark.id} timed out.")
                    break
                time.sleep(1)
                
            execution_time_ms = (time.time() - start_time) * 1000
            
        # 4. Artifact Collection
        artifacts = ArtifactCollector.collect(mission)
        
        # 5. Ground Truth Comparison
        comparison = ComparisonRunner.compare(benchmark, mission)
        
        # 6. Metrics Calculation
        score, coverage, quality, performance = self.metrics_engine.evaluate(mission, comparison, execution_time_ms)
        
        # 7. Evaluation Result Generation
        result = EvaluationResult(
            id=str(uuid.uuid4()),
            benchmark_id=benchmark.id,
            dataset=benchmark.dataset_path or benchmark.id,
            runtime=execution_time_ms,
            score=score,
            coverage=coverage,
            quality=quality,
            performance=performance,
            comparison=comparison,
            artifacts=artifacts,
            summary=f"Evaluated {benchmark.id} with status {mission.status.value}",
            metadata={"status": mission.status.value, "dry_run": dry_run}
        )
        
        logger.info(f"Pipeline completed for {benchmark.id}")
        return result
