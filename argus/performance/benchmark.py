import uuid
import time
from typing import List, Any
from datetime import datetime, timezone

from argus.performance.profiling import Profiler
from argus.performance.metrics import metrics
from argus.performance.cache import clear_all_caches, observation_cache, correlation_cache
from argus.performance.incremental import tracker

# We will need to import some Argus models for real benchmarking
try:
    from argus.runtime.mission import Mission
    from argus.correlation.observation import Observation
    from argus.correlation.models import ObservationCategory, ObservationPriority
    from argus.correlation.correlation import Correlation
    from argus.correlation.evidence import EvidenceBundle
    from argus.investigation.models import Investigation, InvestigationCategory, InvestigationPriority
    HAS_ARGUS_MODELS = True
except ImportError:
    HAS_ARGUS_MODELS = False

class BenchmarkSuite:
    def __init__(self):
        pass

    def _generate_workload(self, num_observations: int, num_correlations: int):
        """Generates synthetic data for benchmarking."""
        if not HAS_ARGUS_MODELS:
            print("Argus models not available, skipping data generation.")
            return None
        
        mission = Mission(target="benchmark.local")
        
        # Generate Observations
        obs_ids = []
        for i in range(num_observations):
            obs_id = uuid.uuid4()
            obs = Observation(
                id=obs_id,
                source=f"bench_agent_{i%10}",
                category=ObservationCategory.API,
                title=f"Benchmark Observation {i}",
                description="Synthetic observation for benchmarking.",
                confidence=0.8,
                priority=ObservationPriority.MEDIUM,
                timestamp=datetime.now(timezone.utc)
            )
            mission.observations.add(obs)
            obs_ids.append(obs_id)
            # Add to cache for benchmark
            observation_cache.set(str(obs_id), obs)
            tracker.update_node(str(obs_id), obs)

        # Generate Correlations
        for i in range(num_correlations):
            corr = Correlation(
                id=uuid.uuid4(),
                title=f"Benchmark Correlation {i}",
                description="Synthetic correlation",
                observations=[obs_ids[i % len(obs_ids)], obs_ids[(i+1) % len(obs_ids)]] if len(obs_ids) > 1 else obs_ids,
                confidence=0.9
            )
            mission.correlations.add(corr)
            correlation_cache.set(str(corr.id), corr)

        return mission

    def run_small(self):
        print("Running Small Benchmark...")
        with Profiler("benchmark_small"):
            self._generate_workload(100, 20)

    def run_medium(self):
        print("Running Medium Benchmark...")
        with Profiler("benchmark_medium"):
            self._generate_workload(1000, 200)

    def run_large(self):
        print("Running Large Benchmark...")
        with Profiler("benchmark_large"):
            self._generate_workload(10000, 2000)

    def run_very_large(self):
        print("Running Very Large Benchmark...")
        with Profiler("benchmark_very_large"):
            # The prompt requested supporting tens of thousands of observations.
            self._generate_workload(20000, 5000)

    def run_all(self):
        metrics.clear()
        tracker.reset()
        clear_all_caches()
        
        self.run_small()
        self.run_medium()
        self.run_large()
        self.run_very_large()
        
        return metrics.get_summary()

suite = BenchmarkSuite()
