import pytest
import uuid
import time
from datetime import datetime, timezone

from argus.performance.cache import (
    ObservationCache, CorrelationCache, clear_all_caches, observation_cache
)
from argus.performance.incremental import IncrementalTracker
from argus.performance.parallel import ParallelExecutor
from argus.performance.metrics import metrics

# Import models
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

@pytest.fixture(autouse=True)
def setup_teardown():
    clear_all_caches()
    metrics.clear()
    yield
    clear_all_caches()
    metrics.clear()

def test_cache_correctness():
    cache = ObservationCache()
    obs_id = str(uuid.uuid4())
    
    obs = Observation(
        id=uuid.UUID(obs_id),
        source="test",
        category=ObservationCategory.API,
        title="Test Obs",
        description="Desc",
        confidence=1.0,
        priority=ObservationPriority.HIGH,
        timestamp=datetime.now(timezone.utc)
    )
    
    # Test miss
    assert cache.get(obs_id) is None
    
    # Test set and hit
    cache.set(obs_id, obs)
    cached_obs = cache.get(obs_id)
    assert cached_obs is not None
    assert cached_obs.id == obs.id
    
    # Test invalidate
    cache.invalidate(obs_id)
    assert cache.get(obs_id) is None

def test_incremental_tracker():
    tracker = IncrementalTracker()
    obs_id = str(uuid.uuid4())
    
    obs = Observation(
        id=uuid.UUID(obs_id),
        source="test",
        category=ObservationCategory.API,
        title="Test Obs",
        description="Desc",
        confidence=1.0,
        priority=ObservationPriority.HIGH,
        timestamp=datetime.now(timezone.utc)
    )
    
    # Initial update should mark dirty
    is_dirty = tracker.update_node(obs_id, obs)
    assert is_dirty is True
    assert tracker.is_dirty(obs_id) is True
    
    # Clear dirty state
    tracker.clear_dirty_state()
    assert tracker.is_dirty(obs_id) is False
    
    # Updating with identical data should NOT mark dirty
    is_dirty_again = tracker.update_node(obs_id, obs)
    assert is_dirty_again is False
    assert tracker.is_dirty(obs_id) is False
    
    # Changing data should mark dirty
    obs.title = "Changed Title"
    is_dirty_modified = tracker.update_node(obs_id, obs)
    assert is_dirty_modified is True
    assert tracker.is_dirty(obs_id) is True

def test_parallel_execution_deterministic():
    executor = ParallelExecutor(max_workers=4)
    
    def process_item(item):
        time.sleep(0.01) # Simulating IO
        return item * 2
        
    inputs = list(range(100))
    # map_tasks should preserve the input order
    results = executor.map_tasks(process_item, inputs)
    
    assert len(results) == 100
    assert results == [i * 2 for i in range(100)]

def test_stress_caching():
    # Test cache capacity and LRU mechanics
    cache = ObservationCache()
    # default max_size for observation cache is 50000. 
    # Let's temporarily mock it smaller for testing.
    cache.max_size = 100
    
    for i in range(150):
        obs_id = str(uuid.uuid4())
        cache.set(obs_id, f"data_{i}")
        
    assert len(cache._cache) == 100
    
def test_metrics_collection():
    metrics.increment("test_counter", 5)
    metrics.record_time("test_timer", 0.5)
    metrics.record_time("test_timer", 1.5)
    
    summary = metrics.get_summary()
    assert summary["counters"]["test_counter"] == 5
    assert summary["averages"]["test_timer"] == 1.0
