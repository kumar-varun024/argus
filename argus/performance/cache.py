from typing import Dict, Any, TypeVar, Generic, Optional
from argus.performance.metrics import metrics

T = TypeVar('T')

class ObjectCache(Generic[T]):
    """Generic LRU Cache for managing memory and reducing duplicate objects."""
    def __init__(self, name: str, max_size: int = 10000):
        self.name = name
        self.max_size = max_size
        self._cache: Dict[str, T] = {}
        # Simple tracking for LRU or just bounding size
        self._access_order = []

    def get(self, key: str) -> Optional[T]:
        if key in self._cache:
            metrics.increment(f"cache_hit_{self.name}")
            # Move to end to mark as recently used
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]
        metrics.increment(f"cache_miss_{self.name}")
        return None

    def set(self, key: str, obj: T) -> None:
        if key in self._cache:
            self._access_order.remove(key)
        else:
            if len(self._cache) >= self.max_size:
                # Evict oldest
                oldest_key = self._access_order.pop(0)
                del self._cache[oldest_key]
        
        self._cache[key] = obj
        self._access_order.append(key)

    def invalidate(self, key: str) -> None:
        if key in self._cache:
            del self._cache[key]
            self._access_order.remove(key)

    def clear(self) -> None:
        self._cache.clear()
        self._access_order.clear()


class ObservationCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("observation", 50000)

class CorrelationCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("correlation", 20000)

class EvidenceCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("evidence", 20000)

class KnowledgeGraphCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("knowledge_graph", 5000)

class WorkflowCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("workflow", 5000)

class InvestigationCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("investigation", 10000)

class ExplanationCache(ObjectCache[Any]):
    def __init__(self):
        super().__init__("explanation", 10000)

# Global instances for the pipeline to use if not injected via DI
observation_cache = ObservationCache()
correlation_cache = CorrelationCache()
evidence_cache = EvidenceCache()
knowledge_graph_cache = KnowledgeGraphCache()
workflow_cache = WorkflowCache()
investigation_cache = InvestigationCache()
explanation_cache = ExplanationCache()

def clear_all_caches():
    observation_cache.clear()
    correlation_cache.clear()
    evidence_cache.clear()
    knowledge_graph_cache.clear()
    workflow_cache.clear()
    investigation_cache.clear()
    explanation_cache.clear()
