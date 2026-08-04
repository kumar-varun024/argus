import uuid
from typing import List, Dict, Optional, Callable, Any

from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

class ObservationRegistry:
    """Centralized in-memory store for Observations across the Mission."""

    def __init__(self):
        # Store observations keyed by their ID
        self._observations: Dict[uuid.UUID, Observation] = {}

    def add(self, observation: Observation) -> None:
        """Add a new observation to the registry."""
        self._observations[observation.id] = observation

    def remove(self, observation_id: uuid.UUID) -> bool:
        """Remove an observation by ID. Returns True if removed, False if not found."""
        if observation_id in self._observations:
            del self._observations[observation_id]
            return True
        return False

    def merge(self, other: 'ObservationRegistry') -> None:
        """Merge another registry's observations into this one."""
        self._observations.update(other._observations)

    def find(self, observation_id: uuid.UUID) -> Optional[Observation]:
        """Find an observation by its exact ID."""
        return self._observations.get(observation_id)

    def search(self, query: str) -> List[Observation]:
        """Search for observations containing the query string in title or description."""
        query = query.lower()
        results = []
        for obs in self._observations.values():
            if query in obs.title.lower() or query in obs.description.lower():
                results.append(obs)
        return results

    def filter(self, 
               category: Optional[ObservationCategory] = None, 
               source: Optional[str] = None,
               min_confidence: Optional[float] = None,
               priority: Optional[ObservationPriority] = None,
               custom_func: Optional[Callable[[Observation], bool]] = None) -> List[Observation]:
        """Filter observations based on multiple optional criteria."""
        results = []
        for obs in self._observations.values():
            if category and obs.category != category:
                continue
            if source and obs.source != source:
                continue
            if min_confidence is not None and obs.confidence < min_confidence:
                continue
            if priority and obs.priority != priority:
                continue
            if custom_func and not custom_func(obs):
                continue
            results.append(obs)
        return results

    def get_all(self) -> List[Observation]:
        """Return all observations."""
        return list(self._observations.values())

    def clear(self) -> None:
        """Clear all observations."""
        self._observations.clear()

class CorrelationRegistry:
    """Centralized in-memory store for Correlations across the Mission."""

    def __init__(self):
        # Store correlations keyed by their ID
        from argus.correlation.correlation import Correlation
        self._correlations: Dict[uuid.UUID, Correlation] = {}

    def add(self, correlation) -> None:
        """Add a new correlation to the registry."""
        self._correlations[correlation.id] = correlation

    def remove(self, correlation_id: uuid.UUID) -> bool:
        """Remove a correlation by ID. Returns True if removed, False if not found."""
        if correlation_id in self._correlations:
            del self._correlations[correlation_id]
            return True
        return False

    def merge(self, other: 'CorrelationRegistry') -> None:
        """Merge another registry's correlations into this one."""
        self._correlations.update(other._correlations)

    def find(self, correlation_id: uuid.UUID):
        """Find a correlation by its exact ID."""
        return self._correlations.get(correlation_id)

    def search(self, query: str) -> list:
        """Search for correlations containing the query string in title or description."""
        query = query.lower()
        results = []
        for corr in self._correlations.values():
            if query in corr.title.lower() or query in corr.description.lower():
                results.append(corr)
        return results

    def get_all(self) -> list:
        """Return all correlations."""
        return list(self._correlations.values())

    def clear(self) -> None:
        """Clear all correlations."""
        self._correlations.clear()

class EvidenceBundleRegistry:
    """Centralized in-memory store for Evidence Bundles across the Mission."""

    def __init__(self):
        # Store bundles keyed by their ID
        from argus.correlation.evidence import EvidenceBundle
        self._bundles: Dict[uuid.UUID, EvidenceBundle] = {}

    def add(self, bundle) -> None:
        self._bundles[bundle.id] = bundle

    def remove(self, bundle_id: uuid.UUID) -> bool:
        if bundle_id in self._bundles:
            del self._bundles[bundle_id]
            return True
        return False

    def merge(self, other: 'EvidenceBundleRegistry') -> None:
        self._bundles.update(other._bundles)

    def find(self, bundle_id: uuid.UUID):
        return self._bundles.get(bundle_id)

    def search(self, query: str) -> list:
        query = query.lower()
        results = []
        for bundle in self._bundles.values():
            if query in bundle.title.lower() or query in bundle.description.lower():
                results.append(bundle)
        return results

    def get_all(self) -> list:
        return list(self._bundles.values())

    def clear(self) -> None:
        self._bundles.clear()
