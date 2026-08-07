import uuid
from typing import Dict, List, Optional
from argus.hypothesis.models import Hypothesis, HypothesisStatus

class HypothesisRegistry:
    """Centralized store for Hypothesis objects."""

    def __init__(self):
        self._hypotheses: Dict[uuid.UUID, Hypothesis] = {}

    def add(self, hypothesis: Hypothesis) -> None:
        self._hypotheses[hypothesis.id] = hypothesis

    def remove(self, hypothesis_id: uuid.UUID) -> bool:
        if hypothesis_id in self._hypotheses:
            del self._hypotheses[hypothesis_id]
            return True
        return False

    def find(self, hypothesis_id: uuid.UUID) -> Optional[Hypothesis]:
        return self._hypotheses.get(hypothesis_id)

    def search(self, query: str) -> List[Hypothesis]:
        query = query.lower()
        results = []
        for hyp in self._hypotheses.values():
            if query in hyp.title.lower() or query in hyp.description.lower() or query in hyp.summary.lower():
                results.append(hyp)
        return results

    def filter_by_category(self, category_value: str) -> List[Hypothesis]:
        return [hyp for hyp in self._hypotheses.values() if hyp.category.value == category_value]

    def filter_by_status(self, status: HypothesisStatus) -> List[Hypothesis]:
        return [hyp for hyp in self._hypotheses.values() if hyp.status == status]

    def get_all(self) -> List[Hypothesis]:
        return list(self._hypotheses.values())

    def clear(self) -> None:
        self._hypotheses.clear()
