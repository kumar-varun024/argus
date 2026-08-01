from typing import Dict, List
from argus.intelligence.heuristics import BaseHeuristic

class HeuristicRegistry:
    def __init__(self):
        self._heuristics: Dict[str, BaseHeuristic] = {}

    def register(self, heuristic: BaseHeuristic):
        if heuristic.id in self._heuristics:
            raise ValueError(f"Heuristic '{heuristic.id}' is already registered.")
        self._heuristics[heuristic.id] = heuristic

    def unregister(self, heuristic_id: str):
        if heuristic_id in self._heuristics:
            del self._heuristics[heuristic_id]

    def get_all(self) -> List[BaseHeuristic]:
        return list(self._heuristics.values())

    def get(self, heuristic_id: str) -> BaseHeuristic:
        return self._heuristics.get(heuristic_id)

    def get_by_category(self, category: str) -> List[BaseHeuristic]:
        return [h for h in self._heuristics.values() if h.category == category]
