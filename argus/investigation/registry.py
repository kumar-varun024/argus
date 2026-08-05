import uuid
from typing import Dict, List, Optional
from argus.investigation.models import Investigation

class InvestigationRegistry:
    """Centralized store for Investigation objects."""

    def __init__(self):
        self._investigations: Dict[uuid.UUID, Investigation] = {}

    def add(self, investigation: Investigation) -> None:
        self._investigations[investigation.id] = investigation

    def remove(self, investigation_id: uuid.UUID) -> bool:
        if investigation_id in self._investigations:
            del self._investigations[investigation_id]
            return True
        return False

    def find(self, investigation_id: uuid.UUID) -> Optional[Investigation]:
        return self._investigations.get(investigation_id)

    def search(self, query: str) -> List[Investigation]:
        query = query.lower()
        results = []
        for inv in self._investigations.values():
            if query in inv.title.lower() or query in inv.description.lower() or query in inv.summary.lower():
                results.append(inv)
        return results
        
    def filter_by_category(self, category_value: str) -> List[Investigation]:
        return [inv for inv in self._investigations.values() if inv.category.value == category_value]

    def get_all(self) -> List[Investigation]:
        return list(self._investigations.values())

    def clear(self) -> None:
        self._investigations.clear()
