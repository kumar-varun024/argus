from argus.evidence.model import Evidence


class EvidenceStore:

    def __init__(self):

        self._items = []

    def add(self, evidence: Evidence):

        self._items.append(evidence)

    def all(self):

        return list(self._items)

    def filter(self, category: str):

        return [
            item
            for item in self._items
            if item.category == category
        ]

    def count(self):

        return len(self._items)

    def clear(self):

        self._items.clear()

    def __iter__(self):

        return iter(self._items)

    def __len__(self):

        return len(self._items)
