class FactStore:

    def __init__(self):

        self._facts = set()

    def add(self, fact):

        self._facts.add(fact)

    def has(self, fact):

        return fact in self._facts

    def all(self):

        return sorted(self._facts)

    def __len__(self):

        return len(self._facts)

    def __iter__(self):

        return iter(self._facts)
