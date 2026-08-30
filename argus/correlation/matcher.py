from typing import List, Tuple, Optional, Callable
from argus.correlation.observation import Observation
from argus.correlation.rules import DEFAULT_RULES
from argus.graph.graph import KnowledgeGraph

class CorrelationMatcher:
    """Matches observations against each other using modular rules."""

    def __init__(self, rules: Optional[List[Tuple[str, Callable]]] = None, graph: Optional[KnowledgeGraph] = None):
        self.rules = rules or DEFAULT_RULES
        self.graph = graph

    def find_matches(self, obs1: Observation, obs2: Observation) -> List[str]:
        """
        Evaluate all rules against the two observations.
        Returns a list of rule names that successfully matched.
        """
        matched_rules = []
        for rule_name, rule_func in self.rules:
            try:
                matched = False
                try:
                    matched = rule_func(obs1, obs2, graph=self.graph)
                except TypeError:
                    matched = rule_func(obs1, obs2)
                if matched:
                    matched_rules.append(rule_name)
            except Exception:
                # If a rule fails unexpectedly, we continue with others
                pass
        return matched_rules
