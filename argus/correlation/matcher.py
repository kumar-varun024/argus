from typing import List, Tuple
from argus.correlation.observation import Observation
from argus.correlation.rules import DEFAULT_RULES

class CorrelationMatcher:
    """Matches observations against each other using modular rules."""

    def __init__(self, rules: List[Tuple[str, callable]] = None):
        self.rules = rules or DEFAULT_RULES

    def find_matches(self, obs1: Observation, obs2: Observation) -> List[str]:
        """
        Evaluate all rules against the two observations.
        Returns a list of rule names that successfully matched.
        """
        matched_rules = []
        for rule_name, rule_func in self.rules:
            try:
                if rule_func(obs1, obs2):
                    matched_rules.append(rule_name)
            except Exception:
                # If a rule fails unexpectedly, we continue with others
                pass
        return matched_rules
