from argus.knowledge import KnowledgeBase

from .hypothesis import Hypothesis


class ReasoningEngine:

    def __init__(self):

        self.knowledge = KnowledgeBase()

    def generate(self, mission):

        hypotheses = []

        observations = self._collect_observations(mission)

        for rule in self.knowledge.rules_for():

            if self._matches(rule.requires, observations):

                hypotheses.append(
                    Hypothesis(
                        title=rule.name,
                        description=rule.hypothesis,
                        confidence=self._confidence(
                            rule.requires,
                            observations,
                        ),
                        severity=rule.severity,
                        evidence=rule.requires,
                        reasoning=[
                            rule.description,
                        ],
                        next_actions=rule.investigation,
                        tags=rule.tags,
                    )
                )

        return hypotheses

    def _collect_observations(self, mission):

        observed = set()

        for evidence in mission.evidence:

            observed.add(evidence.value)

        return observed

    def _matches(self, required, observed):

        return all(item in observed for item in required)

    def _confidence(self, required, observed):

        matched = sum(1 for item in required if item in observed)

        return round(matched / len(required), 2)
