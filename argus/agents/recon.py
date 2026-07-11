from argus.agents.base import BaseAgent
from argus.analyzers import AuthenticationAnalyzer
from argus.reasoning import ReasoningEngine

from argus.collectors import (
    SubfinderCollector,
    HttpxCollector,
    KatanaCollector,
    JavaScriptCollector,
    NucleiCollector,
    TechnologyCollector,
)


class ReconAgent(BaseAgent):

    def __init__(self):
        super().__init__("Recon Agent")

        self.collectors = [
            SubfinderCollector(),
            HttpxCollector(),
            KatanaCollector(),
            JavaScriptCollector(),
            NucleiCollector(),
            TechnologyCollector(),
        ]

        self.authentication = AuthenticationAnalyzer()
        self.reasoning = ReasoningEngine()

    def think(self, mission):

        print(f"Target: {mission.target}")
        print("Planning reconnaissance...")

    def execute(self, mission):

        for collector in self.collectors:
            collector.collect(mission)

        self.authentication.analyze(mission)

        mission.hypotheses = self.reasoning.generate(mission)

    def evaluate(self, mission):

        print("\nMission Summary")
        print("-------------------------")
        print(f"Subdomains : {len(mission.subdomains)}")
        print(f"Live Hosts : {len(mission.live_hosts)}")
        print(f"Endpoints  : {len(mission.endpoints)}")
        print(f"JavaScript : {len(mission.javascript)}")
        print(f"APIs       : {len(mission.apis)}")
        print(f"Evidence   : {len(mission.evidence)}")
        print(f"Findings   : {len(mission.findings)}")
        print(f"Hypotheses : {len(mission.hypotheses)}")

        if mission.hypotheses:

            print("\nReasoning")
            print("-------------------------")

            for hypothesis in mission.hypotheses:

                print(
                    f"\n[{hypothesis.confidence:.2f}] "
                    f"{hypothesis.title}"
                )

                print(hypothesis.description)

                print("Next:")

                for action in hypothesis.next_actions:
                    print(f"  • {action}")

        print("\nRecon phase complete.")
