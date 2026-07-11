from argus.collectors.base import BaseCollector
from argus.evidence import Evidence


class TechnologyCollector(BaseCollector):

    def collect(self, mission):

        print("\nTechnology Intelligence...")

        discovered = set()

        for host in mission.live_hosts:

            for tech in host.get("technologies", []):

                if tech in discovered:
                    continue

                discovered.add(tech)

                mission.evidence.add(
                    Evidence(
                        category="technology",
                        value=tech,
                        source=host["url"],
                    )
                )

        print(f"✓ Technologies: {len(discovered)}")
