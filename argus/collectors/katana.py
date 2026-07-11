from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry


class KatanaCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission):

        tool = registry.get("crawler")

        print(f"\nRunning {tool.name}...")

        mission.endpoints.clear()

        if not mission.live_hosts:
            print("No live hosts found.")
            return

        seen = set()

        for host in mission.live_hosts:

            result = self.runtime.run_command(
                executable=tool.command,
                args=[
                    "-u",
                    host["url"],
                    "-silent",
                ],
            )

            endpoints = ReconParser.parse_katana(
                result["stdout"]
            )

            for endpoint in endpoints:

                if endpoint in seen:
                    continue

                seen.add(endpoint)

                mission.endpoints.append(
                    {
                        "host": host["url"],
                        "url": endpoint,
                    }
                )

        print(f"✓ Found {len(mission.endpoints)} endpoints")
