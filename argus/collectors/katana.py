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

            endpoints = ReconParser.parse_katana(result["stdout"])

            for endpoint in endpoints:
                url_str = endpoint["url"] if isinstance(endpoint, dict) else str(endpoint)

                if url_str in seen:
                    continue

                seen.add(url_str)

                endpoint_record = dict(endpoint) if isinstance(endpoint, dict) else {"url": url_str, "path": ""}
                endpoint_record["host"] = host["url"]
                endpoint_record["url"] = url_str

                mission.endpoints.append(endpoint_record)

        print(f"✓ Found {len(mission.endpoints)} endpoints")
