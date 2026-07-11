from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry


class HttpxCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission):

        tool = registry.get("live_host_detector")

        print(f"\nRunning {tool.name}...")

        if not mission.subdomains:
            print("No subdomains found.")
            return

        input_data = "\n".join(mission.subdomains)

        result = self.runtime.run_command(
            executable=tool.command,
            args=[
                "-json",
                "-silent",
            ],
            stdin=input_data,
        )

        mission.live_hosts = ReconParser.parse_httpx(
            result["stdout"]
        )

        print(f"✓ Found {len(mission.live_hosts)} live hosts")
