from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry


class SubfinderCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission):

        tool = registry.get("subdomain_enumerator")

        print(f"\nRunning {tool.name}...")

        result = self.runtime.run_command(
            executable=tool.command,
            args=[
                "-d",
                mission.target,
                "-silent",
            ],
        )

        mission.subdomains = ReconParser.parse_subfinder(result["stdout"])

        print(f"✓ Found {len(mission.subdomains)} subdomains")
