from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime


class NucleiCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission):

        if not mission.live_hosts:
            print("No live hosts.")
            return

        print("Running Nuclei...")

        findings = []

        for host in mission.live_hosts:

            result = self.runtime.run_command(
                executable="nuclei",
                args=[
                    "-u",
                    host["url"],
                    "-silent",
                    "-jsonl",
                ],
            )

            for line in result["stdout"].splitlines():

                if line.strip():

                    findings.append(line)

        mission.notes.extend(findings)

        print(f"✓ Nuclei Findings: {len(findings)}")
