from __future__ import annotations

import json
import logging
import shutil

from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.registry import registry
from argus.evidence.model import Evidence

logger = logging.getLogger(__name__)


class NucleiCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission) -> list[Evidence]:
        tool = registry.get("vulnerability_scanner")
        tool_name = tool.name if tool else "Nuclei"
        cmd = tool.command if tool and tool.command else "nuclei"

        live_hosts = getattr(mission, "live_hosts", [])
        if not live_hosts:
            print("No live hosts.")
            return []

        has_binary = shutil.which(cmd) is not None or shutil.which("nuclei") is not None
        if not has_binary:
            logger.info("Nuclei binary not found on PATH; skipping vulnerability scan cleanly.")
            print("Nuclei binary not installed; skipping.")
            return []

        print(f"\nRunning {tool_name}...")
        exec_cmd = cmd if shutil.which(cmd) else "nuclei"
        evidence_list = []

        if getattr(mission, "vulnerabilities", None) is None:
            mission.vulnerabilities = []

        for host in live_hosts:
            host_url = host["url"] if isinstance(host, dict) else str(host)
            try:
                result = self.runtime.run_command(
                    executable=exec_cmd,
                    args=[
                        "-u",
                        host_url,
                        "-silent",
                        "-jsonl",
                    ],
                )
                stdout = result.get("stdout", "")
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            mission.vulnerabilities.append(data)
                            info = data.get("info", {})
                            title = info.get("name", data.get("template-id", "Nuclei Finding"))
                            severity = info.get("severity", "info").lower()
                            description = info.get("description", "")
                            ev = Evidence(
                                category="vulnerability",
                                source="nuclei",
                                title=f"Nuclei: {title}",
                                description=description,
                                severity=severity,
                                value=data,
                                metadata=data,
                            )
                            if hasattr(mission, "evidence") and hasattr(mission.evidence, "add"):
                                mission.evidence.add(ev)
                            evidence_list.append(ev)
                            continue
                    except json.JSONDecodeError:
                        pass

                    # Plain text finding
                    finding_dict = {"finding": line, "host": host_url}
                    mission.vulnerabilities.append(finding_dict)
                    ev = Evidence(
                        category="vulnerability",
                        source="nuclei",
                        title=f"Nuclei Finding on {host_url}",
                        description=line,
                        severity="info",
                        value=finding_dict,
                        metadata=finding_dict,
                    )
                    if hasattr(mission, "evidence") and hasattr(mission.evidence, "add"):
                        mission.evidence.add(ev)
                    evidence_list.append(ev)
            except Exception as e:
                logger.warning(f"Nuclei execution failed on {host_url}: {e}")

        print(f"✓ Nuclei Findings: {len(evidence_list)}")
        return evidence_list
