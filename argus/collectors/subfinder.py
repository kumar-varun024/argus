from __future__ import annotations

import logging
import shutil
from urllib.parse import urlparse
import ipaddress

from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry
from argus.evidence.model import Evidence

logger = logging.getLogger(__name__)


def _extract_host(target: str) -> str:
    """Extract host / domain / IP from a target string or URL."""
    if not target:
        return ""
    target = target.strip()
    if "://" in target or target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            return host or target
        except Exception:
            pass
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            target = target.split("/")[0]
    if target.startswith("[") and "]" in target:
        return target[1:target.index("]")]
    if ":" in target:
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            parts = target.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0]
    return target


class SubfinderCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission) -> list[Evidence]:
        tool = registry.get("subdomain_enumerator")
        cmd = tool.command if tool and tool.command else "subfinder"

        tool_name = tool.name if tool else "Subfinder"
        print(f"\nRunning {tool_name}...")

        host = _extract_host(getattr(mission, "target", ""))
        subdomains = []

        # Check if binary is available
        has_binary = shutil.which(cmd) is not None or shutil.which("subfinder") is not None

        if has_binary:
            try:
                exec_cmd = cmd if shutil.which(cmd) else "subfinder"
                result = self.runtime.run_command(
                    executable=exec_cmd,
                    args=[
                        "-d",
                        host or mission.target,
                        "-silent",
                    ],
                )
                parsed = ReconParser.parse_subfinder(result.get("stdout", ""))
                subdomains = [s["hostname"] if isinstance(s, dict) else str(s) for s in parsed]
            except Exception as e:
                logger.warning(f"Subfinder execution failed: {e}; falling back to Python-native target seeding")
                subdomains = []

        if not subdomains:
            # Fallback: seed target host
            fallback_sub = host or getattr(mission, "target", "")
            if fallback_sub:
                subdomains = [fallback_sub]
                logger.info(f"Subfinder fallback: seeded subdomain '{fallback_sub}'")

        if not getattr(mission, "subdomains", None):
            mission.subdomains = list(subdomains)
        else:
            for s in subdomains:
                if s not in mission.subdomains:
                    mission.subdomains.append(s)

        evidence_list = []
        for s in mission.subdomains:
            ev = Evidence(
                category="subdomain",
                source="subfinder",
                title=f"Discovered Subdomain: {s}",
                description=f"Subdomain {s} identified for target {mission.target}",
                value={"subdomain": s},
                metadata={"subdomain": s},
            )
            if hasattr(mission, "evidence") and hasattr(mission.evidence, "add"):
                mission.evidence.add(ev)
            evidence_list.append(ev)

        print(f"✓ Found {len(mission.subdomains)} subdomains")
        return evidence_list
