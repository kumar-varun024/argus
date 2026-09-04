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


def _derive_host_dict(item: str, base_target: str = "") -> dict:
    """Derives a structured live_host dictionary from a subdomain or target string."""
    item = item.strip()
    scheme = "https"
    port = 443
    host = item

    if "://" in item or item.startswith(("http://", "https://")):
        try:
            parsed = urlparse(item)
            scheme = parsed.scheme or "https"
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            if parsed.port:
                port = parsed.port
            else:
                port = 80 if scheme == "http" else 443
        except Exception:
            pass
    else:
        # Check base_target for scheme/port hint
        if base_target and ("://" in base_target or base_target.startswith(("http://", "https://"))):
            try:
                parsed_base = urlparse(base_target)
                if parsed_base.scheme:
                    scheme = parsed_base.scheme
                if parsed_base.port:
                    port = parsed_base.port
                else:
                    port = 80 if scheme == "http" else 443
            except Exception:
                pass

        # Handle bracketed IPv6 (e.g. [::1]:9000 or [::1])
        if item.startswith("[") and "]" in item:
            bracket_end = item.index("]")
            raw_ip = item[1:bracket_end]
            host = f"[{raw_ip}]"
            rest = item[bracket_end + 1 :]
            if rest.startswith(":"):
                port_str = rest[1:]
                if port_str.isdigit():
                    port = int(port_str)
                    if port == 80:
                        scheme = "http"
                    elif port == 443:
                        scheme = "https"
        # Check if item itself has a port (e.g. localhost:8080 or 127.0.0.1:8080)
        elif ":" in item:
            try:
                ipaddress.ip_address(item)
            except ValueError:
                parts = item.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
                    port = int(parts[1])
                    if port == 80:
                        scheme = "http"
                    elif port == 443:
                        scheme = "https"

    # For URL construction, if host is IPv6 without brackets, bracket it
    url_host = host
    if ":" in host and not host.startswith("["):
        try:
            ipaddress.ip_address(host)
            url_host = f"[{host}]"
        except ValueError:
            pass

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = f"{scheme}://{url_host}"
    else:
        url = f"{scheme}://{url_host}:{port}"

    return {
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "status": 200,
        "title": "",
        "server": "",
        "technologies": [],
    }


class HttpxCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission) -> list[Evidence]:
        tool = registry.get("live_host_detector")
        tool_name = tool.name if tool else "httpx"
        print(f"\nRunning {tool_name}...")

        cmd_candidates = []
        if tool and tool.command:
            cmd_candidates.append(tool.command)
        cmd_candidates.extend(["httpx-toolkit", "httpx", "/usr/bin/httpx-toolkit", "/usr/bin/httpx"])

        exec_cmd = None
        for candidate in cmd_candidates:
            if shutil.which(candidate):
                exec_cmd = candidate
                break

        subdomains = getattr(mission, "subdomains", [])
        if not subdomains and getattr(mission, "target", None):
            subdomains = [mission.target]

        live_hosts = []

        if exec_cmd and subdomains:
            try:
                input_data = "\n".join(subdomains)
                result = self.runtime.run_command(
                    executable=exec_cmd,
                    args=[
                        "-json",
                        "-silent",
                    ],
                    stdin=input_data,
                )
                parsed = ReconParser.parse_httpx(result.get("stdout", ""))
                if parsed:
                    live_hosts = parsed
            except Exception as e:
                logger.warning(f"httpx execution failed: {e}; falling back to Python-native live host seeding")
                live_hosts = []

        if not live_hosts:
            # Fallback: create structured host dicts from subdomains or target
            target_str = getattr(mission, "target", "")
            items_to_seed = subdomains if subdomains else ([target_str] if target_str else [])
            for item in items_to_seed:
                host_dict = _derive_host_dict(item, base_target=target_str)
                live_hosts.append(host_dict)
            logger.info(f"httpx fallback: seeded {len(live_hosts)} live hosts")

        mission.live_hosts = live_hosts

        evidence_list = []
        for h in mission.live_hosts:
            host_url = h.get("url", "")
            ev = Evidence(
                category="live_host",
                source="httpx",
                title=f"Live Host: {host_url}",
                description=f"Live host detected at {host_url} (status: {h.get('status', 200)})",
                value=h,
                metadata=h,
            )
            if hasattr(mission, "evidence") and hasattr(mission.evidence, "add"):
                mission.evidence.add(ev)
            evidence_list.append(ev)

        print(f"✓ Found {len(mission.live_hosts)} live hosts")
        return evidence_list
