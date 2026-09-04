from __future__ import annotations

import logging
import shutil
from urllib.parse import urlparse, parse_qs

from argus.collectors.base import BaseCollector
from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry
from argus.evidence.model import Evidence

logger = logging.getLogger(__name__)


def _derive_endpoint_dict(host_entry: dict | str, base_target: str = "") -> dict:
    """Derives a structured endpoint dict from a live_host entry or target."""
    if isinstance(host_entry, dict):
        host_url = host_entry.get("url", "")
    else:
        host_url = str(host_entry).strip()

    path = "/"
    params: dict = {}

    # Inspect base_target if present
    parsed_target = None
    if base_target:
        target_str = base_target.strip()
        has_scheme = "://" in target_str or target_str.startswith(("http://", "https://"))
        target_to_parse = target_str if has_scheme else f"http://{target_str}"
        try:
            parsed_target = urlparse(target_to_parse)
        except Exception:
            pass

    if parsed_target and parsed_target.path and parsed_target.path not in ("", "/"):
        path = parsed_target.path
        if parsed_target.query:
            raw_params = parse_qs(parsed_target.query)
            params = {k: v[0] if len(v) == 1 else v for k, v in raw_params.items()}
    elif host_url:
        has_scheme = "://" in host_url or host_url.startswith(("http://", "https://"))
        host_to_parse = host_url if has_scheme else f"http://{host_url}"
        try:
            parsed_host = urlparse(host_to_parse)
            if parsed_host.path and parsed_host.path not in ("", "/"):
                path = parsed_host.path
            if parsed_host.query:
                raw_params = parse_qs(parsed_host.query)
                params = {k: v[0] if len(v) == 1 else v for k, v in raw_params.items()}
        except Exception:
            pass

    # Normalize clean_host
    if "://" in host_url or host_url.startswith(("http://", "https://")):
        try:
            ph = urlparse(host_url)
            clean_host = f"{ph.scheme}://{ph.netloc}"
        except Exception:
            clean_host = host_url.rstrip("/")
    else:
        clean_host = host_url.rstrip("/")
        if "/" in clean_host:
            clean_host = clean_host.split("/")[0]

    clean_host = clean_host.rstrip("/")
    if path == "/":
        endpoint_url = f"{clean_host}/" if clean_host.startswith(("http://", "https://")) else clean_host
    elif path.startswith("/"):
        endpoint_url = f"{clean_host}{path}"
    else:
        endpoint_url = f"{clean_host}/{path}"

    return {
        "url": endpoint_url,
        "path": path,
        "host": clean_host,
        "method": "GET",
        "params": params,
    }


class KatanaCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()

    def collect(self, mission) -> list[Evidence]:
        tool = registry.get("crawler")
        tool_name = tool.name if tool else "Katana"
        print(f"\nRunning {tool_name}...")

        cmd = tool.command if tool and tool.command else "katana"
        has_binary = shutil.which(cmd) is not None or shutil.which("katana") is not None

        if getattr(mission, "endpoints", None) is None:
            mission.endpoints = []
        else:
            mission.endpoints.clear()

        live_hosts = getattr(mission, "live_hosts", [])
        target_str = getattr(mission, "target", "")

        # If no live hosts available, attempt to derive one from target
        if not live_hosts and target_str:
            if "://" not in target_str and not target_str.startswith(("http://", "https://")):
                live_hosts = [{"url": f"https://{target_str}"}]
            else:
                live_hosts = [{"url": target_str}]

        seen = set()

        if has_binary and live_hosts:
            exec_cmd = cmd if shutil.which(cmd) else "katana"
            for host in live_hosts:
                host_url = host["url"] if isinstance(host, dict) else str(host)
                try:
                    result = self.runtime.run_command(
                        executable=exec_cmd,
                        args=[
                            "-u",
                            host_url,
                            "-silent",
                        ],
                    )
                    endpoints = ReconParser.parse_katana(result.get("stdout", ""))
                    for endpoint in endpoints:
                        url_str = endpoint["url"] if isinstance(endpoint, dict) else str(endpoint)
                        if url_str in seen:
                            continue
                        seen.add(url_str)
                        endpoint_record = dict(endpoint) if isinstance(endpoint, dict) else {"url": url_str, "path": ""}
                        endpoint_record["host"] = host_url
                        endpoint_record["url"] = url_str
                        if "method" not in endpoint_record:
                            endpoint_record["method"] = "GET"
                        if "params" not in endpoint_record:
                            endpoint_record["params"] = {}
                        mission.endpoints.append(endpoint_record)
                except Exception as e:
                    logger.warning(f"Katana crawler failed on {host_url}: {e}")

        # Fallback: if no endpoints found via binary, seed from live hosts
        if not mission.endpoints and live_hosts:
            logger.info("Katana fallback: seeding endpoints directly from live hosts")
            for host in live_hosts:
                ep = _derive_endpoint_dict(host, base_target=target_str)
                if ep["url"] not in seen:
                    seen.add(ep["url"])
                    mission.endpoints.append(ep)

        evidence_list = []
        for ep in mission.endpoints:
            ev = Evidence(
                category="endpoint",
                source="katana",
                title=f"Discovered Endpoint: {ep.get('url', '')}",
                description=f"Discovered endpoint {ep.get('path', '/')} on {ep.get('host', '')}",
                value=ep,
                metadata=ep,
            )
            if hasattr(mission, "evidence") and hasattr(mission.evidence, "add"):
                mission.evidence.add(ev)
            evidence_list.append(ev)

        print(f"✓ Found {len(mission.endpoints)} endpoints")
        return evidence_list
