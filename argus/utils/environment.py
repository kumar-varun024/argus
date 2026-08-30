"""
Environment detector utility for Argus.

Discovers external CLI tools, target network reachability, and cloud metadata
endpoints to configure mission execution and tool routing.
"""

import ipaddress
import logging
import os
import shutil
import socket
import urllib.parse
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class EnvironmentDetector:
    """
    Detects available tools, network connectivity, and cloud metadata environment.
    """

    DEFAULT_EXTERNAL_TOOLS: List[str] = [
        "subfinder",
        "httpx",
        "nuclei",
        "katana",
        "dnsx",
        "node",
        "npm",
    ]

    CLOUD_METADATA_ENDPOINTS: Dict[str, Dict[str, Any]] = {
        "aws": {
            "name": "AWS EC2 IMDSv1/v2",
            "url": "http://169.254.169.254/latest/meta-data/",
            "headers": {},
        },
        "gcp": {
            "name": "Google Cloud Metadata",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "headers": {"Metadata-Flavor": "Google"},
        },
        "azure": {
            "name": "Azure Instance Metadata Service",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true"},
        },
    }

    def __init__(self, timeout: float = 2.0):
        """
        Initialize EnvironmentDetector.

        Args:
            timeout: Network and probe timeout in seconds.
        """
        self.timeout = timeout

    def check_tools(self, tool_names: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Check if external CLI tools are available on the system PATH.

        Handles tool aliases (e.g. httpx -> httpx-toolkit).

        Args:
            tool_names: Optional list of tool names to check. Defaults to DEFAULT_EXTERNAL_TOOLS.

        Returns:
            Dict mapping tool name to availability boolean.
        """
        tools_to_check = tool_names if tool_names is not None else self.DEFAULT_EXTERNAL_TOOLS
        results: Dict[str, bool] = {}

        for tool in tools_to_check:
            if tool == "httpx":
                # Check for either httpx or httpx-toolkit
                available = bool(shutil.which("httpx") or shutil.which("httpx-toolkit"))
            else:
                available = bool(shutil.which(tool))
            results[tool] = available

        return results

    def check_network(self, target: str) -> Dict[str, Any]:
        """
        Validate DNS resolution and HTTP reachability to the target.

        Args:
            target: Hostname, IP address, or URL.

        Returns:
            Dict containing DNS and HTTP reachability details.
        """
        if not target or not target.strip():
            return {
                "target": "",
                "host": "",
                "dns_resolvable": False,
                "ip_addresses": [],
                "http_reachable": False,
                "status_code": None,
                "error": "No target specified",
            }

        target_clean = target.strip()
        try:
            is_raw_ip = False
            try:
                ip = ipaddress.ip_address(target_clean)
                is_raw_ip = True
                if ip.version == 6:
                    host = str(ip)
                    url_to_test = f"http://[{host}]"
                else:
                    host = str(ip)
                    url_to_test = f"http://{host}"
            except ValueError:
                pass

            if not is_raw_ip:
                if "://" in target_clean:
                    scheme, rest = target_clean.split("://", 1)
                    authority = rest.split("/")[0].split("?")[0].split("#")[0]
                    path_query = rest[len(authority):]

                    try:
                        ip = ipaddress.ip_address(authority)
                        if ip.version == 6:
                            host = str(ip)
                            url_to_test = f"{scheme}://[{host}]{path_query}"
                        else:
                            host = str(ip)
                            url_to_test = target_clean
                    except ValueError:
                        parsed = urllib.parse.urlparse(target_clean)
                        host = parsed.hostname or parsed.netloc or target_clean
                        url_to_test = target_clean
                else:
                    if target_clean.startswith("[") or "]" in target_clean:
                        parsed = urllib.parse.urlparse(f"http://{target_clean}")
                        host = parsed.hostname or parsed.netloc or target_clean
                        url_to_test = f"http://{target_clean}"
                    else:
                        first_part = target_clean.split("/")[0]
                        try:
                            ip = ipaddress.ip_address(first_part)
                            if ip.version == 6:
                                host = str(ip)
                                path_query = target_clean[len(first_part):]
                                url_to_test = f"http://[{host}]{path_query}"
                            else:
                                host = str(ip)
                                url_to_test = f"http://{target_clean}"
                        except ValueError:
                            host = first_part.split(":")[0]
                            url_to_test = f"http://{target_clean}"

            if not host:
                raise ValueError(f"Could not extract host from target: {target}")

        except (ValueError, Exception) as e:
            return {
                "target": target,
                "host": "",
                "dns_resolvable": False,
                "ip_addresses": [],
                "http_reachable": False,
                "status_code": None,
                "error": f"Invalid target URL: {e}",
            }

        dns_resolvable = False
        ip_addresses: List[str] = []
        dns_error: Optional[str] = None

        try:
            addr_info = socket.getaddrinfo(host, None)
            ips = set()
            for item in addr_info:
                sockaddr = item[4]
                if sockaddr and sockaddr[0]:
                    ips.add(sockaddr[0])
            ip_addresses = sorted(list(ips))
            dns_resolvable = len(ip_addresses) > 0
        except Exception as e:
            dns_error = str(e)
            dns_resolvable = False

        http_reachable = False
        status_code: Optional[int] = None
        http_error: Optional[str] = None

        if dns_resolvable or host in ("localhost", "127.0.0.1", "::1"):
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                    resp = client.get(url_to_test)
                    status_code = resp.status_code
                    http_reachable = True
            except Exception as e:
                http_error = str(e)
                http_reachable = False

        error = http_error or dns_error if not http_reachable else None

        return {
            "target": target,
            "host": host,
            "dns_resolvable": dns_resolvable,
            "ip_addresses": ip_addresses,
            "http_reachable": http_reachable,
            "status_code": status_code,
            "error": error,
        }

    def check_cloud_metadata(self) -> Dict[str, Any]:
        """
        Check accessibility of AWS, GCP, and Azure cloud metadata services.

        Returns:
            Dict containing reachability status for each cloud provider.
        """
        endpoints_res: Dict[str, Dict[str, Any]] = {}
        probe_timeout = min(self.timeout, 1.0)

        for provider, cfg in self.CLOUD_METADATA_ENDPOINTS.items():
            url = cfg["url"]
            headers = cfg.get("headers", {})
            accessible = False
            status_code: Optional[int] = None

            try:
                with httpx.Client(timeout=probe_timeout, follow_redirects=False) as client:
                    resp = client.get(url, headers=headers)
                    status_code = resp.status_code
                    if resp.status_code == 200:
                        accessible = True
            except Exception:
                accessible = False
                status_code = None

            endpoints_res[provider] = {
                "accessible": accessible,
                "status_code": status_code,
            }

        return {
            "aws": endpoints_res.get("aws", {}).get("accessible", False),
            "gcp": endpoints_res.get("gcp", {}).get("accessible", False),
            "azure": endpoints_res.get("azure", {}).get("accessible", False),
            "endpoints": endpoints_res,
        }

    def detect(self, target: str = "") -> Dict[str, Any]:
        """
        Execute full environment discovery.

        Args:
            target: Optional target hostname/URL to check network reachability for.

        Returns:
            Structured composite dictionary with tools, network, cloud_metadata, and summary.
        """
        tools_res = self.check_tools()
        network_res = self.check_network(target) if target else {
            "target": "",
            "host": "",
            "dns_resolvable": False,
            "ip_addresses": [],
            "http_reachable": False,
            "status_code": None,
            "error": "No target specified",
        }
        cloud_res = self.check_cloud_metadata()

        tools_avail = sum(1 for v in tools_res.values() if v)
        tools_miss = sum(1 for v in tools_res.values() if not v)

        summary = {
            "tools_available_count": tools_avail,
            "tools_missing_count": tools_miss,
            "network_reachable": network_res.get("http_reachable", False),
            "in_cloud_environment": any([
                cloud_res.get("aws", False),
                cloud_res.get("gcp", False),
                cloud_res.get("azure", False),
            ]),
        }

        return {
            "tools": tools_res,
            "network": network_res,
            "cloud_metadata": cloud_res,
            "summary": summary,
        }
