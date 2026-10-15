"""
Mission scope derivation.

Pure helper (no Argus dependencies) that turns a target string — URL, domain,
wildcard, IP, or CIDR — into the default authorization scope rules for a mission.
Extracted verbatim from ``argus.runtime.mission`` so it can be unit-tested and
reused without importing the heavyweight Mission dataclass.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def derive_default_scope(target: str) -> list[str]:
    """Derives default authorization scope rules from a mission target string."""
    if not target or not isinstance(target, str):
        return []
    target = target.strip()
    if not target:
        return []

    # Check if target is a wildcard domain like *.example.com
    if target.startswith("*."):
        base = target[2:].strip()
        return [target, base] if base else [target]

    # Check if target is a full URL with scheme
    if "://" in target or target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc.split(":")[0]
        except Exception:
            host = target
    else:
        # Check CIDR notation first (e.g., 10.0.0.0/24)
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return [target]
            except ValueError:
                # Path without scheme, e.g. example.com/api or 192.168.1.1/api
                host = target.split("/")[0]
        else:
            host = target

        # Handle host:port notation (excluding pure IPv6 addresses)
        if ":" in host and not host.startswith("["):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                # Check if it has a port at the end (e.g., api.example.com:8080)
                parts = host.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]

    if not host:
        return []

    # Strip IPv6 enclosing brackets if present (e.g., [::1] or [::1]:9000)
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    # Check if host is a valid IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    # Check if host is a valid CIDR network
    try:
        ipaddress.ip_network(host, strict=False)
        return [host]
    except ValueError:
        pass

    # Check if host is wildcard
    if host.startswith("*."):
        base = host[2:].strip()
        return [host, base] if base else [host]

    # Domain or hostname
    return [host, f"*.{host}"]


# Backward-compatible alias for the original private name.
_derive_default_scope = derive_default_scope
