"""Build display-only pending proposal summaries from local workspace state."""

from hashlib import sha256
from ipaddress import ip_network
import re
from typing import TypedDict
from urllib.parse import urlsplit


_DISPLAY_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}\Z")


class PendingProposalSummary(TypedDict):
    proposal_id: str
    target: str
    profile: str
    mission_id: str | None
    expires_at: float
    review: None
    conversation_id: str


def _display_target(target: str) -> str:
    """Display only a host, network, or URL origin. URL components can contain secrets."""
    if len(target) > 2048:
        return "[unavailable]"
    if _DISPLAY_HOST.fullmatch(target):
        return target
    if "://" not in target:
        if "%" in target:
            return "[unavailable]"
        try:
            ip_network(target, strict=False)
        except ValueError:
            return "[unavailable]"
        return target

    try:
        parsed = urlsplit(target)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return "[unavailable]"
    if parsed.scheme not in {"http", "https"} or host is None:
        return "[unavailable]"
    if ":" in host:
        # IPv6 literals are validated by urlsplit. Avoid displaying zone IDs.
        if "%" in host:
            return "[unavailable]"
        host = f"[{host}]"
    elif not _DISPLAY_HOST.fullmatch(host):
        return "[unavailable]"
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")


def summarize_pending_proposal(
    nonce: str, *, target: str, profile: str, mission_id: str | None, expires_at: float,
) -> PendingProposalSummary:
    # The listing ID must never be accepted as the original approval nonce.
    display_id = sha256(f"pending-proposal-display\0{nonce}".encode()).hexdigest()
    return {
        "proposal_id": f"review-{display_id}",
        "target": _display_target(target),
        "profile": profile,
        "mission_id": mission_id,
        "expires_at": expires_at,
        # The process-local record has no saved policy review or conversation binding.
        "review": None,
        "conversation_id": "",
    }
