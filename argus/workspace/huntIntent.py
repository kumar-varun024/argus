"""Deterministic hunt-intent parser for the workspace chat.

Turns a free-text chat message into a structured HuntRequest ONLY when the
message is an unambiguous command to hunt a concrete target. This is
intentionally deterministic (no LLM): the target extracted here is what the
executor will scan, so it must not be model-controlled. Even so, it is not
the authorization boundary -- argus.authorization.gate re-verifies the target
against mission scope before anything runs (defense in depth).

Precision over recall: a hunt VERB plus a concrete TARGET must both be
present, and interrogative phrasing ("what did the scan of X find?") is
treated as a read, not a command, to avoid spurious approval cards.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

HUNT_ACTION: str = "hunt"
DEFAULT_PROFILE: str = "recon"
VALID_PROFILES: Tuple[str, ...] = ("quick", "recon", "vuln", "full")

# Verb -> the message must contain at least one of these to be a hunt command.
HUNT_VERBS: Tuple[str, ...] = (
    "hunt", "scan", "recon", "enumerate", "pentest", "pen test",
    "assess", "probe", "attack", "exploit", "fuzz",
)

# Sentence-opening interrogatives that reliably signal a READ (a question),
# not a command. Deliberately narrow: ambiguous leads like "do/can/could/would"
# also begin polite commands ("can you scan X", "do a full pentest"), so they
# are excluded -- a missed question only yields a deniable approval card.
QUESTION_LEADS: Tuple[str, ...] = (
    "what", "why", "how", "when", "where", "which", "who", "did", "does",
)

# Profile keyword -> canonical profile, checked in this priority order.
PROFILE_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("quick", "quick"), ("fast", "quick"),
    ("full", "full"), ("complete", "full"), ("thorough", "full"), ("deep", "full"), ("everything", "full"),
    ("vulnerability", "vuln"), ("vulnerabilities", "vuln"), ("vuln", "vuln"), ("cve", "vuln"),
    ("recon", "recon"), ("reconnaissance", "recon"), ("discovery", "recon"), ("enumerate", "recon"),
)

_URL_PATTERN = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b")
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)


@dataclass(frozen=True)
class HuntRequest:
    """A parsed, actionable request to launch a hunt against one target."""

    action: str
    target: str
    profile: str
    raw_message: str


def _looksLikeQuestion(lowered: str) -> bool:
    # Only a TRAILING '?' marks a question -- a '?' mid-message is almost always
    # a URL query string (…/login?next=1), not interrogation.
    stripped = lowered.strip()
    if stripped.endswith("?"):
        return True
    return any(stripped.startswith(lead + " ") for lead in QUESTION_LEADS)


def _hasHuntVerb(lowered: str) -> bool:
    return any(verb in lowered for verb in HUNT_VERBS)


def _extractTarget(message: str) -> Optional[str]:
    """First URL, else first IPv4/CIDR, else first bare domain. Deterministic."""
    url_match = _URL_PATTERN.search(message)
    if url_match:
        return url_match.group(0).rstrip(".,;)")
    ip_match = _IPV4_PATTERN.search(message)
    if ip_match:
        return ip_match.group(0)
    domain_match = _DOMAIN_PATTERN.search(message)
    if domain_match:
        return domain_match.group(0)
    return None


def _extractProfile(lowered: str) -> str:
    for keyword, profile in PROFILE_KEYWORDS:
        if keyword in lowered:
            return profile
    return DEFAULT_PROFILE


def parseHuntRequest(message: str) -> Optional[HuntRequest]:
    """Return a HuntRequest iff `message` is a command to hunt a concrete
    target; otherwise None (the message is handled as normal chat)."""
    if not message or not message.strip():
        return None
    lowered = message.lower()
    if _looksLikeQuestion(lowered):
        return None
    if not _hasHuntVerb(lowered):
        return None
    target = _extractTarget(message)
    if not target:
        return None
    return HuntRequest(
        action=HUNT_ACTION,
        target=target,
        profile=_extractProfile(lowered),
        raw_message=message,
    )
