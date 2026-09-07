"""Shared outcome type and helpers for the gap-template rule tables.

An outcome is one of:
  ("recon", <key into _RECON_TEMPLATES>)
  ("specialist", <TaskCategory>)
  ("dynamic", <handler(generator, gap, area_lower, desc_lower) -> template dict>)
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

from argus.planning.models import TaskCategory
from argus.planning.templates import _RECON_TEMPLATES, _SPECIALIST_TEMPLATES

Outcome = Tuple[str, Any]
KeywordRule = Tuple[frozenset, Outcome]


def recon(key: str) -> Outcome:
    return ("recon", key)


def specialist(category: TaskCategory) -> Outcome:
    return ("specialist", category)


def dynamic(handler: Callable) -> Outcome:
    return ("dynamic", handler)


def resolveOutcome(generator: Any, gap: Any, areaLower: str, descLower: str, outcome: Outcome) -> Dict[str, Any]:
    """Turn a rule outcome into a concrete template dict."""
    kind, payload = outcome
    if kind == "recon":
        return _RECON_TEMPLATES[payload]
    if kind == "specialist":
        return _SPECIALIST_TEMPLATES[payload]
    return payload(generator, gap, areaLower, descLower)


def firstKeywordOutcome(descLower: str, ladder: Tuple[KeywordRule, ...], default: Outcome) -> Outcome:
    """First-match-wins over a keyword ladder; ladder order is semantically load-bearing."""
    for keywords, outcome in ladder:
        if any(keyword in descLower for keyword in keywords):
            return outcome
    return default
