"""Entrypoint tying AREA_RULES and CATEGORY_FALLBACK_HANDLERS together.

Mirrors the original _resolve_template_for_gap method's exact control flow:
try every AREA_RULES entry in order (first match wins), then the
category-specific fallback handler if one exists for gap.category, then the
final default.
"""
from __future__ import annotations

from typing import Any, Dict

from argus.planning.models import TaskCategory
from argus.planning.templates import _SPECIALIST_TEMPLATES
from argus.planning.gapTemplateRules.areaRules import AREA_RULES
from argus.planning.gapTemplateRules.categoryFallback import CATEGORY_FALLBACK_HANDLERS
from argus.planning.gapTemplateRules.outcomeResolution import resolveOutcome


def resolveTemplateForGap(generator: Any, gap: Any) -> Dict[str, Any]:
    """Resolve the appropriate task template for a given CoverageGap."""
    areaLower = (gap.area or "").lower()
    descLower = (gap.description or "").lower()

    for aliases, outcome in AREA_RULES:
        if areaLower in aliases:
            return resolveOutcome(generator, gap, areaLower, descLower, outcome)

    handler = CATEGORY_FALLBACK_HANDLERS.get(gap.category)
    if handler is not None:
        return handler(generator, gap, areaLower, descLower)

    return _SPECIALIST_TEMPLATES.get(gap.category, _SPECIALIST_TEMPLATES[TaskCategory.COVERAGE_IMPROVEMENT])
