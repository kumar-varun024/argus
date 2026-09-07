"""Ordered coverage-gap -> task-template resolution rules for TaskGenerator.

Extracted as data from the former 408-line if/elif chain in
TaskGenerator._resolve_template_for_gap. Split into:

  outcomeResolution.py - shared Outcome type + resolution helpers
  areaRules.py          - the ordered AREA_RULES table (order load-bearing)
  categoryFallback.py   - category-based fallback, incl. EVIDENCE_CORRELATION_LADDER
  resolver.py           - resolveTemplateForGap, the public entrypoint

Behavior preserved and pinned by
tests/planning/test_gap_template_rules_characterization.py.
"""
from argus.planning.gapTemplateRules.resolver import resolveTemplateForGap

__all__ = ["resolveTemplateForGap"]
