"""Priority-chain regression test for GenericVulnRule + the 20-entry config
table (argus/graph/attackSurface/genericVulnRules.py).

Unlike test_attack_surface_characterization.py (which pins observable
behavior against a frozen snapshot), this test validates an internal
consistency property of the *current* implementation: that
addGenericVulnRule actually honors each rule's declared param_keys/
detail_keys priority order (first-truthy-key wins) and defaults. It exists
because the config table was hand-transcribed from 20 originally-duplicated
per-section functions (see git history prior to the Stage 2 DRY
unification) -- a wrong key order for e.g. CORS's 3-key param_keys would
not necessarily be caught by the broad-sweep characterization scenarios,
which only ever set one key at a time.

Verified once at unification time by comparing this same priority-chain
sweep (122 scenarios) against the original per-section functions pulled
from git history: 122/122 matched. That comparison isn't repeatable going
forward (the old functions are gone), so this test instead pins the
CURRENT correct behavior directly.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.attackSurface.genericVulnRule import GenericVulnRule, addGenericVulnRule
from argus.graph.attackSurface.genericVulnRules import GENERIC_VULN_RULES_PART1, GENERIC_VULN_RULES_PART2
from argus.graph.attackSurface.lookupHelpers import buildCategoryIndex, buildLiveHostIndex, makeGetItems, makeResolveLiveHost
from argus.graph.graph import KnowledgeGraph

ALL_RULES: Tuple[GenericVulnRule, ...] = tuple(GENERIC_VULN_RULES_PART1) + tuple(GENERIC_VULN_RULES_PART2)
BASE_URL = "https://priority-chain.example.com/path"


def _runRule(rule: GenericVulnRule, metadata: Dict[str, Any]):
    # severity="" (not the Evidence dataclass's "info" default): Evidence
    # always has a severity attribute, so getattr(ev, "severity", X) never
    # falls through to X -- only "ev.severity or X" does, and only when
    # ev.severity itself is falsy. This is what actually exercises
    # rule.default_severity below.
    graph = KnowledgeGraph()
    store = EvidenceStore()
    store.add(Evidence(category=rule.categories[0], value="", metadata=metadata, severity=""))
    byCat = buildCategoryIndex(store.all())
    getItems = makeGetItems(byCat)
    liveHostsList, lhByUrl, lhByHost = buildLiveHostIndex(graph)
    resolveLh = makeResolveLiveHost(liveHostsList, lhByUrl, lhByHost)
    addGenericVulnRule(graph, getItems, resolveLh, rule)
    vulnNodes = [n for n in graph.nodes.values() if n.type == "vulnerability"]
    assert len(vulnNodes) == 1, f"expected exactly one vulnerability node, got {len(vulnNodes)}"
    return vulnNodes[0]


def _dropoutScenarios(keys: Tuple[str, ...]) -> List[Tuple[str, Dict[str, str], str]]:
    """(scenarioName, metadata, expectedWinningValue) for each dropout depth."""
    scenarios = []
    for depth in range(len(keys)):
        metadata = {"url": BASE_URL}
        for i in range(depth, len(keys)):
            metadata[keys[i]] = f"sentinel_{keys[i]}_{i}"
        scenarios.append((f"depth_{depth}", metadata, f"sentinel_{keys[depth]}_{depth}"))
    return scenarios


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: f"section{r.section_num}")
def test_param_priority_chain(rule: GenericVulnRule):
    """For rules with 2+ param_keys, the highest-priority present key wins."""
    if not rule.has_param or len(rule.param_keys) < 2:
        pytest.skip("single or no param key -- nothing to order")
    for scenarioName, metadata, expectedWinner in _dropoutScenarios(rule.param_keys):
        node = _runRule(rule, metadata)
        assert expectedWinner in node.id, (
            f"section {rule.section_num} {scenarioName}: expected '{expectedWinner}' in vuln_id, got {node.id!r}"
        )


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: f"section{r.section_num}")
def test_detail_priority_chain(rule: GenericVulnRule):
    """For rules with 2+ detail_keys, the highest-priority present key wins
    and appears in vuln_name."""
    if len(rule.detail_keys) < 2:
        pytest.skip("single or no detail key -- nothing to order")
    for scenarioName, metadata, expectedWinner in _dropoutScenarios(rule.detail_keys):
        node = _runRule(rule, metadata)
        assert expectedWinner in node.value, (
            f"section {rule.section_num} {scenarioName}: expected '{expectedWinner}' in vuln_name, got {node.value!r}"
        )


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: f"section{r.section_num}")
def test_defaults_when_no_optional_keys_present(rule: GenericVulnRule):
    """With no param_keys/detail_keys set, template_id/severity/name defaults apply."""
    node = _runRule(rule, {"url": BASE_URL})
    assert rule.template_id_default in node.id
    assert node.metadata["severity"] == rule.default_severity
    if rule.detail_keys:
        assert rule.detail_default in node.value
    else:
        assert node.value == rule.name_template
    if rule.has_param:
        # No param present -> vuln_id must fall back to the 2-part (template_id:url) form.
        assert node.id == f"vulnerability:{rule.template_id_default}:{BASE_URL}"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: f"section{r.section_num}")
def test_endpoint_status_code_flag(rule: GenericVulnRule):
    """endpoint_includes_status_code controls whether the endpoint node's
    metadata carries a "status_code" key (only section 9 omits it)."""
    graph = KnowledgeGraph()
    store = EvidenceStore()
    store.add(Evidence(category=rule.categories[0], value="", metadata={"url": BASE_URL}, severity="info"))
    byCat = buildCategoryIndex(store.all())
    getItems = makeGetItems(byCat)
    liveHostsList, lhByUrl, lhByHost = buildLiveHostIndex(graph)
    resolveLh = makeResolveLiveHost(liveHostsList, lhByUrl, lhByHost)
    addGenericVulnRule(graph, getItems, resolveLh, rule)
    endpointNodes = [n for n in graph.nodes.values() if n.type == "endpoint"]
    assert len(endpointNodes) == 1
    assert ("status_code" in endpointNodes[0].metadata) == rule.endpoint_includes_status_code
