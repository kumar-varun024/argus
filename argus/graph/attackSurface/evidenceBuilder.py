"""build_from_evidence orchestrator: calls each extracted section in the
exact original order, threading graph/get_items/resolve_lh/target through.

Verbatim relocation of attack_surface.py's build_from_evidence (former lines
17-43, 297) plus the setup at lines 45-58. Behavior pinned by
tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

from typing import Optional

from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attackSurface.lookupHelpers import buildCategoryIndex, buildLiveHostIndex, makeGetItems, makeResolveLiveHost
from argus.graph.attackSurface.reconSections import addEndpoints, addLiveHosts, addSubdomains, addTechnologies
from argus.graph.attackSurface.bespokeVulnSections import (
    addGenericVulnerabilities, addInformationDisclosure, addSubdomainTakeover, addXss,
)
from argus.graph.attackSurface.genericVulnRule import addGenericVulnRule
from argus.graph.attackSurface.genericVulnRules import GENERIC_VULN_RULES_PART1, GENERIC_VULN_RULES_PART2


def buildFromEvidence(evidence: Optional[EvidenceStore], target: str = "", graph: Optional[KnowledgeGraph] = None) -> KnowledgeGraph:
    """
    Builds and populates a KnowledgeGraph from structured evidence records.

    Args:
        evidence: EvidenceStore containing discovered evidence.
        target: The root mission target.
        graph: Optional existing KnowledgeGraph to append to.

    Returns:
        KnowledgeGraph: The populated graph.
    """
    if graph is None:
        graph = KnowledgeGraph()

    # 1. Target Node
    if target:
        target_id = f"target:{target}"
        graph.add(Node(id=target_id, type="target", value=target, metadata={"target": target}))

    if evidence is None:
        return graph

    evidence_items = evidence.all() if hasattr(evidence, "all") else list(evidence)
    by_cat = buildCategoryIndex(evidence_items)
    get_items = makeGetItems(by_cat)

    addSubdomains(graph, get_items, target)
    addLiveHosts(graph, get_items, target)

    live_hosts_list, lh_by_url, lh_by_host = buildLiveHostIndex(graph)
    resolve_lh = makeResolveLiveHost(live_hosts_list, lh_by_url, lh_by_host)

    addTechnologies(graph, get_items, resolve_lh)
    addEndpoints(graph, get_items, resolve_lh)
    addGenericVulnerabilities(graph, get_items, resolve_lh)
    addSubdomainTakeover(graph, get_items, target)
    addInformationDisclosure(graph, get_items, target)

    # Sections 9,10,11, then bespoke XSS (12), then 13-29 -- split around XSS
    # to preserve the exact original section order (load-bearing: a later
    # section's live-host resolution can see a node an earlier one created).
    for rule in GENERIC_VULN_RULES_PART1:
        addGenericVulnRule(graph, get_items, resolve_lh, rule)
    addXss(graph, get_items, resolve_lh)
    for rule in GENERIC_VULN_RULES_PART2:
        addGenericVulnRule(graph, get_items, resolve_lh, rule)

    return graph
