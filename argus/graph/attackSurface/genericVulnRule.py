"""Generic vulnerability-block processor: the shared shape behind 20 of the
21 near-duplicate vulnerability sections in the original build_from_evidence
method (sections 9,10,11,13-29; section 12/XSS keeps its own hand-written
function in bespokeVulnSections.py for its severity-mapping quirk).

Each of those 20 sections was a byte-for-byte copy of the same 8-step
sequence -- derive target_url/base_url, build vuln_id/vuln_name/vuln_meta,
ensure an endpoint node, ensure a vulnerability node, resolve-or-create a
live_host, connect three edge types -- varying only in: the get_items
category list, the template_id default, which metadata keys feed the
"param" component of vuln_id (some sections skip this entirely -- see
GenericVulnRule.has_param), which metadata keys feed the descriptive
"detail" embedded in vuln_name (some sections have no detail at all -- a
static name), the default severity, and whether the endpoint node's
metadata includes "status_code" (every section does except #9).

Behavior pinned by tests/graph/test_attack_surface_characterization.py --
the same 45-scenario oracle used for the Stage 1 mechanical extraction,
reused here since a config-table bug would show up as a graph diff exactly
the same way a relocation bug would.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from argus.graph.node import Node


@dataclass(frozen=True)
class GenericVulnRule:
    """One vulnerability section's configuration.

    has_param=False means the section never computes a "param" component at
    all (vuln_id is only ever template_id[:target_url]) -- sections 9 and 10
    are the only two like this; every other section has at least
    param_keys=("parameter",).

    detail_keys=() means the section has a static vuln_name with no dynamic
    suffix (sections 9, 10, 11) -- name_template is used as-is. Otherwise
    name_template must contain a literal "{detail}" placeholder.
    """

    section_num: int
    categories: Tuple[str, ...]
    template_id_default: str
    has_param: bool
    param_keys: Tuple[str, ...]
    detail_keys: Tuple[str, ...]
    detail_default: str
    name_template: str
    default_severity: str
    endpoint_includes_status_code: bool = True


def _firstMetadataValue(ev: Any, keys: Tuple[str, ...]) -> Optional[str]:
    for key in keys:
        value = ev.metadata.get(key)
        if value:
            return value
    return None


def _buildVulnId(templateId: str, targetUrl: Optional[str], paramValue: Optional[str], hasParam: bool) -> str:
    if hasParam and targetUrl and paramValue:
        return f"vulnerability:{templateId}:{targetUrl}:{paramValue}"
    if targetUrl:
        return f"vulnerability:{templateId}:{targetUrl}"
    return f"vulnerability:{templateId}"


def _buildVulnName(ev: Any, rule: GenericVulnRule) -> str:
    if not rule.detail_keys:
        return ev.title or rule.name_template
    detail = _firstMetadataValue(ev, rule.detail_keys) or rule.detail_default
    return ev.title or rule.name_template.format(detail=detail)


def _resolveOrCreateLiveHost(graph, resolve_lh, target_url: Optional[str], base_url: Optional[str]):
    lh_node = resolve_lh(target_url_val=target_url, host_val=base_url)
    if not lh_node and base_url:
        lh_id = f"live_host:{base_url}"
        if lh_id not in graph.nodes:
            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
        lh_node = graph.get(lh_id)
    return lh_node


def addGenericVulnRule(graph, get_items, resolve_lh, rule: GenericVulnRule) -> None:
    """Process one GenericVulnRule -- the shared body of sections 9,10,11,13-29."""
    for ev in get_items(*rule.categories):
        target_url = ev.metadata.get("url") or ev.value
        parsed_url = urllib.parse.urlparse(target_url) if target_url else None
        base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
        template_id = ev.metadata.get("template_id") or rule.template_id_default
        param_value = _firstMetadataValue(ev, rule.param_keys) if rule.has_param else None

        vuln_id = _buildVulnId(template_id, target_url, param_value, rule.has_param)
        vuln_name = _buildVulnName(ev, rule)
        vuln_meta = dict(ev.metadata) if ev.metadata else {}
        if "name" not in vuln_meta:
            vuln_meta["name"] = vuln_name
        if "severity" not in vuln_meta:
            vuln_meta["severity"] = getattr(ev, "severity", rule.default_severity) or rule.default_severity

        ep_id = f"endpoint:{target_url}" if target_url else None
        if ep_id and ep_id not in graph.nodes:
            ep_meta = {"url": target_url}
            if rule.endpoint_includes_status_code:
                ep_meta["status_code"] = ev.metadata.get("status_code", 200)
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata=ep_meta))

        graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

        lh_node = _resolveOrCreateLiveHost(graph, resolve_lh, target_url, base_url)
        if lh_node:
            if ep_id:
                graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
        if ep_id:
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
