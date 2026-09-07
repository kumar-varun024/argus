"""Shared lookup helpers used across build_from_evidence's sections.

Verbatim relocation of the original method's category index, get_items
closure, live-host index, and resolve_lh closure (attack_surface.py, former
lines 45-58 and 118-172) -- turned into factory functions so each extracted
section can receive the same behavior via an explicit parameter instead of
a shared closure. Behavior pinned by
tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from argus.graph.node import Node


def buildCategoryIndex(evidenceItems: List[Any]) -> Dict[str, List[Any]]:
    by_cat: dict[str, list[Any]] = {}
    for ev in evidenceItems:
        cat = getattr(ev, "category", None)
        if cat is not None:
            by_cat.setdefault(str(cat), []).append(ev)
    return by_cat


def makeGetItems(by_cat: Dict[str, List[Any]]) -> Callable[..., List[Any]]:
    def get_items(*categories: str) -> list[Any]:
        res: list[Any] = []
        for c in categories:
            items = by_cat.get(c)
            if items:
                res.extend(items)
        return res
    return get_items


def buildLiveHostIndex(graph) -> Tuple[List[Node], Dict[str, Node], Dict[str, Node]]:
    # Fast lookup indexes for live hosts
    live_hosts_list = graph.nodes_by_type("live_host")
    lh_by_url: dict[str, Node] = {}
    lh_by_host: dict[str, Node] = {}
    for lh in live_hosts_list:
        lh_val = lh.value
        lh_url = lh.metadata.get("url") or lh_val
        lh_host = lh.metadata.get("host")
        if lh_url:
            lh_by_url[lh_url] = lh
            lh_by_url[lh_url.rstrip("/")] = lh
        if lh_host:
            lh_by_host[lh_host] = lh
        if lh_val:
            lh_by_url[lh_val] = lh
            lh_by_host[lh_val] = lh
    return live_hosts_list, lh_by_url, lh_by_host


def makeResolveLiveHost(
    live_hosts_list: List[Node], lh_by_url: Dict[str, Node], lh_by_host: Dict[str, Node],
) -> Callable[..., Optional[Node]]:
    def resolve_lh(target_url_val: Optional[str] = None, host_val: Optional[str] = None) -> Optional[Node]:
        if target_url_val:
            if target_url_val in lh_by_url:
                return lh_by_url[target_url_val]
            t_rstrip = target_url_val.rstrip("/")
            if t_rstrip in lh_by_url:
                return lh_by_url[t_rstrip]
            if target_url_val in lh_by_host:
                return lh_by_host[target_url_val]
            parsed = urllib.parse.urlparse(target_url_val)
            if parsed.scheme and parsed.netloc:
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base in lh_by_url:
                    return lh_by_url[base]
            if parsed.netloc and parsed.netloc in lh_by_host:
                return lh_by_host[parsed.netloc]
            if parsed.hostname and parsed.hostname in lh_by_host:
                return lh_by_host[parsed.hostname]
            for n in live_hosts_list:
                u = n.metadata.get("url") or n.value
                if u and (target_url_val.startswith(u) or u.startswith(target_url_val)):
                    return n

        if host_val:
            if host_val in lh_by_host:
                return lh_by_host[host_val]
            if host_val in lh_by_url:
                return lh_by_url[host_val]
            parsed_h = urllib.parse.urlparse(host_val).hostname or host_val
            if parsed_h in lh_by_host:
                return lh_by_host[parsed_h]
            for n in live_hosts_list:
                if n.metadata.get("host") == host_val or n.value == host_val or n.metadata.get("host") == parsed_h or parsed_h in n.value:
                    return n

        if len(live_hosts_list) == 1:
            return live_hosts_list[0]
        return None
    return resolve_lh
