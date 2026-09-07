"""build() orchestrator: ingests structured Mission attributes directly
(subdomains/live_hosts/technologies/endpoints/vulnerabilities), bypassing the
evidence store. Verbatim relocation of attack_surface.py's former build()
method (lines 1303-1481), split into one function per ingestion block for
the 40-line function limit. Behavior pinned by
tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node


def _ingestMissionSubdomains(mission: Any, graph: KnowledgeGraph, target: str) -> None:
    # Subdomains
    for sub in getattr(mission, "subdomains", []) or []:
        hostname = sub.get("hostname") if isinstance(sub, dict) else str(sub)
        if hostname:
            sub_id = f"subdomain:{hostname}"
            sub_meta = sub if isinstance(sub, dict) else {"hostname": hostname}
            graph.add(Node(id=sub_id, type="subdomain", value=hostname, metadata=sub_meta))
            if target:
                graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")


def _ingestMissionLiveHosts(mission: Any, graph: KnowledgeGraph, target: str) -> None:
    # Live hosts
    for h in getattr(mission, "live_hosts", []) or []:
        if isinstance(h, dict):
            url = h.get("url") or h.get("host") or ""
            host = h.get("host")
            if not host and url:
                host = urllib.parse.urlparse(url).hostname or url
            meta = dict(h)
        else:
            url = str(h)
            host = urllib.parse.urlparse(url).hostname or url
            meta = {"url": url, "host": host}

        lh_id = f"live_host:{url}" if url else f"live_host:{host}"
        lh_val = url if url else host
        graph.add(Node(id=lh_id, type="live_host", value=lh_val, metadata=meta))

        if host:
            sub_id = f"subdomain:{host}"
            if sub_id not in graph.nodes:
                graph.add(Node(id=sub_id, type="subdomain", value=host, metadata={"hostname": host}))
                if target:
                    graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")
            graph.connect(sub_id, lh_id, edge_type="HOSTS")
        elif target:
            target_sub_id = f"subdomain:{target}"
            if target_sub_id in graph.nodes:
                graph.connect(target_sub_id, lh_id, edge_type="HOSTS")
            else:
                graph.connect(f"target:{target}", lh_id, edge_type="HOSTS")

        for tech in meta.get("technologies", []):
            if tech:
                tech_name = str(tech).strip()
                tech_id = f"technology:{tech_name}"
                graph.add(Node(id=tech_id, type="technology", value=tech_name, metadata={"name": tech_name}))
                graph.connect(lh_id, tech_id, edge_type="RUNS_TECHNOLOGY")


def _ingestMissionTechnologies(mission: Any, graph: KnowledgeGraph) -> None:
    # Technologies
    for t in getattr(mission, "technologies", []) or []:
        tech_name = t.get("name") if isinstance(t, dict) else str(t)
        if tech_name:
            tech_name = str(tech_name).strip()
            tech_id = f"technology:{tech_name}"
            graph.add(Node(id=tech_id, type="technology", value=tech_name, metadata={"name": tech_name}))
            live_hosts = graph.nodes_by_type("live_host")
            if len(live_hosts) == 1:
                graph.connect(live_hosts[0].id, tech_id, edge_type="RUNS_TECHNOLOGY")


def _ingestMissionEndpoints(mission: Any, graph: KnowledgeGraph) -> None:
    # Endpoints
    for ep in getattr(mission, "endpoints", []) or []:
        if isinstance(ep, dict):
            ep_url = ep.get("url") or ep.get("path") or ""
            ep_host = ep.get("host")
            meta = dict(ep)
        else:
            ep_url = str(ep)
            ep_host = urllib.parse.urlparse(ep_url).hostname
            meta = {"url": ep_url, "host": ep_host}

        if ep_url:
            ep_id = f"endpoint:{ep_url}"
            graph.add(Node(id=ep_id, type="endpoint", value=ep_url, metadata=meta))

            lh_node = None
            for n in graph.nodes_by_type("live_host"):
                lh_url = n.metadata.get("url") or n.value
                if lh_url and ep_url.startswith(lh_url):
                    lh_node = n
                    break
            if not lh_node and ep_host:
                for n in graph.nodes_by_type("live_host"):
                    if n.metadata.get("host") == ep_host or n.value == ep_host:
                        lh_node = n
                        break
            if not lh_node:
                live_hosts = graph.nodes_by_type("live_host")
                if len(live_hosts) == 1:
                    lh_node = live_hosts[0]
            if lh_node:
                graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")


def _ingestMissionVulnerabilities(mission: Any, graph: KnowledgeGraph) -> None:
    # Vulnerabilities
    for vuln in getattr(mission, "vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            vuln_name = vuln.get("template_id") or vuln.get("name") or "Vulnerability"
            meta = dict(vuln)
        else:
            vuln_name = str(vuln)
            meta = {"name": vuln_name}

        url = meta.get("url")
        vuln_id = f"vulnerability:{vuln_name}:{url}" if url else f"vulnerability:{vuln_name}"
        graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=meta))

        lh_node = None
        vuln_host = meta.get("host") or meta.get("matched_at") or meta.get("subdomain")
        cname = meta.get("cname")
        service = meta.get("service")

        if vuln_host:
            sub_id = f"subdomain:{vuln_host}"
            if sub_id in graph.nodes:
                graph.connect(sub_id, vuln_id, edge_type="HAS_VULNERABILITY")
            if cname:
                cname_id = f"cname:{cname}"
                graph.add(Node(id=cname_id, type="cname", value=cname, metadata={"cname": cname, "service": service or ""}))
                if sub_id in graph.nodes:
                    graph.connect(sub_id, cname_id, edge_type="POINTS_TO_CNAME")

            for n in graph.nodes_by_type("live_host"):
                lh_url = n.metadata.get("url") or n.value
                if lh_url and (vuln_host.startswith(lh_url) or lh_url.startswith(vuln_host) or n.metadata.get("host") == vuln_host):
                    lh_node = n
                    break
            if not lh_node:
                parsed_vhost = urllib.parse.urlparse(vuln_host).hostname or vuln_host
                for n in graph.nodes_by_type("live_host"):
                    if n.metadata.get("host") == parsed_vhost or parsed_vhost in n.value:
                        lh_node = n
                        break
        if not lh_node:
            live_hosts = graph.nodes_by_type("live_host")
            if len(live_hosts) == 1:
                lh_node = live_hosts[0]
        if lh_node:
            graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")

        if meta.get("url"):
            ep_url = meta.get("url")
            ep_id = f"endpoint:{ep_url}"
            if ep_id in graph.nodes:
                graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")


def buildFromMission(builder: Any, mission: Any) -> KnowledgeGraph:
    """
    Builds and populates a KnowledgeGraph directly from a Mission instance.

    Args:
        builder: The AttackSurfaceGraphBuilder instance (dispatches through
            builder.build_from_evidence, mirroring the original method's
            self.build_from_evidence(...) call).
        mission: The Mission object to build from.

    Returns:
        KnowledgeGraph: The populated graph attached to mission.attack_surface_graph.
    """
    target = getattr(mission, "target", "") or ""
    graph = getattr(mission, "attack_surface_graph", None)
    if graph is None:
        graph = getattr(mission, "graph", None)
    if graph is None:
        graph = KnowledgeGraph()

    # 1. Build from evidence store if available
    evidence = getattr(mission, "evidence", None)
    if evidence is not None and hasattr(evidence, "all"):
        builder.build_from_evidence(evidence, target=target, graph=graph)

    # 2. Ingest structured attributes from mission (handles missions populated without evidence store)
    if target:
        target_id = f"target:{target}"
        graph.add(Node(id=target_id, type="target", value=target, metadata={"target": target}))

    _ingestMissionSubdomains(mission, graph, target)
    _ingestMissionLiveHosts(mission, graph, target)
    _ingestMissionTechnologies(mission, graph)
    _ingestMissionEndpoints(mission, graph)
    _ingestMissionVulnerabilities(mission, graph)

    # Attach to mission
    try:
        mission.attack_surface_graph = graph
        mission.graph = graph
    except Exception:
        pass

    return graph
