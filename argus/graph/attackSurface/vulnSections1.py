"""Vulnerability evidence sections 6-10: generic vulnerability, subdomain
takeover, information disclosure, broken access control, path traversal.

Verbatim relocation from the original build_from_evidence method. Behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addGenericVulnerabilities(graph, get_items, resolve_lh):
    """Section 6: Vulnerabilities."""
    # 6. Vulnerabilities
    for ev in get_items("vulnerability"):
        if getattr(ev, "category", None) == "vulnerability":
            vuln_name = ev.metadata.get("template_id") or ev.metadata.get("name") or ev.value
            vuln_id = f"vulnerability:{vuln_name}"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "template_id" not in vuln_meta and ev.metadata.get("template_id"):
                vuln_meta["template_id"] = ev.metadata.get("template_id")
            if "severity" not in vuln_meta and getattr(ev, "severity", None):
                vuln_meta["severity"] = ev.severity

            graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

            # Link Live Host -> Vulnerability
            vuln_host = ev.metadata.get("host") or ev.metadata.get("matched_at")
            lh_node = resolve_lh(target_url_val=vuln_host, host_val=vuln_host)
            if lh_node:
                graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")


def addSubdomainTakeover(graph, get_items, target):
    """Section 7: Subdomain Takeover Vulnerabilities."""
    # 7. Subdomain Takeover Vulnerabilities
    for ev in get_items("subdomain_takeover"):
            subdomain = ev.metadata.get("subdomain") or ev.metadata.get("host") or ev.value
            cname = ev.metadata.get("cname")
            service = ev.metadata.get("service") or "Unknown"
            template_id = ev.metadata.get("template_id") or f"subdomain-takeover-{service.lower().replace(' ', '-')}"
            vuln_id = f"vulnerability:{template_id}:{subdomain}" if subdomain else f"vulnerability:{template_id}"
            vuln_name = ev.title or f"Subdomain Takeover ({service})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "critical") or "critical"

            graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

            if subdomain:
                sub_id = f"subdomain:{subdomain}"
                if sub_id not in graph.nodes:
                    graph.add(Node(id=sub_id, type="subdomain", value=subdomain, metadata={"hostname": subdomain}))
                    if target:
                        graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")
                graph.connect(sub_id, vuln_id, edge_type="HAS_VULNERABILITY")

            if cname:
                cname_id = f"cname:{cname}"
                graph.add(Node(id=cname_id, type="cname", value=cname, metadata={"cname": cname, "service": service}))
                if subdomain:
                    graph.connect(f"subdomain:{subdomain}", cname_id, edge_type="POINTS_TO_CNAME")


def addInformationDisclosure(graph, get_items, target):
    """Section 8: Information Disclosure Vulnerabilities."""
    # 8. Information Disclosure Vulnerabilities
    for ev in get_items("information_disclosure"):
            target_url = ev.metadata.get("url") or ev.value
            base_url = ev.metadata.get("host") or target_url
            template_id = ev.metadata.get("template_id") or "info-disclosure"
            path = ev.metadata.get("path") or ""
            vuln_id = f"vulnerability:{template_id}:{target_url}"
            vuln_name = ev.title or f"Information Disclosure ({path})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "high") or "high"

            ep_id = f"endpoint:{target_url}"
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

            # Link live host to endpoint & vulnerability
            lh_node = None
            if base_url:
                lh_node = graph.get(f"live_host:{base_url}")
                if not lh_node:
                    for n in graph.nodes_by_type("live_host"):
                        if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                            lh_node = n
                            break
            if not lh_node:
                live_hosts = graph.nodes_by_type("live_host")
                if len(live_hosts) == 1:
                    lh_node = live_hosts[0]

            if lh_node:
                graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

            # Secrets
            for idx, sec in enumerate(ev.metadata.get("secrets", [])):
                sec_type = sec.get("type", "secret") if isinstance(sec, dict) else "secret"
                sec_val = sec.get("value", str(sec)) if isinstance(sec, dict) else str(sec)
                sec_id = f"secret:{sec_type}:{idx}:{target_url}"
                graph.add(Node(id=sec_id, type="secret", value=sec_val, metadata=sec if isinstance(sec, dict) else {"value": sec_val}))
                graph.connect(vuln_id, sec_id, edge_type="EXPOSES_SECRET")

            # Internal Subdomains
            for domain in ev.metadata.get("internal_domains", []):
                sub_id = f"subdomain:{domain}"
                if sub_id not in graph.nodes:
                    graph.add(Node(id=sub_id, type="subdomain", value=domain, metadata={"hostname": domain, "source": target_url}))
                    if target:
                        graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")
                graph.connect(vuln_id, sub_id, edge_type="DISCLOSED_SUBDOMAIN")


def addBrokenAccessControl(graph, get_items, resolve_lh):
    """Section 9: Broken Access Control / IDOR Vulnerabilities."""
    # 9. Broken Access Control / IDOR Vulnerabilities
    for ev in get_items("broken_access_control"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "broken-access-control"
            vuln_id = f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}"
            vuln_name = ev.title or "Broken Access Control (IDOR)"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "critical") or "critical"

            ep_id = f"endpoint:{target_url}" if target_url else None
            if ep_id and ep_id not in graph.nodes:
                graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url}))

            graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

            # Link live host to endpoint & vulnerability
            lh_node = resolve_lh(target_url_val=target_url, host_val=base_url)
            if not lh_node and base_url:
                lh_id = f"live_host:{base_url}"
                if lh_id not in graph.nodes:
                    parsed_b = urllib.parse.urlparse(base_url)
                    graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                lh_node = graph.get(lh_id)

            if lh_node:
                if ep_id:
                    graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
            if ep_id:
                graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")



def addPathTraversal(graph, get_items, resolve_lh):
    """Section 10: Path Traversal Vulnerabilities."""
    # 10. Path Traversal Vulnerabilities
    for ev in get_items("path_traversal"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "path-traversal"
            vuln_id = f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}"
            vuln_name = ev.title or "Path Traversal"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "critical") or "critical"

            ep_id = f"endpoint:{target_url}" if target_url else None
            if ep_id and ep_id not in graph.nodes:
                graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))

            graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

            # Link live host to endpoint & vulnerability
            lh_node = resolve_lh(target_url_val=target_url, host_val=base_url)
            if not lh_node and base_url:
                lh_id = f"live_host:{base_url}"
                if lh_id not in graph.nodes:
                    parsed_b = urllib.parse.urlparse(base_url)
                    graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                lh_node = graph.get(lh_id)

            if lh_node:
                if ep_id:
                    graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
            if ep_id:
                graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

