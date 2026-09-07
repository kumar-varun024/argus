"""Vulnerability evidence sections 11-15: SQL injection, XSS, command
injection, SSRF, OAuth/OIDC.

Verbatim relocation from the original build_from_evidence method. Behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addSqlInjection(graph, get_items, resolve_lh):
    """Section 11: SQL Injection Vulnerabilities."""
    # 11. SQL Injection Vulnerabilities
    for ev in get_items("sql_injection"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "sqli"
            param_name = ev.metadata.get("parameter") or ""
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or "SQL Injection"
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



def addXss(graph, get_items, resolve_lh):
    """Section 12: Cross-Site Scripting (XSS) Vulnerabilities."""
    # 12. Cross-Site Scripting (XSS) Vulnerabilities
    for ev in get_items("xss", "cross_site_scripting"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "xss"
            param_name = ev.metadata.get("parameter") or ""
            xss_type = str(ev.metadata.get("xss_type", "reflected")).lower()

            # Map severity: Stored = critical, Reflected = high, DOM/Header = medium
            if "stored" in xss_type:
                default_sev = "critical"
            elif "dom" in xss_type or "header" in xss_type:
                default_sev = "medium"
            else:
                default_sev = "high"

            ev_sev = ev.metadata.get("severity") or getattr(ev, "severity", None)
            if not ev_sev or ev_sev == "info":
                vuln_sev = default_sev
            else:
                vuln_sev = ev_sev

            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Cross-Site Scripting ({xss_type.capitalize()})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta or vuln_meta["severity"] == "info":
                vuln_meta["severity"] = vuln_sev

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



def addCommandInjection(graph, get_items, resolve_lh):
    """Section 13: Command Injection (CMDi) Vulnerabilities."""
    # 13. Command Injection (CMDi) Vulnerabilities
    for ev in get_items("command_injection", "cmdi", "os_command_injection", "cmd_injection"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "cmdi"
            param_name = ev.metadata.get("parameter") or ""
            technique = ev.metadata.get("technique") or "result_based"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Command Injection ({technique})"
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



def addSsrf(graph, get_items, resolve_lh):
    """Section 14: Server-Side Request Forgery (SSRF) Vulnerabilities."""
    # 14. Server-Side Request Forgery (SSRF) Vulnerabilities
    for ev in get_items("ssrf", "server_side_request_forgery", "ssrf_validation"):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "ssrf"
            param_name = ev.metadata.get("parameter") or ""
            technique = ev.metadata.get("technique") or "cloud_metadata"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Server-Side Request Forgery ({technique})"
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



def addOauth(graph, get_items, resolve_lh):
    """Section 15: OAuth / OIDC Misconfigurations, Token Validation & Stateful Authentication Vulnerabilities."""
    # 15. OAuth / OIDC Misconfigurations, Token Validation & Stateful Authentication Vulnerabilities
    for ev in get_items(
            "oauth",
            "oidc",
            "oauth_oidc",
            "oauth_misconfiguration",
            "token_validation",
            "session_management",
            "authentication",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "oauth-misconfiguration"
            param_name = ev.metadata.get("parameter") or ""
            misconfig = ev.metadata.get("misconfiguration_type") or "authentication"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"OAuth / Stateful Auth Vulnerability ({misconfig})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "high") or "high"

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

