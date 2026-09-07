"""Vulnerability evidence sections 21-25: race conditions, business logic,
SSTI, cache security, CORS.

Verbatim relocation from the original build_from_evidence method. Behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addRaceConditions(graph, get_items, resolve_lh):
    """Section 21: Race Condition & Concurrency Vulnerabilities."""
    # 21. Race Condition & Concurrency Vulnerabilities
    for ev in get_items(
        "race_condition",
        "race_conditions",
        "limit_overrun",
        "toctou",
        "concurrency",
        "concurrency_limit",
        "session_concurrency",
        "multi_redemption",
    ):
        target_url = ev.metadata.get("url") or ev.value
        parsed_url = urllib.parse.urlparse(target_url) if target_url else None
        base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
        template_id = ev.metadata.get("template_id") or "race-conditions"
        param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
        vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "race_condition"
        vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
        vuln_name = ev.title or f"Race Condition ({vuln_type})"
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



def addBusinessLogic(graph, get_items, resolve_lh):
    """Section 22: Business Logic Flaws & State Machine Security Vulnerabilities."""
    # 22. Business Logic Flaws & State Machine Security Vulnerabilities
    for ev in get_items(
        "business_logic",
        "business_logic_flaws",
        "business_logic_security",
        "state_machine",
        "state_machine_security",
        "price_tampering",
        "quantity_tampering",
        "parameter_tampering",
        "workflow_bypass",
        "workflow_skip",
        "workflow_step_skip",
        "mass_assignment",
        "coupon_stacking",
        "idempotency_abuse",
        "differential_state_verification",
        "differential_state",
    ):
        target_url = ev.metadata.get("url") or ev.value
        parsed_url = urllib.parse.urlparse(target_url) if target_url else None
        base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
        template_id = ev.metadata.get("template_id") or "business-logic"
        param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
        vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "business_logic"
        vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
        vuln_name = ev.title or f"Business Logic Vulnerability ({vuln_type})"
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



def addSsti(graph, get_items, resolve_lh):
    """Section 23: Server-Side Template Injection (SSTI) Vulnerabilities."""
    # 23. Server-Side Template Injection (SSTI) Vulnerabilities
    for ev in get_items(
            "ssti",
            "server_side_template_injection",
            "template_injection",
            "ssti_rce",
            "ssti_blind",
            "ssti_error",
            "jinja2",
            "twig",
            "freemarker",
            "velocity",
            "mako",
            "spel",
            "thymeleaf",
            "erb",
            "smarty",
            "pug",
            "ejs",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "ssti"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
            engine = ev.metadata.get("engine") or ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "template_injection"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Server-Side Template Injection ({engine})"
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



def addCacheSecurity(graph, get_items, resolve_lh):
    """Section 24: Web Cache Poisoning & Cache Deception Vulnerabilities."""
    # 24. Web Cache Poisoning & Cache Deception Vulnerabilities
    for ev in get_items(
            "cache_security",
            "cache_poisoning",
            "web_cache_poisoning",
            "cache_deception",
            "web_cache_deception",
            "unkeyed_header_poisoning",
            "unkeyed_param_poisoning",
            "unkeyed_query_poisoning",
            "parameter_cloaking",
            "cache_key_normalization",
            "fat_get_poisoning",
            "method_override_poisoning",
            "wcd",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "web-cache-poisoning"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "cache_security"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Web Cache Security ({vuln_type})"
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

