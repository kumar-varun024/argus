"""Vulnerability evidence sections 16-20: XXE, deserialization, GraphQL,
WebSocket, HTTP request smuggling.

Verbatim relocation from the original build_from_evidence method. Behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addXmlParserSecurity(graph, get_items, resolve_lh):
    """Section 16: XML Parser Security / XXE Vulnerabilities."""
    # 16. XML Parser Security / XXE Vulnerabilities
    for ev in get_items(
            "xml_parser_validation",
            "xxe",
            "xml_external_entity",
            "xml_parser",
            "xml_parser_security",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "xxe"
            param_name = ev.metadata.get("parameter") or ""
            technique = ev.metadata.get("technique") or "external_entity"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"XML Parser Misconfiguration ({technique})"
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



def addDeserialization(graph, get_items, resolve_lh):
    """Section 17: Insecure Deserialization Vulnerabilities."""
    # 17. Insecure Deserialization Vulnerabilities
    for ev in get_items(
            "deserialization",
            "insecure_deserialization",
            "unsafe_deserialization",
            "java_deserialization",
            "python_pickle",
            "php_unserialize",
            "ruby_marshal",
            "dotnet_viewstate",
            "dotnet_binary_formatter",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "deserialization"
            param_name = ev.metadata.get("parameter") or ""
            fmt = ev.metadata.get("format") or "deserialization"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Insecure Deserialization ({fmt})"
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



def addGraphqlSecurity(graph, get_items, resolve_lh):
    """Section 18: GraphQL Security Vulnerabilities."""
    # 18. GraphQL Security Vulnerabilities
    for ev in get_items(
            "graphql",
            "graphql_security",
            "graphql_introspection",
            "graphql_dos",
            "graphql_batching",
            "graphql_access_control",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "graphql-security"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "security_misconfiguration"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"GraphQL Security ({vuln_type})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "medium") or "medium"

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



def addWebsocketSecurity(graph, get_items, resolve_lh):
    """Section 19: WebSocket Security Vulnerabilities."""
    # 19. WebSocket Security Vulnerabilities
    for ev in get_items(
            "websocket",
            "websocket_security",
            "cswsh",
            "websocket_injection",
            "websocket_dos",
            "websocket_auth",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "websocket-security"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "security_misconfiguration"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"WebSocket Security ({vuln_type})"
            vuln_meta = dict(ev.metadata) if ev.metadata else {}
            if "name" not in vuln_meta:
                vuln_meta["name"] = vuln_name
            if "severity" not in vuln_meta:
                vuln_meta["severity"] = getattr(ev, "severity", "medium") or "medium"

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



def addRequestSmuggling(graph, get_items, resolve_lh):
    """Section 20: HTTP Request Smuggling Vulnerabilities."""
    # 20. HTTP Request Smuggling Vulnerabilities
    for ev in get_items(
            "request_smuggling",
            "http_request_smuggling",
            "cl_te",
            "te_cl",
            "te_te",
            "h2_smuggling",
            "smuggling",
            "http_desync",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "request-smuggling"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("technique") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "request_smuggling"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"HTTP Request Smuggling ({vuln_type})"
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

