"""Vulnerability evidence sections 26-29: file upload, API security, auth
bypass, prototype pollution / client-side attacks.

Verbatim relocation from the original build_from_evidence method. Behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addCorsSecurity(graph, get_items, resolve_lh):
    """Section 25: CORS Misconfiguration & HTTP Security Header Vulnerabilities."""
    # 25. CORS Misconfiguration & HTTP Security Header Vulnerabilities
    for ev in get_items(
            "cors",
            "cors_security",
            "cors_headers",
            "cors_misconfiguration",
            "security_headers",
            "http_security_headers",
            "http_headers",
            "security_header",
            "header_security",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "cors-security-finding"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("vector_name") or ev.metadata.get("header_name") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "cors_security"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"CORS / Security Header ({vuln_type})"
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



def addFileUpload(graph, get_items, resolve_lh):
    """Section 26: File Upload Vulnerabilities."""
    # 26. File Upload Vulnerabilities
    for ev in get_items(
            "file_upload",
            "upload_security",
            "unrestricted_upload",
            "unrestricted_file_upload",
            "arbitrary_file_upload",
            "mime_type_bypass",
            "double_extension_bypass",
            "polyglot_magic_bytes",
            "path_traversal_filename",
            "web_shell_execution",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "file-upload-finding"
            filename = ev.metadata.get("filename") or ev.metadata.get("parameter") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "file_upload"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{filename}" if (target_url and filename) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"File Upload Vulnerability ({vuln_type})"
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



def addApiSecurity(graph, get_items, resolve_lh):
    """Section 27: API Security Vulnerabilities (REST & gRPC)."""
    # 27. API Security Vulnerabilities (REST & gRPC)
    for ev in get_items(
            "api_security",
            "api_security_testing",
            "rest_api_security",
            "rest_security",
            "grpc_security",
            "parameter_tampering",
            "mass_assignment",
            "rate_limiting",
            "rate_limiting_bypass",
            "rate_limit_bypass",
            "bola",
            "idor",
            "bola_idor",
            "broken_object_level_authorization",
            "excessive_data_exposure",
            "method_tampering",
            "api_bypass",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "api-security-finding"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("field") or ev.metadata.get("endpoint") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "api_security"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"API Security Vulnerability ({vuln_type})"
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



def addAuthBypass(graph, get_items, resolve_lh):
    """Section 28: Authentication Bypass & Credential Attack Vulnerabilities."""
    # 28. Authentication Bypass & Credential Attack Vulnerabilities
    for ev in get_items(
            "auth_bypass",
            "authentication",
            "authentication_bypass",
            "credential_attack",
            "credential_attacks",
            "brute_force",
            "password_reset",
            "password_reset_abuse",
            "mfa_bypass",
            "session_fixation",
            "jwt_manipulation",
            "default_credentials",
            "session_token_analysis",
            "credential_stuffing",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "auth-bypass-finding"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("field") or ev.metadata.get("endpoint") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "auth_bypass"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Authentication Vulnerability ({vuln_type})"
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



def addPrototypePollution(graph, get_items, resolve_lh):
    """Section 29: Prototype Pollution & Client-Side Attack Vulnerabilities."""
    # 29. Prototype Pollution & Client-Side Attack Vulnerabilities
    for ev in get_items(
            "prototype_pollution",
            "client_side_prototype_pollution",
            "server_side_prototype_pollution",
            "dom_clobbering",
            "html_clobbering",
            "open_redirect",
            "open_redirect_chain",
            "clickjacking",
            "ui_redressing",
            "client_side_attacks",
        ):
            target_url = ev.metadata.get("url") or ev.value
            parsed_url = urllib.parse.urlparse(target_url) if target_url else None
            base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
            template_id = ev.metadata.get("template_id") or "prototype-pollution-finding"
            param_name = ev.metadata.get("parameter") or ev.metadata.get("gadget") or ev.metadata.get("field") or ev.metadata.get("endpoint") or ""
            vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "prototype_pollution"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
            vuln_name = ev.title or f"Client-Side Attack Vulnerability ({vuln_type})"
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

