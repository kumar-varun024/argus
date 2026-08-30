from __future__ import annotations
import urllib.parse
from typing import Any, Optional

from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence


class AttackSurfaceGraphBuilder:
    """
    Transforms structured reconnaissance evidence from an EvidenceStore
    or Mission into a strongly typed KnowledgeGraph.
    """

    def build_from_evidence(
        self,
        evidence: EvidenceStore,
        target: str = "",
        graph: Optional[KnowledgeGraph] = None,
    ) -> KnowledgeGraph:
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

        # 2. Subdomains
        for ev in evidence_items:
            if getattr(ev, "category", None) == "subdomain":
                hostname = ev.metadata.get("hostname") or ev.value
                if hostname:
                    sub_id = f"subdomain:{hostname}"
                    sub_meta = {"hostname": hostname, "source": ev.source}
                    if ev.metadata:
                        sub_meta.update(ev.metadata)
                    graph.add(Node(id=sub_id, type="subdomain", value=hostname, metadata=sub_meta))
                    if target:
                        graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")

        # 3. Live Hosts
        for ev in evidence_items:
            if getattr(ev, "category", None) == "live_host":
                url = ev.metadata.get("url") or ev.value
                host = ev.metadata.get("host")
                if not host and url:
                    parsed = urllib.parse.urlparse(url)
                    host = parsed.hostname or parsed.netloc

                lh_id = f"live_host:{url}" if url else f"live_host:{host}"
                lh_val = url if url else host
                lh_meta = dict(ev.metadata) if ev.metadata else {}
                if url and "url" not in lh_meta:
                    lh_meta["url"] = url
                if host and "host" not in lh_meta:
                    lh_meta["host"] = host

                graph.add(Node(id=lh_id, type="live_host", value=lh_val, metadata=lh_meta))

                # Link Subdomain -> Live Host
                if host:
                    sub_id = f"subdomain:{host}"
                    if sub_id not in graph.nodes:
                        graph.add(Node(id=sub_id, type="subdomain", value=host, metadata={"hostname": host, "source": ev.source}))
                        if target:
                            graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")
                    graph.connect(sub_id, lh_id, edge_type="HOSTS")
                elif target:
                    target_sub_id = f"subdomain:{target}"
                    if target_sub_id in graph.nodes:
                        graph.connect(target_sub_id, lh_id, edge_type="HOSTS")
                    else:
                        graph.connect(f"target:{target}", lh_id, edge_type="HOSTS")

                # Process technologies embedded in live host metadata
                techs = ev.metadata.get("technologies") or []
                if isinstance(techs, str):
                    techs = [t.strip() for t in techs.split(",") if t.strip()]
                for tech in techs:
                    if tech:
                        tech_name = str(tech).strip()
                        tech_id = f"technology:{tech_name}"
                        graph.add(Node(id=tech_id, type="technology", value=tech_name, metadata={"name": tech_name}))
                        graph.connect(lh_id, tech_id, edge_type="RUNS_TECHNOLOGY")

        # 4. Technologies (distinct evidence items)
        for ev in evidence_items:
            if getattr(ev, "category", None) == "technology":
                tech_name = ev.metadata.get("name") or ev.value
                if tech_name:
                    tech_name = str(tech_name).strip()
                    tech_id = f"technology:{tech_name}"
                    tech_meta = dict(ev.metadata) if ev.metadata else {"name": tech_name}
                    if "name" not in tech_meta:
                        tech_meta["name"] = tech_name
                    graph.add(Node(id=tech_id, type="technology", value=tech_name, metadata=tech_meta))

                    lh_target = ev.metadata.get("url") or ev.metadata.get("host")
                    lh_node = None
                    if lh_target:
                        lh_node = graph.get(f"live_host:{lh_target}")
                        if not lh_node:
                            for n in graph.nodes_by_type("live_host"):
                                if n.value == lh_target or n.metadata.get("url") == lh_target or n.metadata.get("host") == lh_target:
                                    lh_node = n
                                    break
                    if not lh_node:
                        live_hosts = graph.nodes_by_type("live_host")
                        if len(live_hosts) == 1:
                            lh_node = live_hosts[0]

                    if lh_node:
                        graph.connect(lh_node.id, tech_id, edge_type="RUNS_TECHNOLOGY")

        # 5. Endpoints
        for ev in evidence_items:
            if getattr(ev, "category", None) == "endpoint":
                ep_url = ev.metadata.get("url") or ev.value
                ep_host = ev.metadata.get("host")
                if not ep_host and ep_url:
                    parsed = urllib.parse.urlparse(ep_url)
                    ep_host = parsed.hostname

                ep_id = f"endpoint:{ep_url}"
                ep_meta = dict(ev.metadata) if ev.metadata else {}
                if ep_url and "url" not in ep_meta:
                    ep_meta["url"] = ep_url
                if ep_host and "host" not in ep_meta:
                    ep_meta["host"] = ep_host

                graph.add(Node(id=ep_id, type="endpoint", value=ep_url, metadata=ep_meta))

                # Link Live Host -> Endpoint
                lh_node = None
                if ep_url:
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

        # 6. Vulnerabilities
        for ev in evidence_items:
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
                lh_node = None
                vuln_host = ev.metadata.get("host") or ev.metadata.get("matched_at")
                if vuln_host:
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

        # 7. Subdomain Takeover Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) == "subdomain_takeover":
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

        # 8. Information Disclosure Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) == "information_disclosure":
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

        # 9. Broken Access Control / IDOR Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) == "broken_access_control":
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 10. Path Traversal Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) == "path_traversal":
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 11. SQL Injection Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) == "sql_injection":
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 12. Cross-Site Scripting (XSS) Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) in ("xss", "cross_site_scripting"):
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 13. Command Injection (CMDi) Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) in ("command_injection", "cmdi", "os_command_injection", "cmd_injection"):
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 14. Server-Side Request Forgery (SSRF) Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) in ("ssrf", "server_side_request_forgery", "ssrf_validation"):
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 15. OAuth / OIDC Misconfigurations, Token Validation & Stateful Authentication Vulnerabilities
        for ev in evidence_items:
            if getattr(ev, "category", None) in (
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
                lh_node = None
                if base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)
                    if not lh_node:
                        for n in graph.nodes_by_type("live_host"):
                            if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                                lh_node = n
                                break
                if not lh_node and target_url:
                    for n in graph.nodes_by_type("live_host"):
                        lh_url = n.metadata.get("url") or n.value
                        if lh_url and target_url.startswith(lh_url):
                            lh_node = n
                            break
                if not lh_node:
                    live_hosts = graph.nodes_by_type("live_host")
                    if len(live_hosts) == 1:
                        lh_node = live_hosts[0]

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        return graph





    def build(self, mission: Any) -> KnowledgeGraph:
        """
        Builds and populates a KnowledgeGraph directly from a Mission instance.

        Args:
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
            self.build_from_evidence(evidence, target=target, graph=graph)

        # 2. Ingest structured attributes from mission (handles missions populated without evidence store)
        if target:
            target_id = f"target:{target}"
            graph.add(Node(id=target_id, type="target", value=target, metadata={"target": target}))

        # Subdomains
        for sub in getattr(mission, "subdomains", []) or []:
            hostname = sub.get("hostname") if isinstance(sub, dict) else str(sub)
            if hostname:
                sub_id = f"subdomain:{hostname}"
                sub_meta = sub if isinstance(sub, dict) else {"hostname": hostname}
                graph.add(Node(id=sub_id, type="subdomain", value=hostname, metadata=sub_meta))
                if target:
                    graph.connect(f"target:{target}", sub_id, edge_type="RESOLVES_TO")

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

        # Attach to mission
        try:
            mission.attack_surface_graph = graph
            mission.graph = graph
        except Exception:
            pass

        return graph
