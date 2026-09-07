"""Recon evidence sections (2-5): subdomains, live hosts, technologies, endpoints.

Each function is a verbatim relocation of one numbered section from the
original attack_surface.py build_from_evidence method -- see that file's
git history for the pre-extraction form. Behavior pinned by
tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

import urllib.parse

from argus.graph.node import Node


def addSubdomains(graph, get_items, target):
    """Section 2: Subdomains."""
    # 2. Subdomains
    for ev in get_items("subdomain"):
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


def addLiveHosts(graph, get_items, target):
    """Section 3: Live Hosts."""
    # 3. Live Hosts
    for ev in get_items("live_host"):
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


def addTechnologies(graph, get_items, resolve_lh):
    """Section 4: Technologies (distinct evidence items)."""
    # 4. Technologies (distinct evidence items)
    for ev in get_items("technology"):
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
                lh_node = resolve_lh(target_url_val=ev.metadata.get("url"), host_val=ev.metadata.get("host"))
                if lh_node:
                    graph.connect(lh_node.id, tech_id, edge_type="RUNS_TECHNOLOGY")


def addEndpoints(graph, get_items, resolve_lh):
    """Section 5: Endpoints."""
    # 5. Endpoints
    for ev in get_items("endpoint"):
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
            lh_node = resolve_lh(target_url_val=ep_url, host_val=ep_host)
            if lh_node:
                graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
