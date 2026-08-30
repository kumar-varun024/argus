from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.evidence.store import EvidenceStore


@dataclass
class HostChange:
    """
    Represents detected drift on a specific live host entity across scan cycles.
    """
    host: str
    status_changed: bool = False
    old_status: Optional[int] = None
    new_status: Optional[int] = None
    server_changed: bool = False
    old_server: Optional[str] = None
    new_server: Optional[str] = None
    added_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    added_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    added_vulnerabilities: list[str] = field(default_factory=list)
    removed_vulnerabilities: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Returns True if any attribute or related entity changed."""
        return (
            self.status_changed
            or self.server_changed
            or bool(self.added_technologies)
            or bool(self.removed_technologies)
            or bool(self.added_endpoints)
            or bool(self.removed_endpoints)
            or bool(self.added_vulnerabilities)
            or bool(self.removed_vulnerabilities)
        )


@dataclass
class AttackSurfaceDiff:
    """
    Structured delta capturing added, removed, and changed assets between two states.
    """
    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)
    new_live_hosts: list[str] = field(default_factory=list)
    removed_live_hosts: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    new_vulnerabilities: list[Any] = field(default_factory=list)
    removed_vulnerabilities: list[Any] = field(default_factory=list)
    changed_hosts: list[HostChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Returns True if there is any addition, removal, or host modification."""
        return (
            bool(self.new_subdomains)
            or bool(self.removed_subdomains)
            or bool(self.new_live_hosts)
            or bool(self.removed_live_hosts)
            or bool(self.new_endpoints)
            or bool(self.removed_endpoints)
            or bool(self.new_technologies)
            or bool(self.removed_technologies)
            or bool(self.new_vulnerabilities)
            or bool(self.removed_vulnerabilities)
            or any(h.has_changes for h in self.changed_hosts)
        )

    def total_changes(self) -> int:
        """Calculates total count of atomic differences."""
        count = (
            len(self.new_subdomains)
            + len(self.removed_subdomains)
            + len(self.new_live_hosts)
            + len(self.removed_live_hosts)
            + len(self.new_endpoints)
            + len(self.removed_endpoints)
            + len(self.new_technologies)
            + len(self.removed_technologies)
            + len(self.new_vulnerabilities)
            + len(self.removed_vulnerabilities)
        )
        for h in self.changed_hosts:
            if h.status_changed:
                count += 1
            if h.server_changed:
                count += 1
            count += len(h.added_technologies) + len(h.removed_technologies)
            count += len(h.added_endpoints) + len(h.removed_endpoints)
            count += len(h.added_vulnerabilities) + len(h.removed_vulnerabilities)
        return count

    def summary(self) -> dict[str, int]:
        """Returns a summarized map of delta metrics."""
        return {
            "new_subdomains": len(self.new_subdomains),
            "removed_subdomains": len(self.removed_subdomains),
            "new_live_hosts": len(self.new_live_hosts),
            "removed_live_hosts": len(self.removed_live_hosts),
            "new_endpoints": len(self.new_endpoints),
            "removed_endpoints": len(self.removed_endpoints),
            "new_technologies": len(self.new_technologies),
            "removed_technologies": len(self.removed_technologies),
            "new_vulnerabilities": len(self.new_vulnerabilities),
            "removed_vulnerabilities": len(self.removed_vulnerabilities),
            "changed_hosts": len([h for h in self.changed_hosts if h.has_changes]),
            "total_changes": self.total_changes(),
        }


class AttackSurfaceDiffEngine:
    """
    Compares two missions, knowledge graphs, or evidence stores and computes
    structured asset deltas.
    """

    @staticmethod
    def diff_graphs(base: KnowledgeGraph, current: KnowledgeGraph) -> AttackSurfaceDiff:
        """
        Computes structured delta between two KnowledgeGraph instances.
        """
        diff = AttackSurfaceDiff()

        # 1. Subdomains
        base_subs = {n.value for n in base.nodes_by_type("subdomain")}
        current_subs = {n.value for n in current.nodes_by_type("subdomain")}
        diff.new_subdomains = sorted(current_subs - base_subs)
        diff.removed_subdomains = sorted(base_subs - current_subs)

        # 2. Live Hosts
        base_lh_map = {n.value: n for n in base.nodes_by_type("live_host")}
        current_lh_map = {n.value: n for n in current.nodes_by_type("live_host")}
        base_lh_keys = set(base_lh_map.keys())
        current_lh_keys = set(current_lh_map.keys())
        diff.new_live_hosts = sorted(current_lh_keys - base_lh_keys)
        diff.removed_live_hosts = sorted(base_lh_keys - current_lh_keys)

        # 3. Endpoints
        base_eps = {n.value for n in base.nodes_by_type("endpoint")}
        current_eps = {n.value for n in current.nodes_by_type("endpoint")}
        diff.new_endpoints = sorted(current_eps - base_eps)
        diff.removed_endpoints = sorted(base_eps - current_eps)

        # 4. Technologies
        base_techs = {n.value for n in base.nodes_by_type("technology")}
        current_techs = {n.value for n in current.nodes_by_type("technology")}
        diff.new_technologies = sorted(current_techs - base_techs)
        diff.removed_technologies = sorted(base_techs - current_techs)

        # 5. Vulnerabilities
        base_vulns_map = {n.value: n.metadata for n in base.nodes_by_type("vulnerability")}
        current_vulns_map = {n.value: n.metadata for n in current.nodes_by_type("vulnerability")}
        new_vuln_keys = sorted(set(current_vulns_map.keys()) - set(base_vulns_map.keys()))
        removed_vuln_keys = sorted(set(base_vulns_map.keys()) - set(current_vulns_map.keys()))

        diff.new_vulnerabilities = [dict(current_vulns_map[k]) for k in new_vuln_keys]
        diff.removed_vulnerabilities = [dict(base_vulns_map[k]) for k in removed_vuln_keys]

        # 6. Changed Hosts (In-place host modifications)
        common_hosts = sorted(base_lh_keys & current_lh_keys)
        for host_key in common_hosts:
            b_node = base_lh_map[host_key]
            c_node = current_lh_map[host_key]

            # Status code
            b_status = b_node.metadata.get("status")
            c_status = c_node.metadata.get("status")
            status_changed = (b_status != c_status and (b_status is not None or c_status is not None))

            # Server
            b_server = b_node.metadata.get("server")
            c_server = c_node.metadata.get("server")
            server_changed = (b_server != c_server and (b_server is not None or c_server is not None))

            # Connected technologies
            b_host_techs = {
                e.target.removeprefix("technology:") if e.target.startswith("technology:") else e.target
                for e in base.edges_from(b_node) if e.type == "RUNS_TECHNOLOGY"
            }
            if not b_host_techs and b_node.metadata.get("technologies"):
                b_host_techs = set(b_node.metadata.get("technologies"))

            c_host_techs = {
                e.target.removeprefix("technology:") if e.target.startswith("technology:") else e.target
                for e in current.edges_from(c_node) if e.type == "RUNS_TECHNOLOGY"
            }
            if not c_host_techs and c_node.metadata.get("technologies"):
                c_host_techs = set(c_node.metadata.get("technologies"))

            added_techs = sorted(c_host_techs - b_host_techs)
            removed_techs = sorted(b_host_techs - c_host_techs)

            # Connected endpoints
            b_host_eps = {
                e.target.removeprefix("endpoint:") if e.target.startswith("endpoint:") else e.target
                for e in base.edges_from(b_node) if e.type == "HAS_ENDPOINT"
            }
            c_host_eps = {
                e.target.removeprefix("endpoint:") if e.target.startswith("endpoint:") else e.target
                for e in current.edges_from(c_node) if e.type == "HAS_ENDPOINT"
            }
            added_eps = sorted(c_host_eps - b_host_eps)
            removed_eps = sorted(b_host_eps - c_host_eps)

            # Connected vulnerabilities
            b_host_vulns = {
                e.target.removeprefix("vulnerability:") if e.target.startswith("vulnerability:") else e.target
                for e in base.edges_from(b_node) if e.type == "HAS_VULNERABILITY"
            }
            c_host_vulns = {
                e.target.removeprefix("vulnerability:") if e.target.startswith("vulnerability:") else e.target
                for e in current.edges_from(c_node) if e.type == "HAS_VULNERABILITY"
            }
            added_vulns = sorted(c_host_vulns - b_host_vulns)
            removed_vulns = sorted(b_host_vulns - c_host_vulns)

            host_change = HostChange(
                host=host_key,
                status_changed=status_changed,
                old_status=b_status if status_changed else None,
                new_status=c_status if status_changed else None,
                server_changed=server_changed,
                old_server=b_server if server_changed else None,
                new_server=c_server if server_changed else None,
                added_technologies=added_techs,
                removed_technologies=removed_techs,
                added_endpoints=added_eps,
                removed_endpoints=removed_eps,
                added_vulnerabilities=added_vulns,
                removed_vulnerabilities=removed_vulns,
            )
            if host_change.has_changes:
                diff.changed_hosts.append(host_change)

        return diff

    @staticmethod
    def diff_missions(base: Any, current: Any) -> AttackSurfaceDiff:
        """
        Computes structured delta between two Mission instances.
        """
        builder = AttackSurfaceGraphBuilder()
        base_graph = getattr(base, "attack_surface_graph", None)
        if base_graph is None:
            base_graph = getattr(base, "graph", None)
        if base_graph is None or base_graph.node_count() == 0:
            base_graph = builder.build(base)

        current_graph = getattr(current, "attack_surface_graph", None)
        if current_graph is None:
            current_graph = getattr(current, "graph", None)
        if current_graph is None or current_graph.node_count() == 0:
            current_graph = builder.build(current)

        return AttackSurfaceDiffEngine.diff_graphs(base_graph, current_graph)

    @staticmethod
    def diff_evidence(
        base: EvidenceStore,
        current: EvidenceStore,
        base_target: str = "",
        current_target: str = "",
    ) -> AttackSurfaceDiff:
        """
        Computes structured delta between two EvidenceStore instances.
        """
        builder = AttackSurfaceGraphBuilder()
        base_graph = builder.build_from_evidence(base, target=base_target)
        current_graph = builder.build_from_evidence(current, target=current_target)
        return AttackSurfaceDiffEngine.diff_graphs(base_graph, current_graph)

    @classmethod
    def diff(cls, base: Any, current: Any) -> AttackSurfaceDiff:
        """
        Poly-input entry point for diffing KnowledgeGraphs, EvidenceStores, or Missions.
        """
        if isinstance(base, KnowledgeGraph) and isinstance(current, KnowledgeGraph):
            return cls.diff_graphs(base, current)
        elif isinstance(base, EvidenceStore) and isinstance(current, EvidenceStore):
            return cls.diff_evidence(base, current)
        else:
            return cls.diff_missions(base, current)
