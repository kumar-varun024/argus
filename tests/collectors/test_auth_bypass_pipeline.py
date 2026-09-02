"""
Pipeline Integration tests for Authentication Bypass & Credential Attack Detection Module:
TaskGenerator DAG templates, Gap Resolution, ToolRegistry & Aliases, PluginExecutorAdapter,
AttackSurfaceGraphBuilder Section 28, ScanDAG topological ordering, and CVSSCalculator mappings.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.auth_bypass import (
    AuthBypassCollector,
    AuthBypassAnalyzer,
    AuthBypassPayloadGenerator,
    AuthVulnerabilityType,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.planning.models import CoverageGap, ResearchTask, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import CWEInfo, ReportSeverity
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


# =============================================================================
# 1. ToolRegistry Lookup & Alias Resolution Tests
# =============================================================================

def test_auth_bypass_tool_registry_registration():
    """Verifies that auth_bypass is registered in ToolRegistry with accurate metadata."""
    tool = registry.get("auth_bypass")
    assert tool is not None
    assert tool.id == "auth_bypass"
    assert "Authentication Bypass" in tool.name
    assert "auth_bypass_detector" in tool.capabilities
    assert "auth_bypass_collector" in tool.capabilities
    assert "auth_bypass_specialist" in tool.capabilities
    assert "auth_bypass" in tool.capabilities
    assert "endpoints" in tool.required_inputs
    assert "vulnerabilities" in tool.produced_outputs
    assert tool.priority >= 90


def test_auth_bypass_tool_registry_aliases():
    """Verifies that all 20+ aliases for auth_bypass resolve correctly in ToolRegistry."""
    aliases = [
        "auth_bypass_collector",
        "authentication_bypass",
        "auth_collector",
        "auth",
        "credential_attack",
        "credential_attacks",
        "brute_force",
        "account_lockout",
        "password_reset",
        "password_reset_abuse",
        "mfa_bypass",
        "2fa_bypass",
        "session_fixation",
        "jwt_manipulation",
        "jwt_bypass",
        "jwt",
        "default_credentials",
        "default_creds",
        "session_token_analysis",
        "credential_stuffing",
    ]

    for alias in aliases:
        aliased_tool = registry.get(alias)
        assert aliased_tool is not None, f"Failed to resolve alias: {alias}"
        assert aliased_tool.id == "auth_bypass", f"Alias {alias} resolved to {aliased_tool.id}, expected auth_bypass"


# =============================================================================
# 2. PluginExecutorAdapter Fallback Instantiation Tests
# =============================================================================

def test_auth_bypass_plugin_executor_adapter_instantiation():
    """Verifies that PluginExecutorAdapter instantiates AuthBypassCollector on primary and alias keys."""
    adapter = PluginExecutorAdapter()

    # Primary ID
    plugin_primary = adapter._instantiate_specialist_fallback("auth_bypass")
    assert isinstance(plugin_primary, AuthBypassCollector)

    # Various alias IDs
    for key in [
        "auth_bypass_collector",
        "jwt_manipulation",
        "mfa_bypass",
        "session_fixation",
        "brute_force",
        "default_credentials",
        "credential_attack",
        "password_reset",
    ]:
        plugin = adapter._instantiate_specialist_fallback(key)
        assert isinstance(plugin, AuthBypassCollector), f"Key {key} did not instantiate AuthBypassCollector"


# =============================================================================
# 3. TaskGenerator DAG Template Integration Tests
# =============================================================================

def test_auth_bypass_dag_recon_template_definition():
    """Verifies that _RECON_TEMPLATES contains the complete auth_bypass DAG definition."""
    assert "auth_bypass" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["auth_bypass"]

    assert tmpl["title"] == "Validate Authentication Bypass & Credential Attacks"
    assert tmpl["category"] == TaskCategory.AUTHENTICATION_ANALYSIS
    assert "endpoints" in tmpl["required_inputs"]
    assert "vulnerabilities" in tmpl["expected_outputs"]
    assert "evidence" in tmpl["expected_outputs"]
    assert "Discover API Endpoints" in tmpl["dependencies"]
    assert tmpl["metadata"]["tool_id"] == "auth_bypass"
    assert tmpl["priority"] >= 0.8


def test_auth_bypass_task_generator_direct_gap_resolution():
    """Verifies that direct area gap names resolve to the auth_bypass recon template."""
    mission = Mission(target="http://example.com")
    gen = TaskGenerator(mission=mission)

    direct_areas = [
        "auth bypass",
        "auth_bypass",
        "authentication bypass",
        "credential attack",
        "credential_attack",
        "credential attacks",
        "brute force",
        "brute_force",
        "account lockout",
        "password reset",
        "password_reset",
        "mfa bypass",
        "mfa_bypass",
        "2fa bypass",
        "jwt manipulation",
        "jwt_manipulation",
        "default credentials",
        "default_credentials",
        "session token analysis",
        "credential stuffing",
    ]

    for area in direct_areas:
        gap = CoverageGap(
            category=TaskCategory.AUTHENTICATION_ANALYSIS,
            area=area,
            description=f"Coverage gap for {area}",
        )
        resolved_tmpl = gen._resolve_template_for_gap(gap)
        assert resolved_tmpl is not None, f"Failed to resolve gap area: {area}"
        assert resolved_tmpl["metadata"]["tool_id"] == "auth_bypass"


def test_auth_bypass_task_generator_keyword_fallback_resolution():
    """Verifies keyword search in gap descriptions for AUTHENTICATION_ANALYSIS and EVIDENCE_CORRELATION."""
    mission = Mission(target="http://example.com")
    gen = TaskGenerator(mission=mission)

    # Keywords under AUTHENTICATION_ANALYSIS category
    auth_keywords = ["login", "mfa", "credential", "brute force", "password reset", "session fixation", "default credential"]
    for kw in auth_keywords:
        gap = CoverageGap(
            category=TaskCategory.AUTHENTICATION_ANALYSIS,
            area="general_gap",
            description=f"Need to audit {kw} vulnerabilities on target",
        )
        resolved = gen._resolve_template_for_gap(gap)
        assert resolved["metadata"]["tool_id"] == "auth_bypass", f"Keyword '{kw}' did not resolve to auth_bypass"

    # Keywords under EVIDENCE_CORRELATION category
    corr_keywords = ["auth bypass", "authentication bypass", "credential attack", "brute force", "mfa bypass", "default credential", "password reset"]
    for kw in corr_keywords:
        gap = CoverageGap(
            category=TaskCategory.EVIDENCE_CORRELATION,
            area="general_corr",
            description=f"Correlate evidence for {kw} findings",
        )
        resolved = gen._resolve_template_for_gap(gap)
        assert resolved["metadata"]["tool_id"] == "auth_bypass", f"Corr keyword '{kw}' did not resolve to auth_bypass"


def test_auth_bypass_scan_dag_task_generation():
    """Verifies that ResearchTask created from auth_bypass template conforms to DAG dependency requirements."""
    tmpl = _RECON_TEMPLATES["auth_bypass"]

    task = ResearchTask(
        title=tmpl["title"],
        description="Audit target endpoints for authentication bypass and credential attack vectors",
        goal=tmpl["goal"],
        category=tmpl["category"],
        required_inputs=["http://example.com/api/v1"],
        expected_outputs=list(tmpl["expected_outputs"]),
        priority=tmpl["priority"],
        dependencies=list(tmpl["dependencies"]),
        metadata=dict(tmpl["metadata"]),
    )
    assert task is not None
    assert task.category == TaskCategory.AUTHENTICATION_ANALYSIS
    assert task.metadata.get("tool_id") == "auth_bypass"
    assert "Discover API Endpoints" in task.dependencies
    assert "vulnerabilities" in task.expected_outputs


# =============================================================================
# 4. AttackSurfaceGraphBuilder Section 28 Tests
# =============================================================================

def test_attack_surface_graph_builder_section_28():
    """Verifies that AttackSurfaceGraphBuilder Section 28 ingests auth_bypass Evidence and builds graph nodes and edges."""
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()

    # Evidence 1: JWT manipulation finding
    ev1 = Evidence(
        category="auth_bypass",
        value="auth_bypass:auth-jwt-alg-none:http://api.target.com/admin/user:Authorization",
        source="auth_bypass",
        severity="critical",
        title="Authentication Vulnerability: jwt_alg_none on http://api.target.com/admin/user",
        description="JWT verification bypass achieved using alg:none",
        metadata={
            "url": "http://api.target.com/admin/user",
            "host": "http://api.target.com",
            "template_id": "auth-jwt-alg-none",
            "technique": "jwt_alg_none",
            "vulnerability_type": "jwt_manipulation",
            "parameter": "Authorization",
            "status_code": 200,
            "cwe_id": "CWE-345",
            "cvss_score": 9.8,
        },
    )
    store.add(ev1)

    # Evidence 2: Default credentials finding
    ev2 = Evidence(
        category="default_credentials",
        value="default_credentials:auth-default-creds:http://portal.target.com/login:admin",
        source="auth_bypass",
        severity="critical",
        title="Authentication Vulnerability: default_credentials on http://portal.target.com/login",
        description="Default credentials admin:admin verified",
        metadata={
            "url": "http://portal.target.com/login",
            "host": "http://portal.target.com",
            "template_id": "auth-default-creds",
            "technique": "default_credentials",
            "vulnerability_type": "default_credentials",
            "parameter": "username:password",
            "status_code": 200,
            "cwe_id": "CWE-798",
            "cvss_score": 9.8,
        },
    )
    store.add(ev2)

    graph = builder.build_from_evidence(store)

    # Validate node creation
    assert "live_host:http://api.target.com" in graph.nodes
    assert "endpoint:http://api.target.com/admin/user" in graph.nodes
    vuln_id1 = "vulnerability:auth-jwt-alg-none:http://api.target.com/admin/user:Authorization"
    assert vuln_id1 in graph.nodes
    assert graph.nodes[vuln_id1].metadata["cwe_id"] == "CWE-345"

    assert "live_host:http://portal.target.com" in graph.nodes
    assert "endpoint:http://portal.target.com/login" in graph.nodes
    vuln_id2 = "vulnerability:auth-default-creds:http://portal.target.com/login:username:password"
    assert vuln_id2 in graph.nodes
    assert graph.nodes[vuln_id2].metadata["cwe_id"] == "CWE-798"

    # Validate edge connections
    def has_edge(src: str, dst: str, etype: str) -> bool:
        return any(e.source == src and e.target == dst and e.type == etype for e in graph.edges)

    assert has_edge("live_host:http://api.target.com", "endpoint:http://api.target.com/admin/user", "HAS_ENDPOINT")
    assert has_edge("live_host:http://api.target.com", vuln_id1, "HAS_VULNERABILITY")
    assert has_edge("endpoint:http://api.target.com/admin/user", vuln_id1, "HAS_VULNERABILITY")

    assert has_edge("live_host:http://portal.target.com", "endpoint:http://portal.target.com/login", "HAS_ENDPOINT")
    assert has_edge("live_host:http://portal.target.com", vuln_id2, "HAS_VULNERABILITY")
    assert has_edge("endpoint:http://portal.target.com/login", vuln_id2, "HAS_VULNERABILITY")


# =============================================================================
# 5. CVSSCalculator CWE Mappings & Base Score Derivations
# =============================================================================

def test_cvss_calculator_auth_bypass_cwe_mappings():
    """Verifies that CVSSCalculator maps authentication CWEs correctly."""
    calc = CVSSCalculator()

    # CWE-287: Improper Authentication (auth_bypass, authentication, mfa_bypass)
    info_287 = calc.get_cwe_for_category("auth_bypass")
    assert info_287 is not None
    assert info_287.id == "CWE-287"
    assert "Authentication" in info_287.name

    info_mfa = calc.get_cwe_for_category("mfa_bypass")
    assert info_mfa is not None
    assert info_mfa.id == "CWE-287"

    # CWE-307: Excessive Authentication Attempts (brute_force, credential_stuffing)
    info_307 = calc.get_cwe_for_category("brute_force")
    assert info_307 is not None
    assert info_307.id == "CWE-307"

    info_cs = calc.get_cwe_for_category("credential_stuffing")
    assert info_cs is not None
    assert info_cs.id == "CWE-307"

    # CWE-384: Session Fixation
    info_384 = calc.get_cwe_for_category("session_fixation")
    assert info_384 is not None
    assert info_384.id == "CWE-384"
    assert info_384.name == "Session Fixation"

    # CWE-640: Password Reset Abuse
    info_640 = calc.get_cwe_for_category("password_reset")
    assert info_640 is not None
    assert info_640.id == "CWE-640"

    # CWE-288: Alternate Path Authentication Bypass
    info_288 = calc.get_cwe_for_category("mfa_forced_browsing")
    assert info_288 is not None
    assert info_288.id == "CWE-288"

    # CWE-1390: Weak Authentication Token
    info_1390 = calc.get_cwe_for_category("jwt_token_weakness")
    assert info_1390 is not None
    assert info_1390.id == "CWE-1390"

    # CWE-798: Default / Hard-coded Credentials
    info_798 = calc.get_cwe_for_category("default_credentials")
    assert info_798 is not None
    assert info_798.id == "CWE-798"

    # CWE-1392: Use of Default Credentials
    info_1392 = calc.get_cwe_for_category("use_of_default_credentials")
    assert info_1392 is not None
    assert info_1392.id == "CWE-1392"

    # CWE-522: Insufficiently Protected Credentials / Leakage
    info_522 = calc.get_cwe_for_category("auth_credential_leakage")
    assert info_522 is not None
    assert info_522.id == "CWE-522"

    # CWE-613: Insufficient Session Expiration
    info_613 = calc.get_cwe_for_category("session_expiration")
    assert info_613 is not None
    assert info_613.id == "CWE-613"


def test_cvss_calculator_score_calculation_from_auth_finding():
    """Verifies calculation of CVSS score and severity for authentication findings."""
    calc = CVSSCalculator()

    # Direct base score calculation with vector string
    crit_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    crit_score = calc.calculate_base_score(crit_vector)
    assert crit_score == 9.8
    assert calc.score_to_severity(crit_score) == ReportSeverity.CRITICAL

    # Calculation via metrics dict
    med_metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
    med_score = calc.calculate_base_score(med_metrics)
    assert med_score == 5.3
    assert calc.score_to_severity(med_score) == ReportSeverity.MEDIUM

    # Approximation for auth finding
    cvss_data = calc.get_approximate_cvss(
        category="auth_bypass",
        severity="high",
        metadata={"cvss_score": 8.8},
    )
    assert cvss_data.score >= 7.0
    assert cvss_data.severity_rating in ("High", "Critical")

