"""
Forensic Auditor 1 Deep Integrity & Stress Verification Script for Sprint 22 SSTI Module.
"""
import copy
import random
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.ssti import (
    SSTICollector,
    ServerSideTemplateInjectionCollector,
    SSTIPayloadGenerator,
    SSTISecurityAnalyzer,
    SSTIProber,
    SSTIProbe,
    SSTIProbeResponse,
    SSTIResult,
    SSTISeverity,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
    SSTI_ERROR_SIGNATURES,
    SSTI_RCE_OUTPUT_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.runtime.registry import registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.planning.task_generator import TaskGenerator, CoverageGap, TaskCategory
from argus.reporting.cvss import CVSSCalculator, ReportSeverity
from argus.reporting.processor import EvidenceProcessor


def run_forensic_checks():
    print("[+] Starting Forensic Auditor Deep Integrity Checks...")

    # 1. Random dynamic arithmetic validation
    gen = SSTIPayloadGenerator()
    for _ in range(50):
        a = random.randint(100, 999)
        b = random.randint(10, 99)
        payload, expected = gen.generate_arithmetic_canary(SSTIEngineFamily.PYTHON_JINJA2, a=a, b=b)
        assert payload == f"{{{{{a}*{b}}}}}"
        assert expected == str(a * b)

        payload_free, expected_free = gen.generate_arithmetic_canary(SSTIEngineFamily.JAVA_FREEMARKER, a=a, b=b)
        assert payload_free == f"${{{a}*{b}}}"
        assert expected_free == str(a * b)
    print("  [✓] Dynamic arithmetic canary calculations verified (50 random samples).")

    # 2. Decision tree routing verification
    diff_payloads = gen.generate_differential_payloads()
    assert len(diff_payloads) >= 8
    coercion_probe = next(p for p in diff_payloads if p.get("discriminator") == "type_coercion")
    assert coercion_probe["payload"] == "{{7*'7'}}"
    assert coercion_probe["rules"]["7777777"] == SSTIEngineFamily.PYTHON_JINJA2
    assert coercion_probe["rules"]["49"] == SSTIEngineFamily.PHP_TWIG
    print("  [✓] Decision tree differential routing catalog verified.")

    # 3. Sandbox escapes catalog inspection
    escapes = gen.generate_sandbox_escape_payloads()
    assert len(escapes) >= 10
    engines_represented = {e["engine"] for e in escapes}
    assert SSTIEngineFamily.PYTHON_JINJA2 in engines_represented
    assert SSTIEngineFamily.PHP_TWIG in engines_represented
    assert SSTIEngineFamily.JAVA_FREEMARKER in engines_represented
    assert SSTIEngineFamily.JAVA_VELOCITY in engines_represented
    assert SSTIEngineFamily.JAVA_SPEL in engines_represented
    assert SSTIEngineFamily.PYTHON_MAKO in engines_represented
    assert SSTIEngineFamily.RUBY_ERB in engines_represented
    assert SSTIEngineFamily.NODE_PUG in engines_represented
    assert SSTIEngineFamily.NODE_EJS in engines_represented
    print("  [✓] Sandbox escape payload suites verified across all major engines.")

    # 4. Mutation strategy transformations
    for strat in SSTIMutationStrategy:
        mutated = gen.apply_mutation_strategy("{{''.__class__.__mro__[1].__subclasses__()}}", strat)
        assert isinstance(mutated, str) and len(mutated) > 0
        assert mutated != ""
    print("  [✓] All 5 mutation and evasion strategies verified.")

    # 5. Security Analyzer Reflection Suppression
    analyzer = SSTISecurityAnalyzer()
    assert analyzer.is_static_reflection("Input: {{7*7}}", "{{7*7}}") is True
    assert analyzer.is_static_reflection("Input: &lt;%= 7*7 %&gt;", "<%= 7*7 %>") is True
    assert analyzer.is_static_reflection("Input: %7B%7B7%2A7%7D%7D", "{{7*7}}") is True
    assert analyzer.is_static_reflection("Input: 49", "{{7*7}}") is False

    # Baseline subtraction
    res_clean = analyzer.analyze_arithmetic_evaluation(
        response_body="Result: 49 items",
        canary_expected="49",
        baseline_body="Baseline: 0 items",
    )
    assert res_clean is not None and res_clean["canary"] == "49"

    res_fp = analyzer.analyze_arithmetic_evaluation(
        response_body="Page 49 of 100",
        canary_expected="49",
        baseline_body="Page 49 of 100",
    )
    assert res_fp is None, "Failed to suppress static baseline number"
    print("  [✓] False positive & static reflection suppression verified.")

    # 6. RCE Signatures
    for rce_text, expected_sig in [
        ("uid=1000(user) gid=1000(user)", "posix_id"),
        ("Linux production-node 5.15.0-generic", "posix_uname"),
        ("root:x:0:0:root:/root:/bin/bash", "posix_passwd"),
        ("nt authority\\system", "windows_whoami"),
        ("Volume Serial Number is 1234-ABCD", "windows_dir"),
        ("java.lang.ProcessBuilder", "java_process"),
    ]:
        match = analyzer.analyze_rce_execution(rce_text)
        assert match is not None, f"Failed matching RCE: {rce_text}"
        assert match["signature"] == expected_sig
        assert match["severity"] == SSTISeverity.CRITICAL
        assert match["cvss_score"] == 9.8
    print("  [✓] RCE signature detection & CRITICAL elevation verified.")

    # 7. Error Signatures
    for err_text, expected_eng in [
        ("jinja2.exceptions.TemplateSyntaxError: unexpected char", "jinja2"),
        ("Twig\\Error\\SyntaxError: Unexpected token", "twig"),
        ("SmartyCompilerException: Syntax Error in template", "smarty"),
        ("freemarker.core.ParseException: Syntax error", "freemarker"),
        ("org.apache.velocity.exception.ParseErrorException", "velocity"),
        ("org.springframework.expression.spel.SpelEvaluationException: EL1004E", "spel"),
        ("mako.exceptions.SyntaxException: Syntax error", "mako"),
        ("django.template.exceptions.TemplateSyntaxError", "django"),
        ("org.thymeleaf.exceptions.TemplateProcessingException", "thymeleaf"),
        ("com.mitchellbosecke.pebble.error.PebbleException", "pebble"),
        ("Pug:SyntaxError: Unexpected token", "pug"),
        ("ejs:SyntaxError: Could not find matching close tag", "ejs"),
        ("Handlebars: Error: Parse error on line 1", "handlebars"),
        ("Dust: Syntax error in template", "dust"),
        ("syntax error, unexpected in ERB template", "erb"),
    ]:
        match = analyzer.analyze_error_fingerprint(err_text)
        assert match is not None, f"Failed matching error for {expected_eng}: {err_text}"
        assert match["engine"] == expected_eng
    print("  [✓] Error fingerprinting verified across all 15 template engine signatures.")

    # 8. Registry & Plugins
    assert registry.get("ssti") is not None
    assert registry.get("jinja2").id == "ssti"
    assert registry.get("twig").id == "ssti"
    assert registry.get("freemarker").id == "ssti"
    adapter = PluginExecutorAdapter()
    assert isinstance(adapter._instantiate_specialist_fallback("ssti"), SSTICollector)
    assert isinstance(adapter._instantiate_specialist_fallback("freemarker"), SSTICollector)
    print("  [✓] ToolRegistry and PluginExecutorAdapter integration verified.")

    # 9. TaskGenerator DAG
    mission = Mission(target="http://target.local")
    tg = TaskGenerator(mission)
    gap = CoverageGap(
        category=TaskCategory.EVIDENCE_CORRELATION,
        area="ssti",
        description="Check template injection",
        severity=0.8,
    )
    tasks = tg.from_gaps([gap])
    assert len(tasks) >= 1
    assert tasks[0].metadata.get("tool_id") == "ssti"
    print("  [✓] TaskGenerator DAG coverage gap resolution verified.")

    # 10. Attack Surface Graph Section 23
    ev = Evidence(
        category="ssti",
        value="ssti:http://target.local/view:name:arithmetic_probe",
        source="ssti",
        title="Server-Side Template Injection (Jinja2) in name",
        severity="high",
        metadata={
            "url": "http://target.local/view",
            "host": "http://target.local",
            "parameter": "name",
            "engine": "jinja2",
            "status_code": 200,
        },
    )
    graph = AttackSurfaceGraphBuilder().build_from_evidence([ev])
    assert "vulnerability:ssti:http://target.local/view:name" in graph.nodes
    assert "endpoint:http://target.local/view" in graph.nodes
    assert "live_host:http://target.local" in graph.nodes
    assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
    assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
    print("  [✓] Attack Surface Graph Section 23 node & edge builder verified.")

    # 11. CVSS & CWE Mappings
    assert CVSSCalculator.get_cwe_for_category("ssti").id == "CWE-1336"
    assert CVSSCalculator.get_cwe_for_category("ssti_rce").id == "CWE-94"
    assert CVSSCalculator.get_approximate_cvss("ssti", ReportSeverity.CRITICAL).score >= 9.5
    assert CVSSCalculator.get_approximate_cvss("ssti", ReportSeverity.HIGH).score >= 7.5
    print("  [✓] CVSS Calculator & CWE database mappings verified.")

    print("\n[✓✓✓] ALL FORENSIC INTEGRITY CHECKS PASSED WITH ZERO VIOLATIONS.")


if __name__ == "__main__":
    run_forensic_checks()
