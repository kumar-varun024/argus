# Sprint 22 Handoff: Server-Side Template Injection (SSTI) Detection Module

**Sprint**: Sprint 22  
**Target Module**: Server-Side Template Injection (SSTI) Detection Module  
**Baseline Test Count**: 1,614 tests  
**New Tests Added**: 34 tests (`tests/collectors/test_ssti.py`, `tests/collectors/test_ssti_adversarial.py`)  
**Post-Sprint Test Count**: 1,648 tests (0 failures, 0 regressions)  
**Status**: COMPLETE & VERIFIED  

---

## 1. Executive Summary

Sprint 22 implemented the Server-Side Template Injection (SSTI) Detection Module for the ARGUS platform. The module actively identifies, fingerprints, and validates SSTI vulnerabilities across web applications, template rendering endpoints, email generators, PDF export services, and dynamic content APIs.

All requirements R1–R5 and acceptance criteria have been achieved and verified through a multi-agent review, adversarial stress-testing, and forensic integrity audit.

---

## 2. Implementation Overview

### 2.1 Core Collector & Prober (`argus/collectors/ssti.py`, `argus/collectors/__init__.py`)
- **Tripartite Architecture**:
  - `SSTIPayloadGenerator`: Generates polyglot arithmetic canaries with dynamic randomized operands (`{{a*b}}`, `${a*b}`, `<%= a*b %>`, `#{a*b}`, `*{a*b}`, `[#ftl]${a*b}`, `[[${a*b}]]`, `{a*b}`), differential decision tree routing (`{{7*'7'}}`), sandbox escape / RCE payloads across 15+ engines, blind timing delay probes, and error syntax triggers.
  - `SSTISecurityAnalyzer`: Strict false-positive reflection suppression via `is_static_reflection()` and `strip_payload_reflections()`, baseline response count subtraction, POSIX/Windows/Java RCE output regex matching, and error stack trace fingerprinting.
  - `SSTIProber`: Injects probes across GET query parameters, POST form-urlencoded bodies, JSON bodies, HTTP request headers (`User-Agent`, `X-Forwarded-For`, custom headers), and REST URL path segments.
  - `SSTICollector(BaseCollector)`: Discovers template endpoints, calibrates baselines, coordinates probing stages, and publishes findings via Quadruple State Publishing (`raw_mission.evidence`, `raw_mission.vulnerabilities`, `raw_mission.attack_surface_graph`, `ControlledMission.publish_finding`).
- **Enums & Data Models**:
  - `SSTISeverity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (with `Severity` alias).
  - `SSTITechnique`: `ARITHMETIC_PROBE`, `DECISION_TREE_ROUTING`, `SANDBOX_ESCAPE_RCE`, `BLIND_TIME_BASED`, `ERROR_BASED_FINGERPRINT`.
  - `SSTIEngineFamily`: Covers 18 engine families (`jinja2`, `mako`, `tornado`, `django`, `freemarker`, `velocity`, `thymeleaf`, `pebble`, `spel`, `twig`, `smarty`, `blade`, `erb`, `pug`, `ejs`, `handlebars`, `dust`, `go`, `generic`).
  - `SSTIMutationStrategy`: 5 distinct strategies (`STRING_CONCAT_ENCODING`, `ATTRIBUTE_INDIRECTION`, `COMMENT_TAG_VARIATION`, `FILTER_WHITESPACE_BYPASS`, `OBJECT_CLASSLOADER_NAVIGATION`).

### 2.2 5 Mutation & Bypass Strategies
1. **String Concatenation & Character Encoding**: `'__cla' + 'ss__'`, `\x69\x64`, `('o' ~ 's')`, `chr(97)`.
2. **Attribute & Property Indirection**: `|attr('__class__')`, `['__class__']`, `['__mro__']`, `['__subclasses__']()`.
3. **Template Comment Inversion & Tag Variations**: `{##}`, `[#ftl]`, `<%# %>`, `//-`, `{{!-- --}}`.
4. **Filter & Whitespace Bypasses**: `\t`, `\n`, `%20`, tag whitespace expansion.
5. **Object Instantiation & Classloader Navigation**: `getClass().getClassLoader().loadClass()`, `T(java.lang.Runtime)`, index inversion.

### 2.3 Pipeline Integration & System Wiring
- **Tool Registry (`argus/runtime/registry.py`)**: Registered `Tool(id="ssti", capability="ssti_detector", priority=95)` and 25 alias lookups.
- **Plugin Adapter (`argus/runtime/plugins.py`)**: `PluginExecutorAdapter._instantiate_specialist_fallback()` instantiates `SSTICollector` for SSTI and template engine keywords.
- **Task Generator DAG (`argus/planning/task_generator.py`)**: Added `_RECON_TEMPLATES["ssti"]` with dependency `Discover API Endpoints`, gap resolution in `_resolve_template_for_gap()`, and dynamic endpoint binding in `from_gaps()`.
- **Attack Surface Graph (`argus/graph/attack_surface.py`)**: Section 23 creates `endpoint` and `vulnerability` nodes linked to `live_host` via `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- **CVSS & CWE Reporting (`argus/reporting/cvss.py`, `argus/reporting/processor.py`)**: Added `CWE-1336` (SSTI) and `CWE-94` (RCE) mappings with preset vectors (Critical 9.8, High 8.2) and default impact/remediation guidance.

---

## 3. Test Suites & Verification Results

- **Unit & Adversarial Tests**: `tests/collectors/test_ssti.py` and `tests/collectors/test_ssti_adversarial.py`
  - Total tests: 34 passed in 1.77s.
  - Coverage: Enums, models, payload generator, security analyzer, prober parameter injection, collector orchestration, quadruple state publishing, pipeline wiring, static reflection rejection, HTML/URL encoded reflection suppression, static baseline numbers rejection, hardened 400/404 handling, differential disambiguation (`{{7*'7'}}`), and 5 mutation strategies.
- **Full Workspace Regression**:
  - Command: `python -m pytest tests/ --ignore=tests/workspace -q`
  - Result: **1,648 passed, 0 failures, 0 regressions** (1,614 baseline + 34 new tests).

---

## 4. Multi-Agent Audit Verdicts

| Subagent | Role | Verdict |
|---|---|:---:|
| `worker_1` | SSTI Implementation Lead | DONE |
| `reviewer_1` | SSTI Code & Architecture Reviewer | APPROVE |
| `reviewer_2` | SSTI Pipeline & Robustness Reviewer | APPROVE |
| `challenger_1` | SSTI Adversarial Challenger 1 | APPROVE |
| `challenger_2` | SSTI Fingerprint Challenger 2 | APPROVE |
| `auditor_1` | SSTI Forensic Integrity Auditor | CLEAN |

---

## 5. Artifacts Created & Modified

- `argus/collectors/ssti.py` (Created)
- `argus/collectors/__init__.py` (Modified)
- `argus/runtime/registry.py` (Modified)
- `argus/runtime/plugins.py` (Modified)
- `argus/planning/task_generator.py` (Modified)
- `argus/graph/attack_surface.py` (Modified)
- `argus/reporting/cvss.py` (Modified)
- `argus/reporting/processor.py` (Modified)
- `tests/collectors/test_ssti.py` (Created)
- `tests/collectors/test_ssti_adversarial.py` (Created)
- `PROJECT.md` (Updated)
- `.agents/sprint22_ssti/handoff.md` (Created)
- `.agents/sprint_handoff.md` (Updated)
