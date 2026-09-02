## 2026-09-02T14:03:09Z
You are the Specialist Implementation Worker (Replacement Round 2) for ARGUS Sprint 29 (Prototype Pollution & Client-Side Attack Detection Module).
Working directory: /home/varun/argus
Agent metadata folder: /home/varun/argus/.agents/worker_impl_sprint29_r2

Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md, /home/varun/argus/PROJECT.md, and /home/varun/argus/.agents/orchestrator/implementation_plan.md before starting work.
Also review the survey handoff reports in /home/varun/argus/.agents/survey_explorer_1/handoff.md, /home/varun/argus/.agents/survey_explorer_2/handoff.md, and /home/varun/argus/.agents/survey_explorer_3/handoff.md for exact class structures and code blueprints.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Owned Files (Exclusive Write Ownership):
1. argus/collectors/prototype_pollution.py (New core collector module)
2. argus/collectors/__init__.py (Export collector, payload generator, prober, analyzer, results, enums, dataclasses, and aliases)
3. argus/planning/task_generator.py (DAG template, gap resolution, endpoint tool ID list)
4. argus/runtime/registry.py (Tool registration with capabilities, priority 95, and 15+ aliases)
5. argus/runtime/plugins.py (PluginExecutorAdapter fallback instantiation)
6. argus/scanning/engine.py (ScanEngine collector_class_map)
7. argus/graph/attack_surface.py (AttackSurfaceGraphBuilder.build_from_evidence Section 29)
8. argus/reporting/cvss.py (CWE-1321, CWE-79, CWE-601, CWE-1021 mappings and preset vectors)
9. tests/collectors/test_prototype_pollution.py (Core unit, component, analyzer, and state publishing tests)
10. tests/collectors/test_prototype_pollution_adversarial.py (Adversarial, evasion, mutation, and fault tolerance tests)
11. tests/collectors/test_prototype_pollution_pipeline.py (Pipeline DAG, registry, graph Section 29, and CVSS tests)

Requirements to Implement:
1. R1: Active Collector & Prober:
   - Create PrototypePollutionCollector inheriting from BaseCollector.
   - Implement _discover_candidate_endpoints, collect, execute, and _emit_evidence.
   - Quadruple State Publishing in _emit_evidence:
     a. raw_mission.evidence (EvidenceStore)
     b. raw_mission.vulnerabilities (List of dicts)
     c. attack_surface_graph KnowledgeGraph (live_host, endpoint, vulnerability nodes + HAS_ENDPOINT, HAS_VULNERABILITY edges)
     d. ControlledMission.publish_finding (if wrapped)
   - Aliases: ClientSideAttackCollector, DOMClobberingCollector, OpenRedirectCollector, ClickjackingCollector.
2. R2: Multi-Vector Client-Side Detection Modes:
   - Server-side prototype pollution: JSON injection (__proto__, constructor.prototype) with observable side effects (status codes, headers, body reflection, error state changes).
   - Client-side prototype pollution: URL fragment & query gadgets (location.hash, URLSearchParams) modifying Object.prototype.
   - DOM clobbering: named HTML elements (id/name) shadowing DOM APIs (document.cookie, document.body, document.getElementById, form elements).
   - Open redirect chains: unvalidated redirect parameters (url=, next=, redirect=, return_to=, continue=) with multi-hop redirect chain tracing (max_hops=5).
   - Clickjacking / UI redressing: missing X-Frame-Options and missing/permissive CSP frame-ancestors on sensitive endpoints.
3. R3: Prototype Pollution Gadget Analysis:
   - Framework gadgets (Express, Lodash, jQuery, Handlebars).
   - DoS via toString/valueOf pollution.
   - Node.js child_process.exec RCE gadget detection (shell, NODE_OPTIONS).
   - Nested property traversal depth analysis.
4. R4: 5 Mutation & Evasion Strategies:
   - JSON Key Encoding Variations (__proto__ vs \u005f\u005fproto\u005f\u005f vs constructor["prototype"]).
   - Content-Type Manipulation (application/json vs application/x-www-form-urlencoded vs multipart/form-data).
   - Redirect URL Encoding Layers (double encoding, Unicode fullwidth, scheme-relative //evil.com, authority @).
   - DOM Clobbering Payload Variants (<a> name vs id, <form>, <input>, <object>, <embed>, nested forms).
   - Frame-Busting Bypass Techniques (sandbox attributes, double framing, data: URI framing).
5. R5: Pipeline Connectivity:
   - Wire all 7 platform touchpoints (__init__.py, task_generator.py, registry.py, plugins.py, engine.py, attack_surface.py, cvss.py).
6. R6: Tests & Zero Regression:
   - Add at least 25 (target 50+) new tests across the 3 test files.
   - Run the full test suite (python -m pytest tests/ --ignore=tests/workspace -x -q) and verify 1,929+ existing tests continue to pass with 0 regressions.
