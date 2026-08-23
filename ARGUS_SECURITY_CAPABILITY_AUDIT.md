# ARGUS RUNTIME SECURITY CAPABILITY AUDIT

> **Audit Date:** 2026-08-20
> **Auditor:** Antigravity (AI Code Auditor)
> **Methodology:** Full static trace of every runtime path from source to subprocess/network. No assumptions made from class names, test mocks, or READMEs.

**Status Vocabulary:**
- 🟢 LIVE — Real code, verified by tracing every call frame to the OS boundary
- 🟡 PARTIAL — Real code exists, but critical links in the chain are missing
- 🟠 ANALYSIS ONLY — Code runs, produces output, but performs zero network activity
- 🔴 NOT IMPLEMENTED — No code exists for this capability
- ⚫ STUB/MOCK — Code exists but explicitly simulates rather than performs the behavior

---

## 1. Executive Summary

Argus is an **intelligence-layer platform** that has been mistaken for an **active attack platform**. The codebase contains a substantial, well-architected analysis engine — but at runtime, almost no security testing actually takes place.

**What Argus CAN do:**
- Run `subfinder`, `httpx-toolkit`, and `katana` as real subprocesses
- Run `nuclei` as a real subprocess, but discard its structured output
- Reason over existing evidence to produce investigations, hypotheses, and priority scores
- Drive a conversational AI workspace (Gemini/OpenAI/GitHub)
- Maintain a rich mission state graph with hypotheses, investigations, and correlation chains

**What Argus CANNOT do (despite extensive class scaffolding):**
- Send any HTTP request autonomously to a target (zero `requests`/`httpx` library calls to targets in the security engine)
- Mutate, fuzz, or replay any request
- Test for SQL injection, XSS, SSRF, CSRF, XXE, path traversal, or any OWASP category
- Perform real GraphQL introspection (the `acquire_schema` method is a stub — only returns data if the string `"introspection-enabled"` appears in the URL)
- Integrate with Burp Suite in any way
- Learn from PortSwigger labs
- Adaptively choose the next test based on the previous result

---

## 2. Runtime Architecture

```
                         ARGUS RUNTIME
+----------------------------------------------------------+
|                                                          |
|  Mission --> ReconAgent.execute()                        |
|                   |                                      |
|          +--------+-----------+                          |
|          |  Collector Loop    |                          |
|          | SubfinderCollector |-> subprocess("subfinder")|  LIVE
|          | HttpxCollector     |-> subprocess("httpx-tk") |  LIVE
|          | KatanaCollector    |-> subprocess("katana")   |  LIVE
|          | NucleiCollector    |-> subprocess("nuclei")   |  PARTIAL (output discarded)
|          | TechnologyCollect  |-> reads httpx JSON        |  LIVE
|          | JavaScriptCollect  |-> reads evidence store    |  ANALYSIS ONLY
|          +--------+-----------+                          |
|                   |                                      |
|  mission.subdomains / live_hosts / endpoints populated   |
|                   |                                      |
|          +--------+----------------------------+         |
|          | AuthenticationAnalyzer.analyze()    |  ANALYSIS ONLY
|          | APIIntelligence.analyze()           |  ANALYSIS ONLY
|          | BusinessObjectAnalyzer.analyze()    |  ANALYSIS ONLY
|          | KnowledgeGraphBuilder.build()       |  ANALYSIS ONLY
|          | Researcher.analyze() -> AI call    |  LIVE (OpenAI API)
|          | ReasoningEngine.generate()          |  ANALYSIS ONLY
|          +------------------------------------+         |
|                                                          |
|  PARALLEL PATH: AutonomousMissionRuntime                 |
|  (exists in code, NEVER instantiated/called anywhere)   |  DEAD CODE
|                                                          |
+----------------------------------------------------------+
```

### Key Architectural Gap

`AutonomousMissionRuntime.run()` in `argus/runtime/mission_runtime.py` defines a full mission loop (planning -> tool execution -> correlation -> hypothesis generation). **It is never instantiated or called from any CLI command, API endpoint, or test.** It is dead code.

---

## 3. Phase 1 — Terminal / External Tool Execution

### 3.1 Execution Mechanisms Found

| Mechanism | File | Real? |
|---|---|---|
| `subprocess.run()` | `argus/runtime/local.py` | 🟢 LIVE |
| `subprocess.run()` | `argus/runtime/sandbox.py` | 🟢 LIVE (via Sandbox.execute_command) |
| `subprocess.run()` | `argus/benchmark/leaderboard/ci.py` | BENCHMARK ONLY |
| `asyncio.create_subprocess_*` | — | 🔴 NOT IMPLEMENTED |
| `os.system` / `os.popen` / `shell=True` | — | 🔴 NOT IMPLEMENTED |

### 3.2 Tool-by-Tool Classification

| Tool | Registered | Collector | subprocess | stdout captured | Parsed to Evidence | Downstream | Classification |
|---|---|---|---|---|---|---|---|
| **subfinder** | YES registry.py | YES SubfinderCollector | YES local.py | YES | YES mission.subdomains (list[str]) | httpx, katana | 🟢 LIVE |
| **httpx** | YES registry.py | YES HttpxCollector | YES local.py | YES | YES mission.live_hosts (parsed JSON) | katana, technology | 🟢 LIVE |
| **katana** | YES registry.py | YES KatanaCollector | YES local.py | YES | YES mission.endpoints (list[dict]) | analysis plugins | 🟢 LIVE |
| **nuclei** | NO not in registry | YES NucleiCollector | YES local.py | YES | NO raw strings to mission.notes | nothing | 🟡 PARTIAL |
| **amass** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **assetfinder** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **dnsx** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **naabu** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **nmap** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **masscan** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **hakrawler** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **gau** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **waybackurls** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **ffuf** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **feroxbuster** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **gobuster** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **sqlmap** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **nikto** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **testssl** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **whatweb** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **WAF detection** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| **Custom shell commands** | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |

### 3.3 New Runtime Path (ToolOrchestrator — Sprint 11)

`ToolOrchestrator` -> `ToolDispatcher` -> `ExternalToolExecutor` -> `Sandbox.execute_command()` is architecturally complete and **real**. However:

- `ExternalToolExecutor.execute()` only has hardcoded argument resolution for `subfinder`, `httpx`, and `katana`
- Only `subfinder` output is parsed into `Evidence` objects. `httpx` and `katana` go into logs only
- `RemoteWorkerExecutor` is an explicit mock: calls `time.sleep(0.05)` and returns success
- `AutonomousMissionRuntime` (the caller of `ToolOrchestrator`) is **never instantiated anywhere** — dead code

### 3.4 Live Execution Runtime Path (Proven)

```
CLI: argus recon <target>
 -> ReconAgent.execute(mission)
    -> SubfinderCollector.collect(mission)
       -> LocalRuntime.run_command("subfinder", ["-d", target, "-silent"])
          -> subprocess.run(["subfinder", "-d", "target.com", "-silent"], capture_output=True)
             -> [REAL OS PROCESS] -> stdout
       -> ReconParser.parse_subfinder(stdout) -> mission.subdomains = [...]

    -> HttpxCollector.collect(mission)
       -> LocalRuntime.run_command("/usr/bin/httpx-toolkit", ["-json", "-silent"], stdin=subdomains)
          -> subprocess.run(["/usr/bin/httpx-toolkit", ...], capture_output=True)
             -> [REAL OS PROCESS] -> JSON per line
       -> ReconParser.parse_httpx(stdout) -> mission.live_hosts = [...]

    -> KatanaCollector.collect(mission)
       -> for host in mission.live_hosts:
             LocalRuntime.run_command("katana", ["-u", host["url"], "-silent"])
                -> [REAL OS PROCESS] -> stdout (URLs)
       -> ReconParser.parse_katana(stdout) -> mission.endpoints.append(...)

    -> NucleiCollector.collect(mission)
       -> LocalRuntime.run_command("nuclei", ["-u", host, "-silent", "-jsonl"])
          -> [REAL OS PROCESS] -> stdout (JSONL)
       -> raw strings -> mission.notes  (NOT converted to Evidence)
```

---

## 4. Phase 2 — Recon Capabilities

| # | Capability | File | Entry Point | Tool | Output | Evidence Object | Network | Classification |
|---|---|---|---|---|---|---|---|---|
| 1 | Subdomain enumeration | collectors/subfinder.py | ReconAgent.execute() | subfinder binary | mission.subdomains: list[str] | NO | YES real DNS | 🟢 LIVE |
| 2 | DNS enumeration | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED |
| 3 | HTTP probing / live hosts | collectors/httpx.py | ReconAgent.execute() | httpx-toolkit binary | mission.live_hosts: list[dict] | NO | YES real HTTP | 🟢 LIVE |
| 4 | Port discovery | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED |
| 5 | Service identification | collectors/httpx.py parser | via httpx JSON | httpx webserver field | host["server"] | NO | YES via httpx | 🟡 PARTIAL |
| 6 | Technology fingerprinting | collectors/technology.py | ReconAgent.execute() | httpx tech field | mission.evidence (Evidence objects) | YES | YES via httpx | 🟢 LIVE |
| 7 | Web crawling / endpoint discovery | collectors/katana.py | ReconAgent.execute() | katana binary | mission.endpoints: list[dict] | NO | YES real HTTP | 🟢 LIVE |
| 8 | Forced endpoint discovery | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED (no ffuf/gobuster) |
| 9 | JavaScript discovery | plugins/javascript/discovery.py | JavaScriptDiscovery.discover() | reads mission.evidence | mission.javascript.files | YES | NO | 🟠 ANALYSIS ONLY |
| 10 | Source map discovery | plugins/javascript/discovery.py | sourceMappingURL pattern match | — | mission.javascript.sourcemaps | YES | NO | 🟠 ANALYSIS ONLY |
| 11 | API discovery | plugins/api/agent.py | APIIntelligenceSpecialist.analyze() | heuristic on endpoints | mission.api_intelligence | YES | NO | 🟠 ANALYSIS ONLY |
| 12 | GraphQL discovery | plugins/graphql/discovery.py | GraphQLDiscovery.discover() | path pattern + evidence scan | mission.graphql.endpoints | YES | NO | 🟠 ANALYSIS ONLY |
| 13 | GraphQL introspection | plugins/graphql/schema.py:61-66 | acquire_schema() | NONE | NONE | NO | NO | ⚫ STUB |
| 14 | Parameter discovery | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED |
| 15 | Historical URL discovery | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED (no gau/waybackurls) |
| 16 | Cloud asset discovery | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED |
| 17 | Certificate/subdomain intelligence | — | — | — | — | — | NO | 🔴 NOT IMPLEMENTED |

### Critical Finding: GraphQL Introspection is a Stub

`acquire_schema(url)` at `schema.py` line 62:
```python
def acquire_schema(self, url: str) -> Optional[GraphQLSchema]:
    if "introspection-enabled" in url:   # <-- will NEVER be true on a real target
        schema = GraphQLSchema(source="Introspection", evidence=[])
        ...
        return schema
    return None
```
This never contacts a real GraphQL endpoint. Introspection is not implemented.

### Critical Finding: Nuclei Output is Discarded

`NucleiCollector` runs `nuclei -u <host> -silent -jsonl` as a real subprocess and captures stdout. But:
```python
for line in result["stdout"].splitlines():
    if line.strip():
        findings.append(line)        # raw string, not parsed
mission.notes.extend(findings)       # appended to notes, not Evidence
```
No JSON parsing. No Evidence object. No Investigation. Nuclei results are silently discarded by the rest of the system.

---

## 5. Phase 3 — OWASP Top 10 Coverage

| OWASP Category | Subcapability | Classification | Notes |
|---|---|---|---|
| **A01 Broken Access Control** | | | |
| | IDOR / BOLA detection | 🟠 ANALYSIS ONLY | ObjectUpdateEndpointHeuristic flags PUT/PATCH endpoints; flags for manual review |
| | Horizontal privilege escalation | 🟠 ANALYSIS ONLY | CrossTenantObjectHeuristic flags objects missing tenant ownership in graph |
| | Vertical privilege escalation | 🟠 ANALYSIS ONLY | MultiRoleResourceHeuristic flags multi-role resources |
| | Forced browsing | 🔴 NOT IMPLEMENTED | No ffuf/gobuster |
| | Missing function-level authorization | 🟠 ANALYSIS ONLY | AdministrativeEndpointHeuristic flags /admin, /manage, /system paths |
| | Nested resource authorization | 🟠 ANALYSIS ONLY | NestedResourceHeuristic flags multi-param paths |
| | Active authorization testing | 🔴 NOT IMPLEMENTED | No requests sent with alternate tokens |
| **A02 Cryptographic Failures** | | | |
| | TLS/certificate analysis | 🔴 NOT IMPLEMENTED | No testssl, no openssl calls |
| | Weak cipher detection | 🔴 NOT IMPLEMENTED | |
| | Cookie security flags | 🟠 ANALYSIS ONLY | SessionLifecycleHeuristic checks Secure/HttpOnly from evidence |
| | JWT algorithm confusion | 🔴 NOT IMPLEMENTED | |
| **A03 Injection** | | | |
| | SQL injection | 🔴 NOT IMPLEMENTED | No payloads, no requests, no comparison |
| | NoSQL injection | 🔴 NOT IMPLEMENTED | |
| | OS command injection | 🔴 NOT IMPLEMENTED | |
| | SSTI | 🔴 NOT IMPLEMENTED | |
| | GraphQL injection | 🔴 NOT IMPLEMENTED | |
| | Nuclei template scanning | 🟡 PARTIAL | Nuclei runs but output not parsed into findings |
| **A04 Insecure Design** | | | |
| | State machine bypass | 🟠 ANALYSIS ONLY | UnexpectedStateTransitionHeuristic, MissingPrerequisiteHeuristic |
| | Workflow shortcut attacks | 🟠 ANALYSIS ONLY | WorkflowShortcutHeuristic |
| | Replay attack detection | 🟠 ANALYSIS ONLY | ReplayableTransactionHeuristic |
| **A05 Security Misconfiguration** | | | |
| | Default credentials | 🔴 NOT IMPLEMENTED | |
| | Open CORS | 🔴 NOT IMPLEMENTED | |
| | Missing security headers | 🔴 NOT IMPLEMENTED | |
| **A06 Vulnerable/Outdated Components** | | | |
| | Technology fingerprinting | 🟢 LIVE | TechnologyCollector from httpx JSON |
| | CVE cross-reference | 🔴 NOT IMPLEMENTED | No CVE lookup |
| | Nuclei vulnerability scan | 🟡 PARTIAL | Nuclei runs; results not parsed |
| **A07 Authentication Failures** | | | |
| | Mechanism detection | 🟠 ANALYSIS ONLY | AuthenticationIntelligenceSpecialist analyzes existing evidence |
| | Session cookie analysis | 🟠 ANALYSIS ONLY | SessionLifecycleHeuristic |
| | OAuth detection | 🟠 ANALYSIS ONLY | OAuthIntegrationHeuristic |
| | Brute force / rate limit testing | 🔴 NOT IMPLEMENTED | |
| | MFA bypass testing | 🔴 NOT IMPLEMENTED | |
| **A08 Software/Data Integrity Failures** | | | |
| | File upload analysis | 🟠 ANALYSIS ONLY | FileUploadSpecialist heuristics over existing evidence |
| | Deserialization detection | 🔴 NOT IMPLEMENTED | |
| **A09 Security Logging/Monitoring Failures** | | | |
| | Any detection | 🔴 NOT IMPLEMENTED | |
| **A10 SSRF** | | | |
| | SSRF surface identification | 🟠 ANALYSIS ONLY | DataImportExportHeuristic mentions SSRF in manual validation steps |
| | Active SSRF testing | 🔴 NOT IMPLEMENTED | No payload, no Burp Collaborator equivalent |

---

## 6. Phase 4 — PortSwigger Web Security Academy Coverage

No PortSwigger-specific code exists anywhere in the codebase.

| Topic | Discover Surface? | Generate Hypothesis? | Send Requests? | Mutate? | Compare Responses? | Validate? | Produce Finding? | Classification |
|---|---|---|---|---|---|---|---|---|
| SQL injection | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Cross-site scripting (XSS) | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| CSRF | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Clickjacking | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| DOM-based vulnerabilities | PARTIAL | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| CORS | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| XXE injection | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| SSRF | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| HTTP request smuggling | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| OS command injection | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Server-side template injection | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Path traversal | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Access control | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| Authentication | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| WebSockets | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Web cache poisoning | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Insecure deserialization | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Information disclosure | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| Business logic vulnerabilities | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| HTTP Host header attacks | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| OAuth authentication | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| File upload vulnerabilities | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| JWT attacks | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Prototype pollution | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| GraphQL API vulnerabilities | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| Race conditions | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| NoSQL injection | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| API testing | PARTIAL | PARTIAL | NO | NO | NO | NO | NO | 🟠 ANALYSIS ONLY |
| Web LLM attacks | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |
| Web cache deception | NO | NO | NO | NO | NO | NO | NO | 🔴 NOT IMPLEMENTED |

**Summary: 0 topics FULLY or PARTIALLY AUTONOMOUS. 11 ANALYSIS ONLY. 19 NOT IMPLEMENTED.**

---

## 7. Phase 5 — PortSwigger Lab Training Architecture

Zero PortSwigger-related code exists anywhere in the codebase. No lab loader, no observation extractor, no technique generalizer, no training representation.

### What Would Be Required

```
LAB OBSERVATION (HTTP traffic capture)
      |
Vulnerability class classifier
      |
Precondition extractor (authentication state, parameter presence, etc.)
      |
Attack surface indicator model (reflection context, URL fetch vectors, etc.)
      |
Hypothesis generation rules (generalizable)
      |
Candidate test strategy generator
      |
Response observation model (status codes, body diff, timing, OOB callbacks)
      |
Validation strategy (what constitutes proof)
      |
Evidence requirements schema
      |
Generalized technique representation
      |
Knowledge Graph entry (stored in KnowledgeManager with CWE/OWASP tags)
```

### What Argus Has Today

| Component | Status |
|---|---|
| KnowledgeManager with CWE/OWASP/CAPEC search | 🟢 IMPLEMENTED (but empty — no knowledge entries loaded) |
| KnowledgeEntry model | 🟢 IMPLEMENTED |
| Lab observation ingestion | 🔴 NOT IMPLEMENTED |
| Vulnerability class classifier from HTTP traffic | 🔴 NOT IMPLEMENTED |
| Generalized technique extractor | 🔴 NOT IMPLEMENTED |
| Knowledge graph population from observations | 🔴 NOT IMPLEMENTED |
| KnowledgeManager connected to planning/hypothesis | 🔴 NOT IMPLEMENTED |

### Critical Gap

`Mission.get_relevant_knowledge(manager)` exists and queries `KnowledgeManager` by business object and technology. **But no code in any planning or hypothesis component calls this method.** The knowledge system is a standalone CRUD store with zero integration into the security reasoning pipeline.

---

## 8. Phase 6 — Autonomous Intelligence

### 8.1 Intelligence Capabilities

The chain `Observations -> CorrelationEngine -> EvidenceBundleRegistry -> InvestigationBuilder -> HypothesisEngine` exists in `mission_runtime.py` and is real code. However, observations feeding it come exclusively from static analysis of existing evidence — not from adaptive test execution.

| Intelligence Capability | Status | Code Location |
|---|---|---|
| Hypothesis generation from investigations | 🟢 IMPLEMENTED | hypothesis/generator.py |
| Hypothesis ranking | 🟢 IMPLEMENTED | hypothesis/ranking.py |
| Confidence scoring | 🟢 IMPLEMENTED | hypothesis/confidence.py |
| Evidence correlation | 🟢 IMPLEMENTED | correlation/engine.py |
| Evidence fusion | 🟢 IMPLEMENTED | correlation/fusion.py |
| Investigation scoring/priority (10 factors) | 🟢 IMPLEMENTED | investigation/scoring.py |
| Attack-surface heuristics | 🟠 ANALYSIS ONLY | All */heuristics.py files |
| Adaptive testing (choose next test from evidence) | 🔴 NOT IMPLEMENTED | No code sends requests |
| Contextual payload generation | 🔴 NOT IMPLEMENTED | No payload templates |
| Response differential analysis | 🔴 NOT IMPLEMENTED | No request/response comparison |
| Cross-user reasoning with active requests | 🔴 NOT IMPLEMENTED | Cannot send requests |
| Abandoning/escalating hypotheses via testing | 🔴 NOT IMPLEMENTED | Hypotheses ranked but never tested |

### 8.2 The Fundamental Gap

Argus implements a sophisticated `Observe -> Reason -> Hypothesize` loop, but is permanently stuck there. The `Hypothesize -> Test -> Observe -> Update` cycle required for true autonomous security testing does not exist. There is no mechanism to:

1. Take a ranked hypothesis
2. Derive test requests for it
3. Send those requests to the target
4. Observe the response
5. Update the hypothesis confidence
6. Choose the next action

---

## 9. Phase 7 — Burp Suite Professional Integration

```
grep -r "burp|montoya|BApp|repeater|collaborator" /home/varun/argus/argus --include="*.py" -i
(no results)
```

| Integration Point | Status |
|---|---|
| Burp currently integrated | 🔴 NOT IMPLEMENTED |
| Burp extension / BApp | 🔴 NOT IMPLEMENTED |
| Montoya API adapter | 🔴 NOT IMPLEMENTED |
| Send requests through Burp Proxy | 🔴 NOT IMPLEMENTED |
| Retrieve HTTP history from Burp | 🔴 NOT IMPLEMENTED |
| Burp findings to Argus Evidence | 🔴 NOT IMPLEMENTED |
| Send requests to Repeater | 🔴 NOT IMPLEMENTED |
| Use Burp Scanner | 🔴 NOT IMPLEMENTED |
| Burp Collaborator / OAST callbacks | 🔴 NOT IMPLEMENTED |
| Mission/target/scope synchronization | 🔴 NOT IMPLEMENTED |

**Zero Burp integration exists. Not a single reference to Burp Suite anywhere in the codebase.**

---

## 10. Phase 8 — End-to-End Proof

### 10.1 Verified Paths

| Category | Path | Verdict |
|---|---|---|
| LIVE: Subfinder | SubfinderCollector -> LocalRuntime -> subprocess.run("subfinder") -> mission.subdomains | Proven by code trace; requires subfinder binary |
| LIVE: httpx | HttpxCollector -> LocalRuntime -> subprocess.run("/usr/bin/httpx-toolkit") -> mission.live_hosts | Proven by code trace; requires httpx-toolkit binary |
| LIVE: katana | KatanaCollector -> LocalRuntime -> subprocess.run("katana") -> mission.endpoints | Proven by code trace; requires katana binary |
| LIVE: AI Research | Researcher.analyze() -> GitHubClient.research() -> openai API -> network | Proven by code; requires valid API key |
| ANALYSIS ONLY: Correlation | CorrelationEngine.process_observation() -> in-memory graph | Unit tested without network |
| ANALYSIS ONLY: Hypothesis | HypothesisEngine.evaluate_all() -> HypothesisGenerator | Unit tested without network |
| ANALYSIS ONLY: Authz heuristics | AuthorizationSpecialist -> AUTHZ_HEURISTIC_REGISTRY -> Investigation objects | Unit tested without network |

### 10.2 Test Coverage Classification

| Test Type | Files | What They Actually Prove |
|---|---|---|
| Unit Tests | tests/workspace/, tests/hypothesis/, tests/correlation/ | Internal logic correctness. No network, no binaries. |
| Integration Tests | tests/workspace/test_web.py, test_persistence.py | FastAPI endpoints via TestClient. No external network. |
| End-to-End Tests | NONE | — |
| Live Target Tests | NONE | — |

**WARNING: There are zero end-to-end tests and zero live-target tests. All 474 passing tests are unit or internal integration tests. They do not prove Argus can perform security testing on a real target.**

---

## 11. Phase 9 — Final Report Matrices

### 11.1 Evidence Pipeline Matrix

| Stage | Component | Status | Evidence Object? |
|---|---|---|---|
| Raw tool output to structured data | ReconParser | 🟢 LIVE | No (plain lists) |
| Subfinder result to Evidence | ExternalToolExecutor (new path, dead) | 🟢 IMPLEMENTED | YES (but path never called) |
| httpx result to Evidence | TechnologyCollector | 🟢 LIVE | YES (technology category) |
| Nuclei result to Evidence | NucleiCollector | 🔴 BROKEN | NO |
| Heuristic output to Investigation | All specialist */heuristics.py | 🟢 IMPLEMENTED | YES Investigation objects |
| Investigation to Hypothesis | HypothesisGenerator | 🟢 IMPLEMENTED | YES Hypothesis objects |
| Hypothesis to Finding/Report | — | 🔴 NOT IMPLEMENTED | No reporting engine |

### 11.2 Autonomous Reasoning Matrix

| Capability | Status |
|---|---|
| Observation ingestion | 🟢 IMPLEMENTED |
| Observation correlation | 🟢 IMPLEMENTED |
| Evidence fusion | 🟢 IMPLEMENTED |
| Investigation building | 🟢 IMPLEMENTED |
| Hypothesis generation | 🟢 IMPLEMENTED |
| Hypothesis ranking | 🟢 IMPLEMENTED |
| Adaptive test selection | 🔴 NOT IMPLEMENTED |
| Payload generation | 🔴 NOT IMPLEMENTED |
| Request mutation | 🔴 NOT IMPLEMENTED |
| Response comparison | 🔴 NOT IMPLEMENTED |
| Finding validation | 🔴 NOT IMPLEMENTED |
| Report generation | 🔴 NOT IMPLEMENTED |

### 11.3 Confirmed False Positives / Inflated Claims

| Item | Claimed | Reality |
|---|---|---|
| GraphQLSchemaAnalyzer.acquire_schema() | GraphQL introspection | STUB — returns mock data only if "introspection-enabled" is in the URL |
| RemoteWorkerExecutor.execute() | Remote tool dispatch | MOCK — calls time.sleep(0.05) and returns success |
| AutonomousMissionRuntime.run() | Full autonomous mission loop | DEAD CODE — never instantiated anywhere |
| Mission.get_relevant_knowledge() | Knowledge-driven mission planning | DISCONNECTED — no caller in planning or hypothesis code |
| NucleiCollector.collect() | Vulnerability scanning | PARTIAL — runs nuclei but discards structured output |

### 11.4 Dead Code

| File | Dead Component | Reason |
|---|---|---|
| runtime/mission_runtime.py | AutonomousMissionRuntime | Never instantiated in any CLI, API, or test |
| runtime/executor.py | RemoteWorkerExecutor | Explicit mock, no real dispatch |
| plugins/graphql/schema.py:61-66 | acquire_schema() | Stub predicate never true on real targets |
| runtime/mission.py:235-252 | get_relevant_knowledge() | Never called by any planning/hypothesis component |
| ai/openai_client.py | OpenAIClient | Empty file (0 bytes) |

---

## 12. Missing Capabilities — Recommended Implementation Order

### Priority 1 — Connect What Already Exists (No new architecture needed)

1. **Wire AutonomousMissionRuntime to a CLI command.** It exists, it is complete, it is just never called.
2. **Parse Nuclei output into Evidence objects.** Add ReconParser.parse_nuclei_jsonl() and populate mission.evidence.
3. **Implement real GraphQL introspection.** Replace the stub with an actual `requests.post(url, json={"query": INTROSPECTION_QUERY})`.
4. **Connect KnowledgeManager to ResearchPlanner.** KnowledgeManager.search() is fully implemented but never queried during mission planning.
5. **Add Evidence objects to Subfinder/Katana outputs.** Both collectors write to plain Python lists. Wrap in Evidence objects to enter the correlation engine.

### Priority 2 — HTTP Request Engine (Critical missing component)

6. **Add HttpRequestEngine** — thin wrapper around httpx/requests that:
   - Validates scope before sending
   - Records every request/response as an Evidence object
   - Supports session management, auth headers, proxy routing

7. **Add RequestMutator** — takes a captured request and generates variants (different parameter values, headers, HTTP methods).

8. **Add ResponseDifferentialAnalyzer** — compares two responses for behaviorally significant differences.

### Priority 3 — Vulnerability Validation

9. **IDOR/BOLA validator** — for each ObjectUpdateEndpointHeuristic finding, send same request with alternate token and compare responses.
10. **Real GraphQL introspection + alias batching + subscription exposure checks.**
11. **Authentication weakness tester** — send malformed tokens, expired tokens, no tokens to auth-required endpoints.

### Priority 4 — PortSwigger Lab Training Architecture

12. **Lab Observation Loader** — import HAR/HTTP archive from a completed lab session.
13. **Technique Extractor** — converts a lab session into a generalized KnowledgeEntry with CWE, attack class, preconditions, validation requirements.
14. **Hypothesis Template Generator** — converts KnowledgeEntry into a hypothesis template for HypothesisGenerator.
15. **Burp Suite Integration** — Montoya API extension to push HTTP history into Argus evidence store.

---

## 13. Summary Scorecard

| Dimension | Score | Notes |
|---|---|---|
| External tool execution | 3/21 tools wired | subfinder, httpx, katana live; nuclei partial; 17 not implemented |
| Recon capabilities | 4/17 live | subdomain, HTTP probe, crawl, technology; rest analysis-only or not implemented |
| OWASP Top 10 active testing | 0/10 | Zero active testing for any category |
| PortSwigger topic coverage | 0/29 | Zero active capability for any topic |
| Burp Suite integration | 0/10 | Completely absent |
| Autonomous reasoning pipeline | 6/12 steps | Full through hypothesis generation; breaks at test dispatch |
| End-to-end proven tests | 0 | All tests are unit/mock |
| PortSwigger lab training | 0% | No architecture exists |

**Conclusion:** Argus is a well-built intelligence and analysis platform with a sophisticated reasoning engine, correlation system, and hypothesis generator. It is NOT yet a security testing platform. The single most critical missing component is an HTTP request engine — without it, every downstream validation capability remains theoretical.
