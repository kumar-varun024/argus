# ARGUS — Complete Project Context & Claude Handoff

## Purpose

This document is a handoff package for Claude or another coding agent. It captures the Argus project's purpose, architecture, historical decisions, implementation audits, current gaps, provider setup, runtime-plumbing work, recon-tool integration, PortSwigger goals, and the planned Burp Suite Professional integration.

**Important:** Treat claims below as historical project context unless independently verified against the current repository. Before changing code, inspect the current branch, git diff, callers, tests, and runtime reachability.

---

# 1. What Argus Is

**Argus** is an autonomous offensive-security research/orchestration platform.

The goal is not to build a collection of disconnected security tools. Argus should intelligently:

1. Accept an authorized target and scope.
2. Plan a security research mission.
3. Discover the target attack surface.
4. Use real security tooling through a controlled execution layer.
5. Normalize tool output into structured evidence.
6. Build observations, relationships, and knowledge-graph context.
7. Generate evidence-grounded vulnerability hypotheses.
8. Investigate and validate hypotheses.
9. Correlate evidence.
10. Produce useful, grounded findings.
11. Learn from previous research and security knowledge.
12. Integrate **Burp Suite Professional** as a first-class capability/source.
13. Cover broad web-application security, including OWASP-style vulnerabilities and PortSwigger Web Security Academy concepts, without becoming dependent on the labs themselves.

The desired core loop is:

```text
OBSERVE
  ↓
UNDERSTAND
  ↓
PLAN
  ↓
EXECUTE
  ↓
COLLECT EVIDENCE
  ↓
UPDATE KNOWLEDGE
  ↓
FORM HYPOTHESIS
  ↓
INVESTIGATE
  ↓
CORRELATE
  ↓
DECIDE
  ↓
PLAN NEXT ACTION
```

---

# 2. Core Architecture

The desired architecture is:

```text
Target + Scope
      |
      v
Mission
      |
      v
Research Planner
      |
      v
Task Graph / Dependencies
      |
      v
Tool Orchestrator
      |
      +-----------------------------+
      |                             |
      v                             v
External Security Tools       Internal Specialists/Plugins
      |                             |
      +-------------+---------------+
                    |
                    v
               Evidence
                    |
                    v
              Observations
                    |
                    v
          Knowledge / Graph Context
                    |
                    v
              Hypotheses
                    |
                    v
             Investigation
                    |
                    v
              Correlation
                    |
                    v
                 Findings
```

A critical design principle:

> **LLM reasoning chooses what should be investigated; deterministic runtime infrastructure decides what can actually execute, within scope and safety constraints.**

The LLM should not bypass the tool registry, scope controls, authorization gates, or execution safety layer by inventing arbitrary commands.

---

# 3. Long-Term Security Capability Goals

Argus should eventually cover:

## Recon

- Subdomain enumeration.
- Live host detection.
- Technology fingerprinting.
- Endpoint discovery/crawling.
- JavaScript discovery and analysis.
- API discovery.
- GraphQL discovery and schema analysis.
- File-upload surface discovery.
- Authentication surface discovery.
- Authorization surface discovery.
- Business-logic/workflow discovery.

## Security analysis/testing

The target capability set includes broad classes such as:

- Authentication weaknesses.
- Authorization/access-control failures.
- IDOR-style/object-level authorization problems.
- Business logic flaws.
- API security issues.
- GraphQL security.
- JavaScript/client-side exposure.
- File-upload weaknesses.
- Injection classes.
- XSS classes.
- SSRF.
- CSRF.
- Request smuggling/parser differential issues.
- Path traversal.
- Deserialization.
- Command/code execution classes.
- Information disclosure.
- Misconfiguration.
- Web-cache-related issues.
- WebSocket issues.
- OAuth/authentication flow issues.
- JWT/session problems.
- Race conditions.
- Host-header issues.
- Prototype-pollution/client-side issues.
- Next.js-specific exposures.
- `/_next` and source-map exposure.
- Middleware analysis.
- Other framework-specific security intelligence.

The goal is not a checklist-only scanner. Argus should reason about novel combinations and cases it was not explicitly hard-coded for.

---

# 4. PortSwigger Web Security Academy Goal

A major future objective is to make Argus capable of handling concepts represented across PortSwigger Web Security Academy labs.

The labs should be treated as:

- Training/reference material.
- Scenario examples.
- Coverage benchmarks.
- Regression cases where appropriate.

**They must not become the sole source of intelligence.**

Argus should learn the underlying security concepts and generalize them to applications and workflows outside the exact lab scenarios.

At the time of the security capability audit, PortSwigger topic coverage was assessed as **0/29**.

---

# 5. Burp Suite Professional Requirement

Burp Suite Professional is a major long-term requirement.

The user explicitly prefers **Burp Suite Professional** for Argus's Burp integration/workflows.

The eventual integration should allow Argus to consume and potentially use Burp-derived data/workflows such as:

- Proxy traffic.
- HTTP history.
- Site map.
- Requests/responses.
- Repeater workflows.
- Scanner findings where appropriate.
- Selected requests for deeper investigation.

The architecture should feed Burp data into the existing evidence pipeline:

```text
Burp Suite Professional
        |
        v
Burp-derived Evidence
        |
        v
Argus Evidence / Observation layer
        |
        v
Correlation / Hypothesis / Investigation
```

Do **not** create a second independent orchestration architecture around Burp.

At the security capability audit point, Burp integration was **0**: there was no Burp reference in the codebase.

---

# 6. Repository Areas

Important areas include:

```text
argus/
├── agents/
├── authorization/
├── benchmark/
├── cli/
├── collectors/
├── correlation/
├── evidence/
├── hypothesis/
├── investigation/
├── learning/
├── planning/
├── plugins/
├── runtime/
├── workspace/
└── ...
```

Important files/components discussed:

```text
argus/workspace/
argus/workspace/provider_router.py
argus/workspace/provider.py

argus/runtime/mission_runtime.py
argus/runtime/controller.py
argus/runtime/executor.py
argus/runtime/orchestrator.py
argus/runtime/dispatcher.py
argus/runtime/registry.py
argus/runtime/parser.py

argus/planning/
argus/hypothesis/
argus/evidence/
argus/correlation/
argus/investigation/
argus/authorization/
argus/plugins/
```

---

# 7. Provider / LLM Architecture

Argus uses a multi-provider `ProviderRouter`.

The active Workspace architecture uses the ProviderRouter rather than the legacy AI client.

Providers discussed/configured include:

- GitHub Models.
- NVIDIA.
- NVIDIA Ultra.
- Gemini.
- DeepSeek.
- OpenAI.
- Grok/XAI.

Environment concepts include:

```text
ARGUS_PRIMARY_PROVIDER
ARGUS_PRIMARY_MODEL
ARGUS_PROVIDER_ORDER

GITHUB_API_KEY
GITHUB_MODEL
GITHUB_API_BASE

NVIDIA_API_KEY
NVIDIA_MODEL_NAME
NVIDIA_API_BASE

NVIDIA_ULTRA_API_KEY
NVIDIA_ULTRA_MODEL_NAME
NVIDIA_ULTRA_API_BASE

GEMINI_API_KEY
GEMINI_MODEL_NAME

DEEPSEEK_API_KEY
DEEPSEEK_MODEL_NAME
DEEPSEEK_API_BASE

OPENAI_API_KEY
OPENAI_MODEL_NAME
OPENAI_API_BASE

GROK/XAI credentials/model variables
```

Always inspect the current repository's provider router before assuming exact variable names.

---

# 8. Provider Priority / Routing History

The active provider priority is controlled by:

```text
ARGUS_PRIMARY_PROVIDER
ARGUS_PROVIDER_ORDER
```

An example used during development:

```text
ARGUS_PRIMARY_PROVIDER=nvidia
ARGUS_PROVIDER_ORDER=nvidia,gemini,deepseek,github,grok
```

A router inspection showed:

```text
1  nvidia
11 gemini
12 deepseek
13 github
31 nvidia_ultra
```

The user later wanted NVIDIA Ultra moved higher because other providers were not reliably working.

Provider order should be checked from the current `.env`, not assumed from this historical example.

---

# 9. Legacy Provider Configuration

A critical discrepancy was discovered:

`ARGUS_AI_PROVIDER` is a legacy configuration concept.

The active Workspace provider system uses:

```text
ARGUS_PRIMARY_PROVIDER
ARGUS_PROVIDER_ORDER
```

The legacy:

```text
argus/ai/client.py
```

contains `NotImplementedError` and is effectively superseded by ProviderRouter.

`argus/config.py` also contains legacy provider references.

Do not remove legacy code blindly; first check imports and runtime reachability.

---

# 10. Provider Verification

The test:

```bash
python -m pytest tests/workspace/test_provider_router.py -v
```

returned:

```text
12 passed
8 warnings
```

Tests included:

- Single provider success.
- GitHub provider route.
- Primary provider priority.
- 429 failover.
- Non-retryable errors.
- Cooldown behavior.
- All providers fail.
- Disabled/missing credentials.
- Streaming success.
- Streaming failure before tokens.
- Streaming failure after tokens.
- Mock fallback.

OpenAI direct verification historically produced:

```text
GET /models -> HTTP 200
POST /chat/completions -> HTTP 429
```

with:

```text
insufficient_quota
```

This indicated the key was accepted enough to access `/models`, but the account/key had no usable completion quota at that time.

Later the user confirmed that an Argus model was working and providing answers, so the current provider state should be verified rather than relying on the historical OpenAI failure.

---

# 11. ProviderRouter Implementation Pattern

OpenAI-compatible providers are built using a pattern equivalent to:

```python
prefix = name.upper()
api_key = os.environ.get(f"{prefix}_API_KEY")
if not api_key:
    return None

api_base = os.environ.get(
    f"{prefix}_API_BASE",
    default_base
)

model = os.environ.get(
    f"{prefix}_MODEL_NAME",
    default_model
)
```

Gemini has a dedicated builder.

GitHub has a dedicated builder.

Failover behavior:

- 401/403 permanently disables a route.
- Retryable errors receive cooldown.
- 429 is retryable and causes fallback.
- Streaming failure paths are tested.

---

# 12. Initial Feature Audit

An earlier audit reported these as implemented/tested:

1. Conversation persistence.
2. Conversation search.
3. Conversation rename.
4. Auto-title generation.
5. Context restoration.
6. Streaming.
7. Multimodal/vision.
8. Provider priority/failover.
9. Auth failure cooldown.
10. Authentication Agent.
11. Business Logic Specialist.
12. Hypothesis generation.
13. ScopeResolver.
14. EvidenceManager.
15. Knowledge Graph semantic search.
16. Correlation Engine.
17. Mission State Machine.
18. GraphQL Plugin.
19. JavaScript Plugin.
20. API/File Upload plugins.
21. Benchmarking Leaderboard.

This was later qualified by the deeper security capability audit: many components existed but were not connected into a true autonomous target-testing pipeline.

---

# 13. Legacy Specialist Agents

The old:

```text
argus/agents/specialists/*
```

subsystem contains stubs/placeholders.

Examples included:

- `pass`.
- Placeholder `think`/`evaluate`.
- Hardcoded recommendation appends.

The modern implementations were moved into:

```text
argus/plugins/*
```

This is a classic architectural migration that was not fully pruned.

Do not assume the legacy specialist files are active.

---

# 14. Legacy Benchmark Runner

```text
argus/performance/benchmark.py
```

was identified as a legacy/stub implementation.

The active benchmark system is:

```text
argus/benchmark/runner/
```

with benchmark CLI support.

---

# 15. Correlation Serializer

```text
argus/correlation/serializer.py
```

was identified as incomplete because it can raise `NotImplementedError` for complex recursive graph payloads.

This is technical debt.

---

# 16. Security Capability Audit — Historical Baseline

A comprehensive security audit reported:

| Dimension | Historical result |
|---|---:|
| External tools wired end-to-end | 3 / 21 |
| Recon capabilities live | 4 / 17 |
| OWASP Top 10 active testing | 0 / 10 |
| PortSwigger topic coverage | 0 / 29 |
| Burp Suite integration | 0 |
| Autonomous reasoning pipeline | 6 / 12 steps |
| End-to-end tests | 0 |
| PortSwigger lab training | 0% |

The three externally wired tools were:

- subfinder
- httpx
- katana

Nuclei could execute but its original output path had a major evidence-integration problem.

---

# 17. Five Major Security Audit Findings

## 17.1 AutonomousMissionRuntime was effectively unreachable

The autonomous mission loop existed architecturally but historically was not actually instantiated through a usable runtime path.

This became the focus of Sprint 0 runtime plumbing.

## 17.2 GraphQL introspection was a stub

The old `acquire_schema()` implementation in:

```text
argus/plugins/graphql/schema.py
```

did not perform genuine GraphQL introspection. It used placeholder behavior.

The desired implementation is:

```text
POST GraphQL introspection query
        ↓
JSON schema
        ↓
GraphQLSchema
        ↓
business analysis
        ↓
evidence/observations
```

with inference as a fallback.

## 17.3 Nuclei output was discarded

The original collector:

```text
argus/collectors/nuclei.py
```

ran Nuclei and appended raw JSONL strings to `mission.notes`.

The newer runtime executor/parser path can normalize Nuclei into structured evidence, but both paths exist and the active path must be verified.

## 17.4 Argus had no general autonomous target HTTP request layer

At the time of the audit, Argus's own code did not generally perform target requests itself; most network activity came through external binaries.

A future controlled HTTP layer is needed for intelligent active testing.

It must enforce:

- scope
- authorization
- rate limits
- evidence capture
- provenance
- safe logging

## 17.5 KnowledgeManager was isolated

KnowledgeManager had CWE/OWASP/CAPEC knowledge structures but was not sufficiently queried by the planning/reasoning pipeline.

Sprint 0 includes connecting KnowledgeManager to ResearchPlanner.

---

# 18. External Tooling

The following binaries were confirmed installed during development:

```text
subfinder
/home/varun/go/bin/subfinder

httpx-toolkit
/usr/bin/httpx-toolkit

katana
/home/varun/go/bin/katana

nuclei
/usr/bin/nuclei
```

Versions observed:

```text
subfinder v2.14.0
httpx-toolkit v1.9.0
katana v1.6.1
nuclei v3.11.0
```

The current Argus registry includes these as external tools.

---

# 19. Tool Registry

`argus/runtime/registry.py` currently registers external tools:

```text
subfinder
httpx
katana_crawler
nuclei
```

and internal specialist tools:

```text
graphql_specialist
javascript_specialist
authorization_specialist
authentication_specialist
file_upload_specialist
api_specialist
business_logic_specialist
```

External tools have:

- command
- supported tasks
- required inputs
- produced outputs
- capabilities
- safety requirements
- timeout
- priority

Internal tools are executed through internal plugin execution.

---

# 20. Tool Dispatcher

`argus/runtime/dispatcher.py`:

1. Resolves task category.
2. Checks required specialists.
3. Finds compatible tools.
4. Sorts candidates deterministically.
5. Selects a tool.
6. Validates safety.
7. Routes to the correct executor.

The original routing algorithm was category-based.

This caused a major recon issue.

---

# 21. Recon Routing Problem

A test produced:

```text
Technology Discovery           -> httpx
API Discovery                  -> httpx
GraphQL Analysis               -> graphql_specialist
JavaScript Analysis            -> javascript_specialist
Authentication Analysis        -> authentication_specialist
Authorization Analysis         -> authorization_specialist
Business Logic Analysis        -> business_logic_specialist
```

The specialist routes were correct.

But recon routing was not.

Reason:

Both `subfinder` and `httpx` supported Technology Discovery and had the same priority. Deterministic sorting therefore selected `httpx`.

Similarly, `httpx`, `katana_crawler`, and `api_specialist` competed for API Discovery.

This means the dispatcher did not understand execution sequence.

---

# 22. Explicit Tool Routing Fix

The project decision was to use the existing `ResearchTask.metadata` field.

Example:

```python
metadata={
    "tool_id": "subfinder"
}
```

The intended resolution order is:

```text
1. Explicit metadata.tool_id
2. required_specialists
3. category-compatible fallback
4. no tool
```

Proposed dispatcher logic:

```python
metadata = getattr(task, "metadata", {}) or {}
requested_tool_id = metadata.get("tool_id")

if requested_tool_id:
    tool = self.registry.get(requested_tool_id)

    if tool:
        logger.info(
            f"Dispatcher: Task explicitly requested "
            f"tool '{requested_tool_id}'"
        )
        return tool

    logger.warning(
        f"Dispatcher: Requested tool '{requested_tool_id}' "
        f"was not found in registry"
    )
```

This should be verified in the current repository before assuming it is already committed.

---

# 23. Desired Recon Pipeline

The intended chain is:

```text
TARGET
  |
  v
Subfinder
  |
  v
Subdomains
  |
  v
HTTPX
  |
  +----> Live Hosts
  |
  +----> Technologies
  |
  v
Katana
  |
  v
Endpoints
  |
  +-------------------------+
  |                         |
  v                         v
GraphQL                  JavaScript
Specialist               Specialist
  |
  +--> Authentication
  |
  +--> Authorization
  |
  +--> Business Logic
```

And:

```text
Live Hosts
    |
    v
Nuclei
    |
    v
Structured vulnerability evidence
```

Long term this must become an iterative loop:

```text
Mission State
     |
     v
Gap Analyzer
     |
     v
Next required task
     |
     v
Tool execution
     |
     v
Evidence
     |
     v
Mission State updated
     |
     v
Gap Analyzer again
```

---

# 24. ResearchTask Model

`argus/planning/models.py` defines:

```text
TECHNOLOGY_DISCOVERY
API_DISCOVERY
GRAPHQL_ANALYSIS
AUTHENTICATION_ANALYSIS
AUTHORIZATION_ANALYSIS
BUSINESS_LOGIC_ANALYSIS
JAVASCRIPT_ANALYSIS
WORKFLOW_ANALYSIS
EVIDENCE_CORRELATION
INVESTIGATION_REVIEW
COVERAGE_IMPROVEMENT
```

`ResearchTask` contains:

```text
id
title
description
goal
category
required_inputs
expected_outputs
priority
confidence
dependencies
required_specialists
estimated_duration_minutes
status
reason
supporting_evidence
metadata
created_at
```

This is already enough to model explicit tool IDs and task dependencies.

---

# 25. Task Scheduler

The existing `TaskScheduler` already preserves dependencies.

Do **not** create another scheduler.

The desired sequence can be represented as:

```text
Subfinder
    ↓
HTTPX
    ↓
Katana
    ↓
Specialist tasks
```

through task dependencies.

---

# 26. GapAnalyzer

`argus/planning/gap_analysis.py` currently checks:

- technologies
- APIs
- GraphQL
- authentication
- authorization
- business logic
- JavaScript
- evidence correlation

The current technology gap logic is too coarse:

```text
if no technologies:
    Technology Discovery gap
```

It does not distinguish:

```text
no subdomains
no live hosts
no technologies
no endpoints
no vulnerability evidence
```

Desired state-aware behavior:

```text
if no subdomains:
    Subfinder

elif subdomains and no live hosts:
    HTTPX

elif live hosts and no endpoints:
    Katana

elif live hosts and vulnerability scan not performed:
    Nuclei
```

The implementation must also avoid regenerating identical tasks indefinitely.

---

# 27. CoverageTracker

`argus/planning/coverage.py` tracks:

- endpoints
- business objects
- workflows
- authentication
- authorization
- technologies
- overall coverage
- gaps

The historical implementation used heuristics.

Technology coverage especially needs stronger execution/evidence semantics.

---

# 28. Nuclei Parser

`argus/runtime/parser.py` now includes `parse_nuclei()`.

It extracts:

```text
template_id
name
severity
host
matched_at
description
tags
extracted_results
```

It parses JSONL and skips malformed lines with warnings.

Example test data:

```json
{
  "template-id": "CVE-2023-XXXX",
  "info": {
    "name": "Example CVE",
    "severity": "high",
    "description": "A test CVE"
  },
  "host": "http://api.example.com"
}
```

---

# 29. Nuclei Collector vs Executor

The legacy collector:

```text
argus/collectors/nuclei.py
```

does:

```text
run nuclei
collect JSONL
append raw lines to mission.notes
```

The newer:

```text
argus/runtime/executor.py
```

contains Nuclei handling that calls:

```text
ReconParser.parse_nuclei()
```

and creates structured evidence.

The active autonomous runtime must be verified so Nuclei findings are not silently reduced to notes.

---

# 30. E2E Testing

An E2E test file exists/was being added:

```text
tests/runtime/test_e2e_mission.py
```

The desired test verifies:

```text
Mission
→ Runtime
→ Planner
→ Tool
→ Evidence
→ Knowledge
→ Hypothesis
→ Investigation
→ Correlation
→ Result
```

Historical test counts differed between repository states. One run reported 482 passing tests; another audit described 474 tests. Treat those as historical numbers and run the current suite.

The project specifically needs more true integration/E2E coverage, not only unit tests.

---

# 31. Sprint 0 — Runtime Plumbing

Sprint 0 was explicitly designed to connect existing components rather than restart the architecture.

## Entry point

Modify:

```text
argus/cli/mission_cli.py
```

to provide:

```text
argus mission run --target <target>
```

It should create/start a mission and report the final outcome while preserving scope controls.

## Runtime

Modify:

```text
argus/runtime/mission_runtime.py
```

to:

- inject the correct TaskScheduler.
- execute ready ResearchTasks through ToolOrchestrator.
- convert evidence into observations.
- advance mission phases correctly.
- add lifecycle logging.

## Controller

Modify:

```text
argus/runtime/controller.py
```

It already wires toward:

```text
MissionPlanner
ResearchPlanner
TaskScheduler
ToolOrchestrator
CorrelationEngine
EvidenceFusionEngine
InvestigationBuilder
PriorityEngine
HypothesisEngine
LearningEngine
```

KnowledgeManager still needs to be integrated where appropriate.

## Executor

Modify:

```text
argus/runtime/executor.py
```

to:

- execute external tools accurately.
- parse subfinder/httpx/katana/nuclei.
- normalize output.
- create/store Evidence.

## Registry

Nuclei was added to the registry.

## Parser

`argus/runtime/parser.py` contains parsers for:

- subfinder
- httpx
- katana
- nuclei

## Knowledge

ResearchPlanner should query KnowledgeManager based on current evidence.

## Observability

Use structured lifecycle logs such as:

```text
MISSION CREATED
PLAN CREATED
TOOL STARTED
TOOL COMPLETED
EVIDENCE CREATED
KNOWLEDGE RETRIEVED
INVESTIGATION STARTED
```

Never log credentials.

---

# 32. Sprint 0 Verification

Use a safe local lab target.

Example:

```bash
argus mission run --target http://localhost:8080
```

Expected sequence:

```text
Mission
→ planning
→ tool execution
→ evidence
→ knowledge
→ hypothesis
→ investigation
→ correlation
→ result
```

Automated:

```bash
pytest tests/runtime/test_e2e_mission.py
pytest
```

External targets should only be tested when explicitly authorized.

---

# 33. Current CLI Architecture

`argus/cli/app.py` registers many subcommands including:

```text
knowledge
queue
workflow
auth
agent
execution
plugin
provenance
mission
intelligence
playbooks
business
api
authn
upload
tools
graphql
javascript
observations
correlations
benchmark
workspace
evidence
investigations
explain
performance
plan
research
scheduler
learning
hypothesis
```

The goal is to make the autonomous mission runtime actually reachable via the CLI.

---

# 34. Specialist Routing

Dispatcher resolution was verified for:

```text
GraphQL Analysis        -> graphql_specialist
JavaScript Analysis     -> javascript_specialist
Authentication Analysis -> authentication_specialist
Authorization Analysis -> authorization_specialist
Business Logic Analysis -> business_logic_specialist
```

This proves tool resolution, not complete execution.

The next verification question is:

> Does the selected specialist actually execute, mutate mission state, create evidence/observations, and feed downstream reasoning?

---

# 35. GraphQL Plugin

Current structure:

```text
argus/plugins/graphql/
├── plugin.py
├── agent.py
├── schema.py
├── business.py
├── models.py
└── tests/
```

Models include:

- GraphQLEndpoint
- GraphQLArgument
- GraphQLField
- GraphQLType
- GraphQLOperation
- GraphQLEnum
- GraphQLUnion
- GraphQLInterface
- GraphQLRelationship
- GraphQLBusinessObject
- GraphQLCRUD
- GraphQLWorkflow
- GraphQLInvestigation

The plugin is substantially implemented.

The major historical problem was real schema acquisition.

---

# 36. JavaScript Plugin

JavaScript plugin was reported implemented/tested with AST parsing and endpoint capability extraction.

Future security intelligence should cover:

- client-side routes
- API endpoints
- source maps
- exposed configuration/secrets
- framework identification
- Next.js
- `/_next`
- middleware
- client-side sinks/sources
- prototype pollution
- framework-specific attack surface

---

# 37. Authentication and Authorization

Argus has modern authentication/authorization components.

Long-term authorization coverage should include:

- resource ownership
- horizontal access control
- vertical privilege boundaries
- object IDs
- API authorization
- workflow authorization
- multi-account comparison

Authentication should include:

- login
- registration
- password reset
- MFA
- OAuth
- JWT
- sessions
- session invalidation
- token handling

These must become evidence-backed active investigations rather than checklist text.

---

# 38. Evidence Architecture

Argus has:

```text
argus/evidence/
```

and an EvidenceManager.

The principle is:

> Important claims must be grounded in concrete evidence with provenance.

Evidence should capture as appropriate:

- source
- target
- request/response or tool output
- timestamp
- provenance
- hashes where appropriate
- structured metadata
- relation to observations/hypotheses

---

# 39. Correlation Architecture

Argus has:

```text
argus/correlation/
```

including:

- CorrelationEngine
- EvidenceFusionEngine
- correlation graph
- observations
- serialization

Goal:

```text
Technology evidence
+
Endpoint evidence
+
Response evidence
+
Authorization evidence
=
Correlated vulnerability hypothesis
```

Correlation should reduce duplicate findings.

---

# 40. Hypothesis Architecture

`argus/hypothesis/engine.py` generates vulnerability hypotheses from evidence.

A hypothesis should be:

- evidence-backed
- testable
- scoped
- prioritized

not merely a speculative statement.

---

# 41. Investigation Architecture

Argus has:

```text
argus/investigation/
```

The desired flow:

```text
Observation
    ↓
Hypothesis
    ↓
Investigation plan
    ↓
Controlled test
    ↓
New evidence
    ↓
Hypothesis update
    ↓
Finding or rejection
```

This is essential for reducing hallucinated vulnerabilities.

---

# 42. Scope / Safety

Argus has:

```text
argus/authorization/scope.py
argus/authorization/gate.py
```

ScopeResolver was reported implemented/tested.

External tools, Burp, and future direct HTTP capabilities must respect scope and authorization.

Do not weaken safety checks merely to make a test pass.

---

# 43. Mission Runtime

Important:

```text
argus/runtime/mission_runtime.py
```

contains `AutonomousMissionRuntime`.

It should coordinate:

- planning
- research tasks
- execution
- evidence
- observations
- investigations
- correlation
- state transitions
- checkpoint/recovery

The current development effort is making this genuinely reachable end-to-end.

---

# 44. Mission Controller

`argus/runtime/controller.py` currently constructs an `AutonomousMissionRuntime` with components including:

```text
MissionStateMachine
MissionCheckpointer
MissionPlanner
ResearchPlanner
TaskScheduler
ToolOrchestrator
CorrelationEngine
EvidenceFusionEngine
InvestigationBuilder
PriorityEngine
HypothesisEngine
LearningEngine
```

The desired strategy is to connect missing dependencies, not create replacements.

---

# 45. Knowledge Manager

Argus has security knowledge structures including:

- CWE
- OWASP
- CAPEC

Historical audit finding:

> KnowledgeManager existed but was insufficiently connected to mission planning/reasoning.

Desired flow:

```text
Evidence
   ↓
Technology/vulnerability concepts
   ↓
KnowledgeManager
   ↓
Relevant CWE/OWASP/CAPEC/security knowledge
   ↓
ResearchPlanner
   ↓
Next task
```

---

# 46. Learning

Argus has:

```text
argus/learning/
```

Long-term learning should use:

- previous missions
- validated findings
- false positives
- validated hypotheses
- security knowledge
- lab scenarios
- benchmarks

PortSwigger labs should teach concepts, not simply provide memorized solutions.

---

# 47. Benchmarking

Active benchmark area:

```text
argus/benchmark/runner/
```

The system should eventually measure:

```text
discovery accuracy
analysis accuracy
hypothesis accuracy
validation accuracy
finding quality
false-positive rate
evidence grounding
```

and compare models/providers.

---

# 48. Architectural Rules for Claude

## Rule 1 — Do not duplicate architecture

Before adding:

- scheduler
- runtime
- planner
- evidence manager
- provider system

inspect existing implementations and reuse them.

## Rule 2 — Prefer modern plugins

Old:

```text
argus/agents/specialists/*
```

Modern:

```text
argus/plugins/*
```

Do not revive legacy stubs without a specific migration reason.

## Rule 3 — Preserve scope

Never bypass:

```text
ScopeResolver
AuthorizationGate
SafetyValidator
```

## Rule 4 — Evidence first

Do not claim a vulnerability from model intuition alone.

## Rule 5 — Deterministic execution

LLMs recommend research. The execution system determines:

- registered tool
- allowed target
- inputs
- safety
- timeout
- result normalization

## Rule 6 — Test connections

Prefer tests that cross boundaries:

```text
Planner
→ Task
→ Dispatcher
→ Executor
→ Evidence
→ Mission state
```

---

# 49. Git Branch Context

A separate branch was created for runtime-plumbing work.

It is **not** a restart of Argus.

Its purpose is to safely connect the existing components without destabilizing `main`.

If commits are made while checked out on that branch, they go to that branch.

Recommended:

```bash
git status
git branch --show-current
git add ...
git commit -m "..."
git push origin <current-branch>
```

Merge to `main` only after verification.

---

# 50. What Has Been Done in Sprint 0

During the development conversation:

- Nuclei was registered in the runtime registry.
- Controller wiring was updated toward TaskScheduler + ToolOrchestrator.
- Parser support was added/expanded.
- Nuclei parser was added.
- ExternalToolExecutor parses Nuclei.
- Dispatcher and registry were inspected.
- GraphQL task resolution was verified.
- Specialist routing was verified.
- External security binaries were verified.
- Provider routing was verified.
- E2E test scaffolding exists.
- Runtime/planning architecture was inspected.

Exact current state must be confirmed with:

```bash
git status
git diff
git log --oneline -10
```

---

# 51. Current Recon Tool Model

Desired definitions:

```text
subfinder
    capability: subdomain_enumerator
    input: target
    output: subdomains

httpx
    capability: live_host_detector
    input: subdomains
    output: live_hosts + technologies

katana_crawler
    capability: crawler
    input: live_hosts
    output: endpoints

nuclei
    capability: vulnerability_scanner
    input: live_hosts
    output: vulnerabilities + observations
```

---

# 52. Current Task Generator Problem

The old task-generation pattern used a generic Technology Discovery task and historically referenced:

```text
required_specialists=["ReconAgent"]
```

This is inconsistent with the modern registry because there is no `ReconAgent` registry tool; there are actual tools such as:

```text
subfinder
httpx
katana_crawler
nuclei
```

The task generator should produce concrete executable tasks with:

```text
metadata.tool_id
required_inputs
expected_outputs
dependencies
```

---

# 53. Desired Concrete Recon Tasks

## A — Discover Subdomains

```text
title: Discover Subdomains
category: Technology Discovery
required_inputs: target
expected_outputs: subdomains
metadata.tool_id: subfinder
```

## B — Fingerprint Live Hosts

```text
title: Fingerprint Live Hosts
category: Technology Discovery
required_inputs: subdomains
expected_outputs: live_hosts, technologies
dependencies: Discover Subdomains
metadata.tool_id: httpx
```

## C — Discover API Endpoints

```text
title: Discover API Endpoints
category: API Discovery
required_inputs: live_hosts
expected_outputs: endpoints
dependencies: Fingerprint Live Hosts
metadata.tool_id: katana_crawler
```

## D — Scan Live Hosts

```text
title: Scan Live Hosts
required_inputs: live_hosts
expected_outputs: vulnerabilities, observations
dependencies: Fingerprint Live Hosts
metadata.tool_id: nuclei
```

The exact category for Nuclei may require checking whether `VULNERABILITY_SCANNING` exists. Do not invent a new category without tracing downstream consumers.

---

# 54. Immediate Next Development Step

First verify explicit tool routing:

```bash
cd ~/argus

python - <<'PY'
from argus.runtime.dispatcher import ToolDispatcher
from argus.runtime.registry import registry
from argus.planning.models import ResearchTask, TaskCategory

tests = [
    ("Subfinder", "subfinder", TaskCategory.TECHNOLOGY_DISCOVERY),
    ("HTTPX", "httpx", TaskCategory.TECHNOLOGY_DISCOVERY),
    ("Katana", "katana_crawler", TaskCategory.API_DISCOVERY),
    ("Nuclei", "nuclei", TaskCategory.EVIDENCE_CORRELATION),
    ("GraphQL", "graphql_specialist", TaskCategory.GRAPHQL_ANALYSIS),
]

dispatcher = ToolDispatcher(registry)

for title, expected, category in tests:
    task = ResearchTask(
        title=title,
        description="Explicit dispatcher routing test",
        goal="Verify tool selection",
        category=category,
        metadata={"tool_id": expected},
    )

    tool = dispatcher.resolve_tool(task)
    actual = tool.id if tool else None
    status = "PASS" if actual == expected else "FAIL"

    print(
        f"{status:4} | {category.value:30} | "
        f"expected={expected:22} | actual={actual}"
    )
PY
```

Expected all `PASS`.

Then inspect:

```bash
sed -n '1,240p' argus/planning/task_generator.py
```

and implement concrete recon task generation.

---

# 55. Development Roadmap

## Sprint 0 — Runtime Plumbing

1. Explicit tool routing.
2. Concrete recon task generation.
3. Dependency-aware scheduling.
4. Evidence normalization.
5. Nuclei evidence integration.
6. Knowledge retrieval.
7. Lifecycle logging.
8. Local E2E mission.
9. CLI mission execution.
10. Full regression suite.

## Sprint 1 — Recon Intelligence

- Subdomain discovery.
- Live-host/technology intelligence.
- Endpoint normalization.
- JS discovery.
- API inventory.
- framework detection.
- attack-surface graph.

## Sprint 2 — Active Web Security Engine

- Controlled HTTP layer.
- Request/response evidence.
- Authentication workflows.
- Authorization testing.
- Business-logic testing.
- Stateful workflow testing.

## Sprint 3 — GraphQL/API/JS Depth

- Real GraphQL introspection.
- GraphQL authorization.
- GraphQL business logic.
- API schema inference.
- JS AST security intelligence.
- Source maps.
- framework-specific analysis.

## Sprint 4 — Burp Suite Professional

- Burp adapter.
- HTTP history.
- Site map.
- Request/response ingestion.
- Scanner evidence.
- Controlled Repeater workflows.
- Burp evidence correlation.

## Sprint 5 — Security Intelligence

- OWASP mapping.
- CWE/CAPEC knowledge.
- PortSwigger topic coverage.
- Lab-inspired benchmarks.
- Independent vulnerability reasoning.

## Sprint 6 — Benchmarking / Learning

- Regression suite.
- False-positive tracking.
- Finding-quality metrics.
- Provider/model comparisons.
- Learning from validated findings.

---

# 56. Final Mental Model

If Claude remembers only one thing:

> **Argus is an evidence-grounded autonomous security research orchestrator, not a wrapper around Nuclei/subfinder and not an LLM that randomly executes shell commands.**

The target system is:

```text
                ARGUS
                  |
       +----------+----------+
       |                     |
   Security Tools         Burp Suite
       |                     |
       +----------+----------+
                  |
              Evidence
                  |
          Knowledge Graph
                  |
             Reasoning
                  |
          Hypothesis Engine
                  |
           Investigation
                  |
             Correlation
                  |
             Findings
                  |
             Learning
```

The most important immediate goal is to make the existing pieces actually execute together:

```text
Planner
  ↓
Task
  ↓
Dependency graph
  ↓
Dispatcher
  ↓
Registered security tool
  ↓
Structured evidence
  ↓
Observation
  ↓
Knowledge
  ↓
Hypothesis
  ↓
Investigation
  ↓
Correlation
  ↓
Finding
  ↓
Next task
```

Only after that loop is genuinely end-to-end should major Burp integration work begin.


---

# 57. COMPLETE ARGUS FUTURE ROADMAP — RED TEAM BUG HUNTER EDITION

This section is the **authoritative forward-looking roadmap** for ARGUS. It supersedes previous phase descriptions and is directly aligned with the full coverage of all 30 vulnerability categories in the PortSwigger Web Security Academy, modern bug bounty workflows, and real-world red team techniques.

---

# 58. Roadmap Philosophy

ARGUS evolves through these layers:

```
FOUNDATION (Done) → RECON INTELLIGENCE (Done) → ATTACK-SURFACE GRAPH & DIFF (Done)
→ GRAPH-AWARE REASONING (Done) → ACTIVE AUTHENTICATED PROBING
→ INJECTION & VULNERABILITY ENGINES → AUTH, ACCESS CONTROL & IDENTITY
→ ADVANCED PROTOCOL ATTACKS → API, AI & MODERN ATTACK SURFACE
→ BURP SUITE INTEGRATION & OAST → AUTONOMOUS REPORTING & LEARNING
```

---

# 59. Current Sprint Status

| Sprint | Phase | Status | Tests | Key Capabilities Delivered |
|--------|-------|:------:|:-----:|---------------------------|
| Sprint 0 | Runtime Plumbing | ✅ Complete | 427 | Mission loop, tool routing DAG, registry, dispatcher |
| Sprint 1 | Recon Intelligence | ✅ Complete | 493 | Subfinder/HTTPX/Katana/Nuclei structured evidence |
| Sprint 2 | Attack-Surface Graph + Diff | ✅ Complete | 543 | KnowledgeGraph, AttackSurfaceGraphBuilder, diff engine |
| Sprint 3 | Graph-Aware Reasoning | ✅ Complete | 578 | Correlation/Investigation/Hypothesis graph-wired; mission loop bug fixed |
| Sprint 4 | CNAME Takeover + Auth Foundation | ✅ Complete | 646 | dnsx CNAME takeover (26 fingerprints), TestIdentity, AuthenticatedHttpClient |
| Sprint 5 | Information Disclosure | 📋 Planned | — | .git, .env, Spring Actuators, source maps, secret extraction |

---

# 60. PHASE 4 — CNAME / SUBDOMAIN TAKEOVER (COMPLETE)

- dnsx registered as external tool, runs CNAME resolution after subfinder
- Fingerprint database of 26 known vulnerable services (AWS S3, GitHub Pages, Heroku, Fastly, Azure, Netlify, Shopify, Zendesk, etc.)
- Dangling CNAME → Evidence(category="subdomain_takeover", severity="critical")
- POINTS_TO_CNAME and HAS_VULNERABILITY edges added to attack surface graph

---

# 61. PHASE 4.5 — AUTHENTICATED TESTING FOUNDATION (COMPLETE)

- TestIdentity dataclass: email, password, cookies, auth_tokens, role, session_valid
- Mission.test_identities — load HackerOne/Bugcrowd test account credentials
- AuthenticatedHttpClient: persistent httpx.Client with cookie jar, scope gating, single-step login
- Supports Bearer token and session cookie authentication patterns

---

# 62. PHASE 5 — ACTIVE PROBING INFRASTRUCTURE

Request replay engine, response diffing, scope-aware rate limiting, per-domain throttling, User-Agent rotation.

---

# 63. PHASE 6 — INFORMATION DISCLOSURE ENGINE (Sprint 5 Target)

PortSwigger: Lab #18 (5 labs) | OWASP: A05

- High-value wordlist: .git/config, .env, phpinfo.php, Dockerfile, source maps (.js.map), Spring Boot Actuators (/actuator/env, /actuator/heapdump)
- Secret extraction from found files: API keys, passwords, internal hostnames
- Graph loop: discovered internal domains expand mission attack surface dynamically
- Evidence(category="information_disclosure", severity="high/medium")

---

# 64. PHASE 7 — ACCESS CONTROL / IDOR ENGINE

PortSwigger: Lab #13 Popular (13 labs) | OWASP: A01

- Horizontal priv-esc: mutate user ID parameters (?id=1 → ?id=2)
- Vertical priv-esc: access admin endpoints as regular user
- X-Original-URL, X-Rewrite-URL bypass
- IDOR via UUID, integer, hash-based identifiers
- Requires: TestIdentity + AuthenticatedHttpClient

---

# 65. PHASE 8 — PATH / DIRECTORY TRAVERSAL ENGINE

PortSwigger: Lab #12 (6 labs) | OWASP: A01

- ../, ....// sequences, URL-encoded (%2e%2e%2f), double-encoded
- Null byte termination (%00), absolute path injection (/etc/passwd)

---

# 66. PHASE 9 — SQL INJECTION ENGINE

PortSwigger: Lab #1 Popular (18 labs) | OWASP: A03

- Union-based, blind conditional error, blind time-delay
- Out-of-band (OAST) via Burp Collaborator / interactsh
- XML/WAF filter bypass
- MySQL, PostgreSQL, MSSQL, Oracle, SQLite fingerprinting

---

# 67. PHASE 10 — CROSS-SITE SCRIPTING (XSS) ENGINE

PortSwigger: Lab #2 Popular (30 labs) | OWASP: A03

- Reflected, Stored, DOM-based XSS
- Source→sink tracing: location.search → eval, innerHTML, document.write
- Filter/WAF bypass, CSP bypass via JSONP/open-redirect in allowlisted domains

---

# 68. PHASE 11 — OS COMMAND INJECTION ENGINE

PortSwigger: Lab #10 (5 labs) | OWASP: A03

- Metacharacter injection: ;, |, &&, backticks
- Blind: time-delay, out-of-band DNS callback

---

# 69. PHASE 12 — SERVER-SIDE TEMPLATE INJECTION (SSTI) ENGINE

PortSwigger: Lab #11 (7 labs) | OWASP: A03

- Jinja2 (Python) → RCE via __class__.__mro__.__subclasses__() chain
- Twig (PHP) → _self.env.getFilter()
- FreeMarker (Java) → Execute class, Smarty, Pebble

---

# 70. PHASE 13 — NoSQL INJECTION ENGINE

PortSwigger: Lab #27 (4 labs) | OWASP: A03

- MongoDB: $ne, $regex, $where, $exists operators
- Auth bypass, data extraction via $regex enumeration

---

# 71. PHASE 14 — XML EXTERNAL ENTITY (XXE) INJECTION ENGINE

PortSwigger: Lab #7 (9 labs) | OWASP: A05

- Classic file retrieval, blind XXE via OAST, XXE→SSRF pivot
- Parameter entity injection via external DTD, XInclude attacks

---

# 72. PHASE 15 — AUTHENTICATION VULNERABILITY ENGINE

PortSwigger: Lab #14 Popular (14 labs) | OWASP: A07

- Username enumeration (timing, error messages)
- Brute-force: rate-limit bypass via X-Forwarded-For, IP rotation
- Password reset poisoning, 2FA/MFA bypass, session fixation

---

# 73. PHASE 16 — OAUTH 2.0 ATTACK ENGINE

PortSwigger: Lab #21 (6 labs) | OWASP: A07

- Missing state parameter (CSRF), lax redirect_uri → code theft
- Implicit flow token leakage, account linking hijacking

---

# 74. PHASE 17 — JWT ATTACK ENGINE

PortSwigger: Lab #23 Trending (8 labs) | OWASP: A02

- alg:none bypass, HMAC vs RSA confusion, weak secret brute-force
- jwk/jku/kid header injection to attacker-controlled JWKS

---

# 75. PHASE 18 — CSRF ENGINE

PortSwigger: Lab #3 (12 labs) | OWASP: A01

- Missing token, SameSite bypass, token-cookie decoupling, Referer bypass

---

# 76. PHASE 19 — BUSINESS LOGIC ENGINE

PortSwigger: Lab #19 Popular (11 labs) | OWASP: A04

- Integer overflow in pricing, negative quantity, multi-step state skipping

---

# 77. PHASE 20 — FILE UPLOAD VULNERABILITY ENGINE

PortSwigger: Lab #22 Popular (7 labs) | OWASP: A03/A01

- Extension bypass (.php5, .phar), MIME spoofing, path traversal via filename
- .htaccess / web.config upload, polyglot files

---

# 78. PHASE 21 — MULTI-IDENTITY / INSIDER TESTING ENGINE

Target: HackerOne, Bugcrowd programs with test account provisioning

- Automated registration using program-provided emails (e.g. varunkumaragrahari@wearehackerone.com)
- Dual-session IDOR: Account A reads Account B resources
- Role escalation verification across user/admin boundaries

---

# 79. PHASE 22 — SSRF ENGINE

PortSwigger: Lab #8 Popular (7 labs) | OWASP: A10

- Internal discovery (localhost, 127.0.0.1), cloud metadata (169.254.169.254)
- Blacklist bypass: IP encoding (127.1, 0x7f000001), DNS rebinding
- Open-redirect SSRF chain, blind SSRF via OAST

---

# 80. PHASE 23 — DOM-BASED VULNERABILITY ENGINE

PortSwigger: Lab #6 (7 labs) | OWASP: A03/A04

- Sources: location.search, document.referrer, postMessage, localStorage
- Sinks: eval, innerHTML, document.write, location.href, jQuery.html()

---

# 81. PHASE 24 — INSECURE DESERIALIZATION ENGINE

PortSwigger: Lab #17 (10 labs) | OWASP: A08

- Java: ysoserial gadget chains
- PHP: __wakeup(), __destruct() magic method injection
- Python: pickle.loads() RCE payload generation

---

# 82. PHASE 25 — HTTP REQUEST SMUGGLING ENGINE

PortSwigger: Lab #9 Trending (22 labs) | OWASP: A05

- CL.TE, TE.CL, TE.TE desync attacks
- HTTP/2 downgrade (H2.CL, H2.TE), request tunneling
- Cache poisoning via smuggling
- Requires: Burp Suite Pro (Phase 36)

---

# 83. PHASE 26 — WEB CACHE POISONING & DECEPTION ENGINE

PortSwigger: Lab #16 + #30 (18 labs) | OWASP: A05

- Unkeyed header injection (X-Forwarded-Host), cache response poisoning
- Cache deception via path normalization discrepancies

---

# 84. PHASE 27 — RACE CONDITION ENGINE

PortSwigger: Lab #26 Trending (6 labs) | OWASP: A04

- Single-packet HTTP/2 synchronization (Turbo Intruder)
- TOCTOU exploitation, rate limit and coupon bypass via racing
- Requires: Burp Suite Pro Turbo Intruder

---

# 85. PHASE 28 — HOST HEADER ATTACK ENGINE

PortSwigger: Lab #20 (7 labs) | OWASP: A05

- Password reset poisoning via X-Forwarded-Host
- Internal routing SSRF, web cache poisoning via Host

---

# 86. PHASE 29 — CORS MISCONFIGURATION ENGINE

PortSwigger: Lab #4 (4 labs) | OWASP: A05

- Arbitrary origin reflection, null origin trust, subdomain trust, weak regex bypass

---

# 87. PHASE 30 — CLICKJACKING ENGINE

PortSwigger: Lab #5 (5 labs) | OWASP: A05

- Transparent iframe overlay, X-Frame-Options bypass, multi-step clickjacking

---

# 88. PHASE 31 — GRAPHQL ATTACK ENGINE

PortSwigger: Lab #25 Trending (5 labs) | OWASP: A01/A05

- Introspection bypass, schema extraction, IDOR via nested queries, batching DoS

---

# 89. PHASE 32 — API SECURITY TESTING ENGINE

PortSwigger: Lab #28 Trending (5 labs) | OWASP: A01/A05

- Hidden endpoint discovery (OpenAPI/Swagger), HTTP method tampering
- Mass assignment, API versioning abuse

---

# 90. PHASE 33 — WEBSOCKET VULNERABILITY ENGINE

PortSwigger: Lab #15 (3 labs) | OWASP: A03/A01

- Frame manipulation/injection, Cross-Site WebSocket Hijacking (CSWSH)

---

# 91. PHASE 34 — PROTOTYPE POLLUTION ENGINE

PortSwigger: Lab #24 Trending (10 labs) | OWASP: A03/A08

- Client-side: __proto__ injection → DOM XSS via prototype gadgets
- Server-side Node.js: lodash.merge / qs pollution → RCE via child_process

---

# 92. PHASE 35 — WEB LLM / AI ATTACK ENGINE

PortSwigger: Lab #29 New (4 labs) | OWASP: LLM Top 10

- Direct/indirect prompt injection, tool-calling manipulation → SSRF/XSS

---

# 93. PHASE 36 — BURP SUITE PROFESSIONAL INTEGRATION

- Proxy routing, active scanner API, Burp Collaborator (blind OAST)
- Turbo Intruder for single-packet race conditions
- Bambda filters synchronized with ARGUS payload templates

---

# 94. PHASE 37 — OAST (Out-of-Band Application Security Testing)

- Self-hosted interactsh or canarytokens listener
- DNS/HTTP callbacks for all blind vulnerability classes
- Auto-correlate callbacks to originating ARGUS test case

---

# 95. PHASE 38 — JAVASCRIPT INTELLIGENCE ENGINE

- Source map decompilation, client-side secret mining
- Endpoint route extraction from React/Angular/Vue bundles
- DOM sink mapping, postMessage handler enumeration

---

# 96. PHASE 39 — AUTOMATED REPORTING ENGINE

- CVSS v3.1 scoring from evidence metadata
- HackerOne and Bugcrowd ready submission format
- Evidence chain: raw request/response per finding
- Deduplication across test runs

---

# 97. PHASE 40 — CONTINUOUS ATTACK SURFACE MONITORING

- Scheduled missions, attack surface diff vs baseline
- New subdomain/endpoint/tech alerts
- Regression detection (verify patches), Slack/Discord integration

---

# 98. What We Should NOT Do

- Jump to exploitation without Phase 5 HTTP engine
- Implement all injection engines without OAST capability
- Run active engines outside declared mission scope
- Skip authenticated testing before IDOR / auth vulnerability engines

---

# 99. Definition of Done for the Full ARGUS Red Team Vision

ARGUS is complete when it can:
- [ ] Autonomously discover full attack surface: subdomains, hosts, endpoints, technologies
- [ ] Detect subdomain takeover via CNAME analysis
- [ ] Log in using program-provided test identity and maintain session
- [ ] Systematically test all 30 PortSwigger Web Security Academy vulnerability categories
- [ ] Use out-of-band callbacks to verify blind vulnerabilities
- [ ] Generate complete, ready-to-submit HackerOne/Bugcrowd reports per finding
- [ ] Monitor attack surface continuously and alert on changes

---

# 100. Ultimate Product Goal

ARGUS is a **fully autonomous red team agent** — the digital equivalent of an elite bug bounty hunter who never sleeps, never misses a parameter, and files clear, evidence-backed reports. It covers in hours what a human covers in days, within scope, without unintended harm, with complete auditability of every action.
