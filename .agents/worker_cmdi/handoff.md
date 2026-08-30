# Sprint 11 Handoff Report: OS Command Injection (CMDi) Detection Engine

**Agent**: Implementation Worker (`worker_cmdi`)  
**Target Repository**: `/home/varun/argus`  
**Milestone**: Sprint 11 — OS Command Injection Detection Engine  
**Timestamp**: 2026-08-30T11:20:00Z  

---

## 1. Observation

### 1.1 Requirements & Specifications
As specified in `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (Sprint 11, lines 135–178), `PROJECT.md`, and `/home/varun/argus/.agents/spec_miner_cmdi/handoff.md`:
- **R1 (Command Injection Collector)**: Implement `CommandInjectionCollector` to test GET query parameters, POST body fields (form-urlencoded and JSON), RESTful path segments, and HTTP request headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`) using `AuthenticatedHttpClient`.
- **R2 (Multi-Technique Detection)**:
  1. *Result-Based Detection*: Injects OS commands (`id`, `whoami`, `uname -a`, `cat /etc/passwd`, `expr 28412 + 19283`, `ver`, `dir`, `set`, `ipconfig`); matches output against regex signatures and exact arithmetic canary match (`47695`) with baseline subtraction.
  2. *Time-Based Blind Differential Detection*: Injects shell delay commands (`sleep`, `ping -c`, `timeout /t`); measures latency delta $\ge 4.0\text{s}$ above baseline.
  3. *Error-Based Detection*: Injects malformed shell syntax to trigger OS shell error messages across Bash, Dash, Zsh, CMD, and PowerShell.
- **R3 (Separator & Bypass Mutations)**: Implement at least 5 distinct mutation strategies (semicolons, pipes, ampersands, command substitutions, newlines `%0a`, URL/double encoding, `$IFS` whitespace substitution, quote obfuscations).
- **R4 (Pipeline Connectivity)**: Wire into `ToolRegistry`, `PluginExecutorAdapter`, `TaskGenerator` DAG, and `AttackSurfaceGraphBuilder` generating `vulnerability:cmdi:...` nodes and `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges.
- **R5 (Zero Regression & E2E Validation)**: All 996+ existing tests must pass, plus $\ge 20$ new unit/pipeline tests.

### 1.2 Files Created & Modified
1. `argus/collectors/command_injection.py` *(Created)*:
   - `Severity` (Enum): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
   - `CommandInjectionResult` (Dataclass): Structured analysis container.
   - `CommandInjectionPayloadGenerator`: Implements base result payloads (POSIX/Windows/Canary), time payloads, error payloads, and 8 distinct mutation strategies:
     1. Semicolons (`mutate_semicolons`: `; cmd`, `;; cmd`, `; cmd ;`, `1; cmd`)
     2. Pipes (`mutate_pipes`: `| cmd`, `|| cmd`, `1 | cmd`)
     3. Ampersands (`mutate_ampersands`: `& cmd`, `&& cmd`, `1 && cmd`)
     4. Command Substitution (`mutate_substitution`: `` `cmd` ``, `$(cmd)`, `` `echo cmd | sh` ``)
     5. Newlines (`mutate_newlines`: `\ncmd`, `\r\ncmd`, `%0acmd`, `%0d%0acmd`)
     6. URL & Double URL Encoding (`mutate_url_encoding`: `%3B`, `%253B`)
     7. Whitespace Substitution (`mutate_whitespace`: `${IFS}`, `$IFS$9`, `%09`, `+`)
     8. Inline Quote Obfuscation (`mutate_inline_quotes`: `w'h'o'a'm'i`, `w"h"o"a"m"i`, `w\hoami`)
   - `CommandInjectionAnalyzer`: Result-based matching (`unix_id`, `unix_passwd`, `unix_uname`, `unix_whoami`, `windows_whoami`, `windows_ver`, `windows_set`, `windows_dir`, `windows_ipconfig`, exact canary `47695`), Time-based differential ($\Delta t \ge 4.0\text{s}$), Error-based shell signatures (Bash/Dash/Zsh, Windows CMD, PowerShell), and False Positive / Reflection guards.
   - `CommandInjectionCollector(BaseCollector)`: Orchestrates parameter injection across GET query params, POST body fields (JSON & form-urlencoded), path segments, and HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`). Emits `Evidence(category="command_injection")`, updates `mission.vulnerabilities`, and expands `mission.attack_surface_graph`.
2. `argus/collectors/__init__.py` *(Modified)*:
   - Exported `CommandInjectionCollector`, `CommandInjectionPayloadGenerator`, `CommandInjectionAnalyzer`, `CommandInjectionResult`.
3. `argus/runtime/registry.py` *(Modified)*:
   - Registered `command_injection` tool with capability `command_injection_detector`, safety requirements, and alias lookups for `cmdi`, `cmd_injection`, `command_injection_collector`, `os_command_injection`, `rce`.
4. `argus/runtime/plugins.py` *(Modified)*:
   - Added fallback instantiation in `PluginExecutorAdapter._instantiate_specialist_fallback` routing `command_injection`, `cmdi`, `cmd_injection`, `command`.
5. `argus/planning/task_generator.py` *(Modified)*:
   - Added `command_injection` task template in `_RECON_TEMPLATES`.
   - Updated `_resolve_template_for_gap` to map focus areas (`command injection`, `cmdi`, `rce`, `shell injection`) and `TaskCategory.EVIDENCE_CORRELATION` gaps to `command_injection`.
   - Populated endpoint inputs for `tool_id == "command_injection"` in `from_gaps`.
6. `argus/graph/attack_surface.py` *(Modified)*:
   - Added Section 13 handling `category in ("command_injection", "cmdi", "os_command_injection", "cmd_injection")` in `AttackSurfaceGraphBuilder.build_from_evidence`, creating `vulnerability:cmdi:...` nodes and connecting `live_host -> HAS_ENDPOINT -> endpoint`, `live_host -> HAS_VULNERABILITY -> vuln`, and `endpoint -> HAS_VULNERABILITY -> vuln`.
7. `tests/collectors/test_command_injection.py` *(Created)*:
   - 26 unit and component test cases covering payload generation, all 8 mutation strategies, result-based/time-based/error-based analyzers, arithmetic canaries, false positive suppression, and parameter injection across query, body, path, headers, and WAF bypass.
8. `tests/pipeline/test_cmdi_pipeline.py` *(Created)*:
   - 8 pipeline integration test cases covering registry lookup, alias resolution, adapter fallback instantiation, DAG template definition, gap resolution, graph node and edge creation, and mission loop execution.

---

## 2. Logic Chain

1. *Architectural Alignment*: By following the proven patterns established in `SQLInjectionCollector` and `XSSCollector`, `CommandInjectionCollector` cleanly separates payload generation, response analysis, and active transport fuzzing.
2. *Multi-Technique Rigor*:
   - Result-based detection verifies direct shell execution by matching deterministic OS command output signatures (`uid=0(root)`, `Linux ...`, `root:x:0:0:`) and computed arithmetic canaries (`47695` from `expr 28412 + 19283`), emitting Critical severity findings (confidence 0.95).
   - Time-based blind differential analysis evaluates latency increases against measured baselines ($\Delta t \ge 4.0\text{s}$), reliably detecting non-reflecting execution sinks.
   - Error-based analysis detects syntax errors and command-not-found patterns from Bash, Dash, Zsh, CMD, and PowerShell, emitting High severity findings (confidence 0.90).
3. *False Positive Suppression*:
   - Baseline subtraction ensures that pre-existing server banners, static documentation, or existing error pages are not falsely flagged.
   - Reflection guards ensure that verbatim echoing of search queries in HTML titles or input fields is rejected unless accompanied by genuine OS execution tokens.
4. *Comprehensive Parameter Coverage*:
   - Fuzzes query parameters, form bodies, JSON payload fields (preserving JSON syntax), numeric/resource path segments, and HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`).
5. *Pipeline & Graph Integrity*:
   - Registering aliases and tools allows the orchestrator, DAG planner, and plugin runner to invoke the collector interchangeably.
   - Graph builder Section 13 ensures all CMDi findings produce fully connected nodes (`live_host`, `endpoint`, `vulnerability`) and bidirectional edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`).

---

## 3. Caveats

- **No Caveats**: Out-of-band (DNS/OAST) interaction is omitted as planned; result-based, time-based blind, and error-based techniques provide comprehensive coverage within the test harness. Mock HTTP client simulations allow deterministic sub-second test execution without relying on live network sleeps.

---

## 4. Conclusion

Sprint 11 (Command Injection Engine) has been fully implemented, integrated, and verified:
- `CommandInjectionCollector`, `CommandInjectionPayloadGenerator`, `CommandInjectionAnalyzer`, and `CommandInjectionResult` are active and exported.
- Registry, Plugins, TaskGenerator DAG, and AttackSurfaceGraphBuilder integrations are operational.
- 34 new tests added (26 unit/component + 8 pipeline integration), achieving 100% pass rate.
- Zero regressions across the entire test suite.

---

## 5. Verification Method

To verify the implementation independently:

```bash
# 1. Run new CMDi collector and pipeline tests (34 tests):
python3 -m pytest tests/collectors/test_command_injection.py tests/pipeline/test_cmdi_pipeline.py -v

# 2. Run full repository test suite (1030 tests, 0 failures):
python3 -m pytest tests/ --ignore=tests/workspace -x -q
```
