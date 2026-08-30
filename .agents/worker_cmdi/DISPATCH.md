## 2026-08-30T11:13:46Z
You are the Implementation Worker subagent for ARGUS Sprint 11: Command Injection (CMDi) Engine.
Your working directory is /home/varun/argus/.agents/worker_cmdi/

MANDATORY FIRST STEP: Read the following specification and survey files:
- /home/varun/argus/.agents/ORIGINAL_REQUEST.md (specifically section ## 2026-08-30T11:08:07Z)
- /home/varun/argus/PROJECT.md
- /home/varun/argus/TEST_INFRA.md
- /home/varun/argus/.agents/explorer_survey_collectors/handoff.md
- /home/varun/argus/.agents/explorer_survey_pipeline/handoff.md
- /home/varun/argus/.agents/spec_miner_cmdi/handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your implementation scope:
1. Implement `argus/collectors/command_injection.py`:
   - `CommandInjectionResult` dataclass.
   - `CommandInjectionPayloadGenerator`:
     - Result-based payloads (POSIX: id, whoami, uname -a, cat /etc/passwd, expr 28412 + 19283; Windows: whoami, ver, dir, set, ipconfig).
     - Time-based blind delay payloads (sleep {delay}, ping -c {delay} 127.0.0.1, timeout /t {delay}).
     - Error-based payloads triggering OS shell error messages.
     - Separator & Bypass Mutation engine (implement at least 5 distinct strategies, including semicolons, pipes, ampersands, backticks/dollar-parens, newlines %0a, URL/double-URL encoding, $IFS whitespace substitutions, quote obfuscations).
   - `CommandInjectionAnalyzer`:
     - Result-based analysis with OS signatures (unix_id, unix_passwd, unix_uname, windows_whoami, windows_ver, etc.) and arithmetic canary exact matches (47695).
     - Time-based differential analysis (delay differential >= 4.0 seconds above baseline and total elapsed >= 4.0 seconds).
     - Error-based analysis with multi-shell error signatures (Bash/Dash/Zsh, Windows CMD, PowerShell).
     - False positive rejection: baseline subtraction and reflection guards (suppress verbatim reflection of payload in normal text without command output).
   - `CommandInjectionCollector(BaseCollector)`:
     - Implements `collect(self, mission: Any) -> List[Evidence]` and `execute(self, mission: Any) -> List[Evidence]`.
     - Handles `ControlledMission` unpacking via `raw_mission = getattr(mission, "_mission", mission)`.
     - Parameter testing across GET query parameters, POST body fields (form-urlencoded & JSON), path segments, and HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`).
     - Emits `Evidence` with `category="command_injection"`, `severity=Severity.CRITICAL` (for result-based & time-based findings) or `Severity.HIGH` (for error-based findings), `confidence >= 0.90`.
2. Update `argus/collectors/__init__.py` to export `CommandInjectionCollector`, `CommandInjectionPayloadGenerator`, `CommandInjectionAnalyzer`, `CommandInjectionResult`.
3. Update `argus/runtime/registry.py`:
   - Register `command_injection` tool with alias mapping (`cmdi`, `cmd_injection`, `command_injection_collector`), capabilities, safety requirements, priority.
4. Update `argus/runtime/plugins.py`:
   - In `_instantiate_specialist_fallback`, add routing for `command_injection` and `cmdi`.
5. Update `argus/planning/task_generator.py`:
   - Add `"command_injection"` template in `_RECON_TEMPLATES`.
   - Update `_resolve_template_for_gap` to map command injection gaps to `"command_injection"`.
   - In `from_gaps`, populate endpoint inputs for `tool_id == "command_injection"`.
6. Update `argus/graph/attack_surface.py`:
   - In `AttackSurfaceGraphBuilder.build_from_evidence`, handle `category == "command_injection"`, create `vulnerability:cmdi:...` node, connect `live_host -> HAS_ENDPOINT -> endpoint`, `live_host -> HAS_VULNERABILITY -> vuln`, and `endpoint -> HAS_VULNERABILITY -> vuln`.
7. Tests:
   - Create `tests/collectors/test_command_injection.py` with comprehensive unit and component test cases (at least 15 tests covering result-based, time-based, error-based, mutations, parameter points, false positive rejection).
   - Create `tests/pipeline/test_cmdi_pipeline.py` with pipeline integration test cases (at least 7 tests covering DAG generation, registry lookup, graph builder edge creation, and mission loop execution).
   - Total new tests must be >= 20.
8. Victory Audit & Verification:
   - Run `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
   - Verify that all 996+ existing tests pass, and all new tests pass with 0 failures, 0 errors, 0 regressions.
9. Documentation & Handoff:
   - Write full, detailed handoff report to BOTH:
     - `/home/varun/argus/.agents/sprint11_cmdi/handoff.md`
     - `/home/varun/argus/.agents/worker_cmdi/handoff.md`
   - Write progress.md in your working directory.
   - Send completion message to orchestrator with test results.
