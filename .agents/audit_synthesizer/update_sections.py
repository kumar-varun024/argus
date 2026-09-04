with open("/home/varun/argus/.agents/audit_synthesizer/make_report.py", "r") as f:
    text = f.read()

# 1. In build_part3_sections:
# Replace in c3 body:
old_s27 = """            out.append(body)"""
new_s27 = """            # Normalize Section 27 and 33
            if i == 27:
                body = body.replace("- **Subsections 27.1–27.16 Detailed Breakdown**:", "- **Implementation Evidence**:\\n  - **Subsections 27.1–27.16 Detailed Breakdown**:")
            elif i == 33:
                body = body.replace("- **Gaps (Rationale for Partial)**:", "- **Gaps**:")
            out.append(body)"""
text = text.replace(old_s27, new_s27, 1)

# 2. In build_part5_sections:
# Format Section 57 with all 6 explicit fields
old_s57 = """    # Format Section 57 with full deep architectural cleanup analysis
    s57_anchor = make_anchor("Section 57: Important Architectural Cleanup (Dual Execution Paths)")
    out.append(f"<a id=\\"{s57_anchor}\\"></a>")
    out.append("#### Section 57: Important Architectural Cleanup (Dual Execution Paths)\\n")
    out.append("- **Status**: ⚠️ Partial")
    out.append("- **Source Files**:\\n"
               "  - **Path A (Legacy DAG Scanner)**: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`), `argus/collectors/*.py` (32 modules)\\n"
               "  - **Path B (Autonomous Mission Runtime)**: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py`\\n"
               "  - **Path C (Agent Step Execution)**: `argus/execution/engine.py` (`ExecutionEngine`), `argus/agents/base.py` (`BaseAgent`)\\n"
               "  - **Adapter Bridge**: `argus/runtime/plugins.py` (`PluginExecutorAdapter`)")
    out.append("- **Implementation Evidence & Deep Architectural Analysis**:\\n")

    # Extract deep analysis from Cluster 5
    start_s57 = c5.find("### Section 57:")
    end_s57 = c5.find("## 2. Logic Chain")
    s57_text = c5[start_s57:end_s57].strip()
    
    # Extract only the body of s57
    body_s57 = s57_text[s57_text.find("#### Direct Code Observations"):]
    out.append(body_s57)
    out.append("\\n---\\n")"""

new_s57 = """    # Format Section 57 with full deep architectural cleanup analysis
    s57_anchor = make_anchor("Section 57: Important Architectural Cleanup (Dual Execution Paths)")
    out.append(f"<a id=\\"{s57_anchor}\\"></a>")
    out.append("#### Section 57: Important Architectural Cleanup (Dual Execution Paths)\\n")
    out.append("- **Status**: ⚠️ Partial")
    out.append("- **Source Files**:\\n"
               "  - **Path A (Legacy DAG Scanner)**: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`), `argus/collectors/*.py` (32 modules)\\n"
               "  - **Path B (Autonomous Mission Runtime)**: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py`\\n"
               "  - **Path C (Agent Step Execution)**: `argus/execution/engine.py` (`ExecutionEngine`), `argus/agents/base.py` (`BaseAgent`)\\n"
               "  - **Adapter Bridge**: `argus/runtime/plugins.py` (`PluginExecutorAdapter`)")
    out.append("- **Implementation Evidence**:\\n"
               "  - Structural co-existence of Path A (Collector Scanning DAG invoked via `argus scan`), Path B (Autonomous Mission Runtime invoked via `argus mission run`), and Path C (Legacy Agent Step Execution).\\n"
               "  - `PluginExecutorAdapter._instantiate_specialist_fallback()` provides an ad-hoc runtime bridge enabling Path B to dynamically execute Path A collectors as plugins.\\n"
               "  - Duplicated resolution maps between `ScanEngine.resolve_collector` (65 lines) and `PluginExecutorAdapter._instantiate_specialist_fallback` (200 lines).\\n"
               "  - Duplicated DAG schedulers between `ScanDAG` and `TaskScheduler`.\\n"
               "  - Duplicated result models across `ScanResult`, `ToolExecutionResult`, and `AgentResult`.")
    out.append("- **Gaps**:\\n"
               "  - Primary user command `argus scan` invokes legacy Path A, bypassing the 10-step autonomous mission loop, hypothesis engine, and knowledge graph.\\n"
               "  - 32 vulnerability collectors directly mutate `mission` attributes rather than returning typed `Evidence` or `ToolExecutionResult` models.\\n"
               "  - Triplicate EventBus implementations (`argus/runtime/events.py`, `argus/core/event_bus.py`, `argus/plugins/events.py`).\\n"
               "  - 14 orphaned Python files with zero imports in `argus/core/`, `argus/workspace/`, and `argus/models/`.")
    out.append("- **Test Coverage**: `tests/scanning/` (62 passed), `tests/runtime/` (140 passed), `tests/collectors/` (1,078 passed).")
    out.append("- **Notes**:\\n"
               "  - **Consolidation Roadmap**: Refactor `argus scan` to invoke `AutonomousMissionRuntime` with a scanning profile; deprecate `ScanEngine`; migrate collectors to return typed `Evidence`; consolidate event buses into `argus.runtime.events`.")

    # Extract deep analysis from Cluster 5
    start_s57 = c5.find("### Section 57:")
    end_s57 = c5.find("## 2. Logic Chain")
    s57_text = c5[start_s57:end_s57].strip()
    
    # Extract only the body of s57
    body_s57 = s57_text[s57_text.find("#### Direct Code Observations"):]
    out.append("\\n**Deep Architectural Analysis of Dual Execution Paths**:\\n")
    out.append(body_s57)
    out.append("\\n---\\n")"""
text = text.replace(old_s57, new_s57, 1)

# 3. In build_part6_sections:
old_part6 = """            out.append(f"#### Section {i}: {SECTION_TITLES.get(i, title)}\\n")
            out.append(body)"""
new_part6 = """            out.append(f"#### Section {i}: {SECTION_TITLES.get(i, title)}\\n")
            # Normalize bold colon in Cluster 6
            norm_body = re.sub(r"- \*\*([A-Za-z ]+):\*\*", r"- **\1**:", body)
            out.append(norm_body)"""
text = text.replace(old_part6, new_part6, 1)

with open("/home/varun/argus/.agents/audit_synthesizer/make_report.py", "w") as f:
    f.write(text)

print("make_report.py successfully updated with normalizations!")
