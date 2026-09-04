# Argus — Improvement Guide

> **Purpose**: This document describes every feature in the Argus codebase that is not fully implemented. Each entry explains exactly what is wrong and provides step-by-step instructions to fix it. There are **19 items** total: **1 broken**, **2 missing**, **16 partial**.
>
> **Working Directory**: `/home/varun/argus`
>
> **Important**: After making changes for any item, run the full test suite with `python -m pytest tests/ -v --tb=short` and ensure zero regressions (current baseline: 2,463 tests, 0 failures).

---

## Table of Contents

| # | Section | Status | Priority | Summary |
|:---:|:---|:---:|:---:|:---|
| 1 | [Performance CLI Mount Bug](#1-section-46-performance-cli-mount-bug) | 🔴 Broken | P0 | One-line fix: missing `name=` argument |
| 2 | [Event Bus Test Coverage](#2-section-10-event-bus-test-coverage) | ⚠️ Partial | P0 | Tests exist but pytest can't discover them |
| 3 | [Credential Vault](#3-section-40-credential-vault) | ❌ Missing | P1 | No secure credential storage exists |
| 4 | [Project Identity & README](#4-section-1-project-identity--readme) | ⚠️ Partial | P1 | README.md is 0 bytes; tagline mismatch |
| 5 | [Scope Manager](#5-section-4-scope-manager) | ⚠️ Partial | P1 | No exclude scope, no bug-bounty importer |
| 6 | [Policy Engine](#6-section-5-policy-engine) | ⚠️ Partial | P2 | Logic scattered across 3+ modules |
| 7 | [Configuration System](#7-section-44-configuration-system) | ⚠️ Partial | P2 | Env-vars only, no file-based config |
| 8 | [Rules Engine](#8-section-43-rules-engine) | ⚠️ Partial | P2 | No unified engine, no external rule DSL |
| 9 | [CLI Surface](#9-section-48-cli-surface) | ⚠️ Partial | P2 | 3 broken + 6 stub commands |
| 10 | [API Intelligence CLI](#10-section-33-api-intelligence-cli) | ⚠️ Partial | P2 | `graph` and `explain` are print stubs |
| 11 | [Plugin SDK CLI](#11-section-38-plugin-sdk-cli) | ⚠️ Partial | P2 | `install/remove/enable/disable` are stubs |
| 12 | [Controlled Plugin Execution](#12-section-39-controlled-plugin-execution) | ⚠️ Partial | P2 | Collectors bypass ControlledMission |
| 13 | [Architectural Cleanup](#13-section-57-architectural-cleanup) | ⚠️ Partial | P3 | Dual execution paths, 3 event buses |
| 14 | [Core Architecture Stubs](#14-section-2-core-architecture-stubs) | ⚠️ Partial | P3 | `core/models.py` and `core/scheduler.py` are stubs |
| 15 | [Technology Packs](#15-section-59-technology-packs) | ⚠️ Partial | P3 | No modular pack framework |
| 16 | [Technology-Aware Investigation](#16-section-70-technology-aware-investigation) | ⚠️ Partial | P3 | Generic detection, no pack-driven planning |
| 17 | [Mission Replay](#17-section-74-mission-replay) | ⚠️ Partial | P3 | No deterministic replay runner |
| 18 | [Production Hardening](#18-section-76-production-hardening) | ⚠️ Partial | P3 | Missing vault, dual paths, no deploy configs |
| 19 | [Core Success Criteria](#19-section-78-core-success-criteria) | ⚠️ Partial | P4 | North Star vision — ongoing |

---

## 1. Section 46: Performance CLI Mount Bug

**Status**: 🔴 BROKEN  
**Priority**: P0 — Immediate one-line fix  
**Affected File**: `argus/cli/app.py` line 71

### What's Wrong

In `argus/cli/app.py:71`, the performance CLI is mounted without a `name` argument:

```python
# CURRENT (line 71) — BROKEN
app.add_typer(performance_app)
```

This causes two problems:
1. `argus performance` fails with `Error: No such command 'performance'`
2. The unnamed mount shadows the `benchmark` command mounted at line 58, breaking `argus benchmark` too

### How to Fix

Change line 71 in `argus/cli/app.py` from:
```python
app.add_typer(performance_app)
```
to:
```python
app.add_typer(performance_app, name="performance")
```

### Verification
```bash
python -m argus performance --help
python -m argus benchmark --help
```
Both commands should display their help text without errors.

---

## 2. Section 10: Event Bus Test Coverage

**Status**: ⚠️ PARTIAL  
**Priority**: P0 — Quick fix  
**Affected File**: `tests/test_event_bus.py`

### What's Wrong

The entire test file contains top-level procedural code instead of `test_*` functions. Pytest collects 0 tests from it:

```python
# CURRENT — pytest cannot discover these
from argus.core.event_bus import EventBus

def on_host_found(host):
    print(f"Host discovered: {host}")

bus = EventBus()
bus.subscribe("HostFound", on_host_found)
bus.publish("HostFound", "api.twilio.com")
```

### How to Fix

Rewrite `tests/test_event_bus.py` to use proper pytest test functions:

```python
from argus.core.event_bus import EventBus


def test_event_bus_subscribe_and_publish():
    """Test that subscribing to an event and publishing it calls the handler."""
    received = []

    def on_host_found(host):
        received.append(host)

    bus = EventBus()
    bus.subscribe("HostFound", on_host_found)
    bus.publish("HostFound", "api.twilio.com")

    assert len(received) == 1
    assert received[0] == "api.twilio.com"


def test_event_bus_multiple_subscribers():
    """Test that multiple subscribers all receive the event."""
    results_a = []
    results_b = []

    bus = EventBus()
    bus.subscribe("ScanComplete", lambda data: results_a.append(data))
    bus.subscribe("ScanComplete", lambda data: results_b.append(data))
    bus.publish("ScanComplete", {"target": "example.com"})

    assert len(results_a) == 1
    assert len(results_b) == 1


def test_event_bus_no_subscribers():
    """Test that publishing to an event with no subscribers does not raise."""
    bus = EventBus()
    bus.publish("UnknownEvent", "data")  # Should not raise


def test_event_bus_different_events():
    """Test that subscribers only receive events they subscribed to."""
    received = []

    bus = EventBus()
    bus.subscribe("EventA", lambda data: received.append(("A", data)))
    bus.publish("EventB", "should_not_appear")

    assert len(received) == 0
```

### Verification
```bash
python -m pytest tests/test_event_bus.py -v
```
Should show 4 tests passing.

---

## 3. Section 40: Credential Vault

**Status**: ❌ MISSING  
**Priority**: P1 — Security-critical  
**Affected Files**: No vault module exists. Credentials are stored in plaintext in:
- `argus/models/test_identity.py:35` — `credentials: Dict[str, Any]`
- `argus/runtime/mission.py:168` — `credentials: list[dict]`
- `argus/runtime/history.py` — dumps credentials to `.argus/history/` JSON files
- `argus/runtime/checkpoint.py` — dumps credentials to `.argus/checkpoints/` JSON files

### What's Wrong

There is no `CredentialVault` class or `argus/vault/` package anywhere in the codebase. Sensitive credentials (passwords, API keys, bearer tokens) are:
1. Stored as plain `Dict[str, Any]` in `TestIdentity.credentials`
2. Stored as `list[dict]` in `Mission.credentials`
3. Serialized **unencrypted** to JSON files on disk during checkpointing and history storage

### How to Fix

Create a new `argus/vault/` package with at minimum:

**`argus/vault/__init__.py`**:
```python
from argus.vault.vault import CredentialVault
```

**`argus/vault/vault.py`** — Implement a `CredentialVault` class that:

1. **Stores credentials in memory encrypted** using `cryptography.fernet.Fernet` (symmetric AES-128-CBC):
   - Generate or load a vault key from an environment variable `ARGUS_VAULT_KEY` or from a file `~/.argus/vault.key`
   - If no key exists, auto-generate one on first use and save to `~/.argus/vault.key` with `chmod 600`

2. **Provides a clean API**:
   ```python
   class CredentialVault:
       def store(self, credential_id: str, credential_data: dict) -> None: ...
       def retrieve(self, credential_id: str) -> dict: ...
       def delete(self, credential_id: str) -> None: ...
       def list_ids(self) -> list[str]: ...
       def exists(self, credential_id: str) -> bool: ...
   ```

3. **Encrypts at rest**: When serializing mission state to disk (in `argus/runtime/history.py` and `argus/runtime/checkpoint.py`), credential fields must be replaced with a vault reference ID (`{"vault_ref": "cred_id_xxx"}`) instead of raw credential values.

4. **Redacts from logs**: Override `__repr__` and `to_dict()` on credential-holding objects to mask sensitive fields (show `"***REDACTED***"` instead of actual values).

5. **Update `TestIdentity.to_dict()`** in `argus/models/test_identity.py:110-129` to redact the `credentials` field when serializing, unless an explicit `include_secrets=True` parameter is passed.

6. **Update `Mission` serialization** in `argus/runtime/mission.py` to store vault references instead of raw credentials.

**`tests/vault/test_vault.py`** — Write tests:
```python
def test_store_and_retrieve(): ...
def test_retrieve_nonexistent_raises(): ...
def test_delete(): ...
def test_list_ids(): ...
def test_credentials_encrypted_on_disk(): ...
def test_to_dict_redacts_by_default(): ...
```

### Dependencies
```bash
pip install cryptography
```
Add `cryptography` to `pyproject.toml` dependencies.

---

## 4. Section 1: Project Identity & README

**Status**: ⚠️ PARTIAL  
**Priority**: P1  
**Affected Files**:
- `README.md` (0 bytes — empty)
- `pyproject.toml` (tagline mismatch)

### What's Wrong

1. `README.md` is completely empty (0 bytes). There is no project description, installation guide, or architecture overview.
2. Tagline mismatch: `pyproject.toml` says `"Autonomous Offensive Security Platform"`, but the specification defines Argus as `"open-source, AI-assisted platform for authorized penetration testing and bug-bounty security research"`.

### How to Fix

1. **Write `README.md`** with at minimum:
   - Project name and description matching the spec: "Argus is an open-source, AI-assisted platform for authorized penetration testing and bug-bounty security research."
   - Core principles (scope-first execution, evidence-backed reasoning, etc.)
   - Installation instructions (`pip install -e .`)
   - Quick-start usage (how to create a mission, run a scan)
   - Architecture overview (the pipeline: Mission → Scope → Policy → Runtime → Evidence → Correlation → Investigation → Report)
   - CLI reference summary
   - License

2. **Update `pyproject.toml`** line 4 — change description from:
   ```toml
   description = "Autonomous Offensive Security Platform"
   ```
   to:
   ```toml
   description = "Open-source, AI-assisted platform for authorized penetration testing and bug-bounty security research"
   ```

3. **Update `argus/cli/app.py`** — update the Typer help string to match:
   ```python
   app = typer.Typer(help="Argus — AI-assisted platform for authorized penetration testing and bug-bounty security research")
   ```

---

## 5. Section 4: Scope Manager

**Status**: ⚠️ PARTIAL  
**Priority**: P1  
**Affected File**: `argus/authorization/scope.py`

### What's Wrong

1. **No exclude scope support**: `ScopeResolver` only has whitelist logic (checking if targets match `mission.scope`). There is no way to define excluded targets that should never be tested even if they match an include rule.
2. **No bug-bounty scope importer**: No parser exists for importing scope from HackerOne/Bugcrowd program definitions (JSON/YAML).
3. **No passive-only mode** within the scope resolver itself.
4. **Class naming**: The spec calls it `ScopeManager` but the implementation is `ScopeResolver`.

### How to Fix

1. **Add exclude scope support** to `ScopeResolver` in `argus/authorization/scope.py`:
   - Modify `check_scope()` to accept an `exclude_scope` list from `mission.exclude_scope` (a new field on Mission)
   - Check excludes FIRST — if a target matches any exclude rule, return `OUT_OF_SCOPE` immediately, before checking include rules
   - Add `exclude_scope: list = field(default_factory=list)` to the `Mission` dataclass in `argus/runtime/mission.py`

2. **Add a `ScopeManager` facade class** (or rename `ScopeResolver` to `ScopeManager`) that wraps the resolver with additional methods:
   ```python
   class ScopeManager:
       def __init__(self, mission):
           self.resolver = ScopeResolver()
           self.mission = mission

       def is_in_scope(self, target: str) -> bool: ...
       def add_include(self, rule: str) -> None: ...
       def add_exclude(self, rule: str) -> None: ...
       def import_bugbounty_scope(self, program_data: dict) -> None: ...
       def is_passive_only(self) -> bool: ...
   ```

3. **Bug-bounty scope importer**: Add a method `import_bugbounty_scope(program_data: dict)` that parses a dictionary with keys like `{"in_scope": [{"asset_type": "URL", "asset_identifier": "*.example.com"}], "out_of_scope": [...]}` (matching HackerOne's common format) and populates `mission.scope` and `mission.exclude_scope`.

4. **Add passive-only mode**: Add a `passive_only: bool = False` field to Mission, and have the scope manager check it when deciding allowed operations.

5. **Write tests** in `tests/authorization/test_scope_manager.py`:
   ```python
   def test_exclude_scope_overrides_include(): ...
   def test_import_bugbounty_scope(): ...
   def test_passive_only_mode(): ...
   ```

---

## 6. Section 5: Policy Engine

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected Files**:
- `argus/runtime/sandbox.py` — `SafetyValidator`
- `argus/authorization/gate.py` — `AuthorizationGate`
- `argus/authorization/rules.py` — role hierarchy rules
- `argus/workspace/context/policy.py` — `ContextPolicy`

### What's Wrong

Policy enforcement logic is scattered across 4+ modules with no unified `PolicyEngine` class. Each module independently checks different aspects of policy, making it hard to audit, extend, or configure centrally.

### How to Fix

1. **Create `argus/policy/__init__.py` and `argus/policy/engine.py`** with a unified `PolicyEngine` class:

   ```python
   class PolicyEngine:
       """Centralized policy enforcement for all Argus operations."""

       def __init__(self, mission):
           self.mission = mission
           self.policy = mission.execution_policy or {}

       def can_execute_tool(self, tool, context) -> PolicyDecision: ...
       def can_access_target(self, target: str) -> PolicyDecision: ...
       def is_operation_allowed(self, operation: str) -> PolicyDecision: ...
       def is_passive_only(self) -> bool: ...
       def get_allowed_permissions(self) -> set: ...
       def validate_agent_permissions(self, agent, action) -> PolicyDecision: ...
   ```

2. **Refactor `SafetyValidator.validate()`** to delegate to `PolicyEngine` methods instead of containing inline policy logic.

3. **Refactor `AuthorizationGate.can_execute_action()`** to delegate to `PolicyEngine`.

4. **Add `argus/policy/models.py`** with a `PolicyDecision` dataclass:
   ```python
   @dataclass
   class PolicyDecision:
       allowed: bool
       reason: str
       policy_rule: str = ""
   ```

5. **Write tests** in `tests/policy/test_engine.py`:
   ```python
   def test_blocked_operations(): ...
   def test_blocked_categories(): ...
   def test_permission_enforcement(): ...
   def test_passive_only_blocks_active_tools(): ...
   def test_policy_decision_has_reason(): ...
   ```

---

## 7. Section 44: Configuration System

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected File**: `argus/config.py` (only 29 lines, env-vars only)

### What's Wrong

The entire configuration system is a 29-line file that reads environment variables with `os.getenv()`. There is:
- No file-based config (`argus.yaml` or `argus.json`)
- No configuration validation (typos in env var names silently produce `None`)
- No profile management (passive, aggressive, bugbounty)
- No `argus config` CLI command

### How to Fix

1. **Replace `argus/config.py`** with a Pydantic-based configuration system:

   ```python
   from pydantic import BaseModel, Field
   from pathlib import Path
   import yaml, os

   class AIConfig(BaseModel):
       provider: str = "none"
       github_token: str = ""
       github_model: str = "deepseek/DeepSeek-V3-0324"
       openai_api_key: str = ""
       gemini_api_key: str = ""
       anthropic_api_key: str = ""

   class RuntimeConfig(BaseModel):
       timeout: int = 300
       max_concurrent_tools: int = 5
       passive_only: bool = False

   class ArgusConfig(BaseModel):
       ai: AIConfig = AIConfig()
       runtime: RuntimeConfig = RuntimeConfig()
       plugin_dir: str = "plugins"
       data_dir: str = ".argus"

   def load_config(config_path: str = "argus.yaml") -> ArgusConfig:
       """Load config from YAML file, with env var overrides."""
       ...
   ```

2. **Support config file discovery**: Look for `argus.yaml` in the current directory, then `~/.argus/config.yaml`, then fall back to env vars.

3. **Add `argus config` CLI command** in `argus/cli/config_cli.py`:
   ```
   argus config show     — display current resolved config
   argus config init     — create a default argus.yaml
   argus config validate — validate the current config file
   ```

4. **Add tests** in `tests/test_config.py`:
   ```python
   def test_load_default_config(): ...
   def test_load_from_yaml_file(): ...
   def test_env_var_overrides_yaml(): ...
   def test_validation_catches_bad_values(): ...
   ```

---

## 8. Section 43: Rules Engine

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected Files**:
- `argus/correlation/rules.py` — 13 hardcoded matching rules
- `argus/authorization/rules.py` — role hierarchy rules

### What's Wrong

Detection rules are split across multiple subpackages with no unified `RulesEngine` class. All rules are hardcoded in Python — there is no way for users to define custom rules via YAML or a DSL.

### How to Fix

1. **Create `argus/rules/__init__.py` and `argus/rules/engine.py`**:

   ```python
   class RulesEngine:
       """Unified deterministic rules engine for detection, correlation, and policy."""

       def __init__(self):
           self.rules: list[Rule] = []

       def load_builtin_rules(self) -> None: ...
       def load_rules_from_yaml(self, path: str) -> None: ...
       def register_rule(self, rule: Rule) -> None: ...
       def evaluate(self, context: dict) -> list[RuleMatch]: ...
   ```

2. **Create `argus/rules/models.py`**:
   ```python
   @dataclass
   class Rule:
       id: str
       name: str
       description: str
       category: str  # "correlation", "authorization", "detection"
       conditions: list[dict]  # structured conditions
       actions: list[str]  # what to do on match
       severity: str = "medium"
       enabled: bool = True

   @dataclass
   class RuleMatch:
       rule: Rule
       matched_data: dict
       confidence: float
   ```

3. **Support YAML rule definitions** — create `argus/rules/loader.py` that parses rules from YAML files:
   ```yaml
   # Example: rules/custom_rules.yaml
   rules:
     - id: custom_sqli_timing
       name: "SQL Injection Timing"
       category: correlation
       conditions:
         - type: observation_match
           field: category
           value: "sql_injection"
         - type: timing_anomaly
           threshold_ms: 5000
       severity: high
   ```

4. **Migrate existing rules**: Wrap the 13 functions in `argus/correlation/rules.py` as `Rule` objects registered with the engine.

5. **Write tests** in `tests/rules/test_engine.py`:
   ```python
   def test_builtin_rules_load(): ...
   def test_yaml_rule_loading(): ...
   def test_rule_evaluation(): ...
   def test_custom_rule_registration(): ...
   ```

---

## 9. Section 48: CLI Surface

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected File**: `argus/cli/app.py` and various `argus/cli/*_cli.py`

### What's Wrong

1. **3 Broken Commands**:
   - `argus performance` — missing `name=` argument (see Item #1 above)
   - `argus benchmark` — shadowed by unnamed performance mount
   - `argus intelligence list` — crashes with `TypeError: 'InvestigationRegistry' object is not iterable`

2. **6 Demo/Stub Commands** that use hardcoded targets instead of accepting mission IDs:
   - `argus execution status/history` — hardcoded `plan-uuid-1234`
   - `argus plugin install/remove/enable/disable` — print stubs (see Item #11)
   - `argus plan` — hardcoded `test.com`
   - `argus research` — hardcoded `demo.example.com`
   - `argus scheduler` — hardcoded `scheduler.example.com`
   - `argus execute` — uses `get_dummy_plan()`

### How to Fix

1. **Fix the 3 broken commands**:
   - Performance CLI: see Item #1 fix
   - Intelligence list: Fix the iteration in `argus/cli/intelligence_cli.py` — the `InvestigationRegistry` object needs to expose an `__iter__` method or the CLI needs to call a `.list()` or `.get_all()` method instead of iterating directly

2. **Replace hardcoded targets with mission-id parameters**:
   - For each stub command, replace hardcoded mission creation with `mission_manager.get_mission(mission_id)` lookups
   - Add `mission_id: str` as a required Typer argument
   - Remove all `get_dummy_plan()`, hardcoded `"test.com"`, `"demo.example.com"` patterns

3. **Add a `--demo` flag** for commands that need demo data, rather than defaulting to it:
   ```python
   @app.command()
   def status(mission_id: str, demo: bool = typer.Option(False, help="Use demo data")):
       if demo:
           # use demo data
       else:
           mission = mission_manager.get_mission(mission_id)
   ```

---

## 10. Section 33: API Intelligence CLI

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected File**: `argus/cli/api_cli.py` lines 48-51 and 77-80

### What's Wrong

Two CLI subcommands are print-only placeholders:

```python
# Line 48-51 — STUB
@app.command()
def graph(mission_id: str):
    console.print("[cyan]Displaying API relationships graph...[/cyan]")
    console.print("(Not fully implemented in CLI yet. Refer to relationships data in the mission object.)")

# Line 77-80 — STUB
@app.command()
def explain(resource_id: str):
    console.print(f"[cyan]Explaining resource {resource_id}...[/cyan]")
    console.print("(Detailed explanations to be implemented.)")
```

### How to Fix

1. **Implement `argus api graph`** — Load the mission, access `mission.resources` and the `RelationshipInferencer` from `argus/plugins/api/relationships.py`, and render a Rich tree or table showing parent-child API resource relationships:

   ```python
   @app.command()
   def graph(mission_id: str):
       """Display API resource relationships graph."""
       from argus.runtime.manager import mission_manager
       from argus.plugins.api.relationships import RelationshipInferencer

       mission = mission_manager.get_mission(mission_id)
       if not mission or not getattr(mission, 'resources', None):
           console.print("[yellow]No API resources found. Run 'argus api inventory' first.[/yellow]")
           return

       inferencer = RelationshipInferencer()
       relationships = inferencer.infer(mission.resources)

       table = Table(title=f"API Relationships for {mission_id}")
       table.add_column("Parent", style="cyan")
       table.add_column("Child", style="green")
       table.add_column("Relationship", style="yellow")

       for rel in relationships:
           table.add_row(rel.parent, rel.child, rel.relationship_type)

       console.print(table)
   ```

2. **Implement `argus api explain`** — Look up a specific resource by ID/path from the mission state, and display its operations, relationships, heuristic findings, and security observations:

   ```python
   @app.command()
   def explain(mission_id: str, resource_path: str):
       """Explain a specific API resource's security analysis."""
       from argus.runtime.manager import mission_manager

       mission = mission_manager.get_mission(mission_id)
       resource = mission.resources.get(resource_path)
       if not resource:
           console.print(f"[red]Resource '{resource_path}' not found.[/red]")
           return

       console.print(f"[bold]Resource:[/bold] {resource.name}")
       console.print(f"[bold]Path:[/bold] {resource_path}")
       console.print(f"[bold]Collection:[/bold] {resource.is_collection}")
       # Display operations, relationships, and heuristic findings
       ...
   ```

---

## 11. Section 38: Plugin SDK CLI

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected File**: `argus/cli/plugin_cli.py` lines 45-64

### What's Wrong

Four CLI subcommands are print-only stubs with no actual logic:

```python
# Lines 45-49 — STUB
@app.command()
def install(path: str):
    console.print(f"[green]Installing plugin from {path}...[/green]")
    console.print("Installation logic (copy/symlink) will go here.")

# Lines 51-54 — STUB
@app.command()
def remove(name: str):
    console.print(f"[red]Removing plugin {name}...[/red]")

# Lines 56-59 — STUB
@app.command()
def enable(name: str):
    console.print(f"[green]Enabling plugin {name}...[/green]")

# Lines 61-64 — STUB
@app.command()
def disable(name: str):
    console.print(f"[yellow]Disabling plugin {name}...[/yellow]")
```

### How to Fix

1. **Implement `install`**: Copy or symlink the plugin directory from `path` into the configured plugin directory (`ARGUS_PLUGIN_DIR`). Validate that the source contains a valid `PluginManifest`. Check dependency compatibility.

2. **Implement `remove`**: Locate the plugin by name in the plugin directory, remove its directory (or unlink if symlinked), and update any plugin registry/state files.

3. **Implement `enable`/`disable`**: Create a plugin state file (e.g., `plugins/.plugin_state.json`) that tracks which plugins are enabled/disabled. The `PluginManager.load_all()` method should consult this state file and skip disabled plugins.

4. **Example implementation for `install`**:
   ```python
   @app.command()
   def install(path: str):
       """Install a plugin into the active plugin directory."""
       import shutil
       from pathlib import Path

       source = Path(path)
       if not source.exists():
           console.print(f"[red]Path '{path}' does not exist.[/red]")
           raise typer.Exit(1)

       # Validate manifest exists
       manifest_file = source / "manifest.json"
       if not manifest_file.exists():
           console.print("[red]No manifest.json found in plugin directory.[/red]")
           raise typer.Exit(1)

       plugin_dir = Path(os.environ.get("ARGUS_PLUGIN_DIR", "plugins"))
       dest = plugin_dir / source.name
       shutil.copytree(source, dest, dirs_exist_ok=True)
       console.print(f"[green]Plugin installed to {dest}[/green]")
   ```

---

## 12. Section 39: Controlled Plugin Execution

**Status**: ⚠️ PARTIAL  
**Priority**: P2  
**Affected Files**:
- `argus/plugins/interfaces.py:16-37` — `ControlledMission` class
- `argus/collectors/*.py` — 32 collector modules

### What's Wrong

`ControlledMission` exists and is properly designed as a read-only facade over the Mission object. However, many collector modules (e.g., `argus/collectors/sql_injection.py`, `argus/collectors/xss.py`, etc.) bypass it entirely and directly access `self._mission` or raw mission attributes, breaking the encapsulation that `ControlledMission` is supposed to enforce.

### How to Fix

1. **Audit all collectors**: Search for direct `_mission` access in collectors:
   ```bash
   grep -rn "_mission\." argus/collectors/ | grep -v "ControlledMission"
   ```

2. **Refactor each collector** to:
   - Accept `ControlledMission` instead of raw `Mission` in its `execute()` / `collect()` method
   - Use `controlled_mission.target` instead of `self._mission.target`
   - Use `controlled_mission.publish_finding()` instead of directly mutating `mission.findings`

3. **Expand `ControlledMission`** in `argus/plugins/interfaces.py` to expose more read-only properties that collectors need:
   ```python
   @property
   def scope(self) -> list:
       return list(self._mission.scope)

   @property
   def endpoints(self) -> list:
       return list(self._mission.endpoints)

   @property
   def technologies(self) -> list:
       return list(getattr(self._mission, 'technologies', []))

   @property
   def options(self) -> dict:
       return dict(getattr(self._mission, 'options', {}))

   def add_evidence(self, evidence_type: str, data: dict) -> None:
       """Safe method to add evidence without raw mission access."""
       ...
   ```

4. **Add validation**: Make `ControlledMission._mission` truly private by using `__mission` (name-mangled) to prevent accidental access.

---

## 13. Section 57: Architectural Cleanup

**Status**: ⚠️ PARTIAL  
**Priority**: P3 — Major refactoring effort  
**Affected Files**:
- **Path A (Legacy)**: `argus/scanning/engine.py`, `argus/scanning/dag.py`, `argus/collectors/*.py` (32 modules)
- **Path B (Modern)**: `argus/runtime/mission_runtime.py`, `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py`
- **Duplicate Event Buses**: `argus/runtime/events.py`, `argus/core/event_bus.py`, `argus/plugins/events.py`

### What's Wrong

Three parallel execution paths exist:
1. **Legacy DAG Scanner** (`argus/scanning/engine.py` + `ScanDAG` + 32 collectors) — invoked via `argus scan`
2. **Autonomous Mission Runtime** (`argus/runtime/mission_runtime.py`) — invoked via `argus mission run`
3. **Legacy Agent Step Execution** (`argus/execution/engine.py`)

Additionally, there are 3 separate `EventBus` implementations that should be unified.

### How to Fix

This is a large refactoring effort. Recommended approach in phases:

**Phase 1 — Unify Event Buses**:
- Pick `argus/runtime/events.py` as the canonical EventBus
- Update all imports from `argus/core/event_bus.py` and `argus/plugins/events.py` to use `argus/runtime/events.py`
- Delete the duplicate event bus files
- Run tests to verify no regressions

**Phase 2 — Route `argus scan` through Mission Runtime**:
- Modify `argus/cli/scan_cli.py` to create a `Mission` and invoke `AutonomousMissionRuntime` instead of `ScanEngine` directly
- Keep collectors as the underlying tool implementations but have them be invoked via the dispatcher/orchestrator

**Phase 3 — Migrate Collectors to Return Typed Evidence**:
- Refactor each collector to return `ToolExecutionResult` objects with typed evidence instead of directly mutating mission state
- Use `ControlledMission` (see Item #12)

**Phase 4 — Deprecate Legacy Modules**:
- Mark `argus/scanning/engine.py`, `argus/scanning/dag.py`, `argus/core/event_bus.py`, `argus/core/scheduler.py`, `argus/core/models.py`, `argus/execution/engine.py` as deprecated
- Remove them after all tests pass without them

---

## 14. Section 2: Core Architecture Stubs

**Status**: ⚠️ PARTIAL  
**Priority**: P3  
**Affected Files**:
- `argus/core/models.py` — only 2 lines (a comment)
- `argus/core/scheduler.py` — 10-line stub with a pass-through generator

### What's Wrong

These files are legacy stubs that contain no real logic:

```python
# argus/core/models.py — entire file
# pyrefly: ignore [missing-import]
```

```python
# argus/core/scheduler.py — entire file
from typing import Iterable

class Scheduler:
    def run(self, tasks: Iterable):
        for task in tasks:
            yield task
```

### How to Fix

1. **Check if anything imports these files**:
   ```bash
   grep -rn "from argus.core.models" argus/ tests/
   grep -rn "from argus.core.scheduler" argus/ tests/
   ```

2. **If nothing imports them**: Delete both files. They are dead code from a legacy architecture.

3. **If something imports them**: Either migrate the imports to the modern equivalents (`argus/runtime/models.py` for models, `argus/planning/scheduler.py` or `argus/runtime/scheduler.py` for scheduling) or add real implementations.

4. **Clean up `argus/core/`**: Check all files in `argus/core/` for similar stubs and remove or consolidate.

---

## 15. Section 59: Technology Packs

**Status**: ⚠️ PARTIAL  
**Priority**: P3  
**Affected Files**: `argus/collectors/technology.py` (generic technology detection)

### What's Wrong

Specialists 9.6–9.9 (Authentication, File Upload, GraphQL, JavaScript) are fully implemented. However, **Technology Packs (9.10)** — modular per-framework intelligence packages (e.g., Django Pack, Spring Boot Pack, WordPress Pack) — do not exist. Technology detection is generic rather than framework-specific.

### How to Fix

1. **Create a Technology Pack framework** in `argus/plugins/techpacks/`:
   ```
   argus/plugins/techpacks/
       __init__.py
       base.py          # BaseTechnologyPack ABC
       registry.py      # TechPackRegistry
       django.py        # DjangoTechPack
       spring.py        # SpringBootTechPack
       wordpress.py     # WordPressTechPack
       nextjs.py        # NextJSTechPack
       laravel.py       # LaravelTechPack
   ```

2. **Define `BaseTechnologyPack`**:
   ```python
   class BaseTechnologyPack(ABC):
       name: str
       technology_signatures: list[str]  # e.g., ["Django", "django"]
       security_questions: list[str]     # framework-specific questions to investigate
       common_vulnerabilities: list[str] # e.g., ["Django DEBUG mode", "ALLOWED_HOSTS misconfiguration"]
       default_endpoints: list[str]      # e.g., ["/admin/", "/__debug__/"]

       @abstractmethod
       def get_investigation_blueprint(self, mission) -> list[ResearchTask]: ...

       @abstractmethod
       def get_security_checks(self) -> list[dict]: ...
   ```

3. **Register packs** with the existing plugin system so they are auto-discovered.

4. **Integrate with `ResearchPlanner`**: When a technology is detected that matches a pack's signatures, the planner should retrieve the pack's investigation blueprints and generate framework-specific research tasks.

---

## 16. Section 70: Technology-Aware Investigation

**Status**: ⚠️ PARTIAL  
**Priority**: P3  
**Affected Files**:
- `argus/planning/research_planner.py`
- `argus/investigation/scoring.py`
- `argus/collectors/technology.py`

### What's Wrong

Generic technology detection and scoring exist, but the planning pipeline doesn't use modular Technology Packs (from Item #15) to generate framework-specific investigation tasks. The planner queries `KnowledgeManager.search(technology=tech)` but there is no structured pack-driven planning.

### How to Fix

This depends on Item #15 (Technology Packs) being implemented first. Once packs exist:

1. **Update `ResearchPlanner.plan()`** in `argus/planning/research_planner.py` to:
   - Check detected technologies against the `TechPackRegistry`
   - If a matching pack is found, call `pack.get_investigation_blueprint(mission)` to get framework-specific research tasks
   - Merge pack-generated tasks with the standard gap analysis tasks

2. **Update `ScoreCalculator`** in `argus/investigation/scoring.py` to give higher priority to investigations that align with a detected technology pack's `common_vulnerabilities`.

---

## 17. Section 74: Mission Replay

**Status**: ⚠️ PARTIAL  
**Priority**: P3  
**Affected Files**:
- `argus/runtime/history.py` — `MissionStorage` (stores history)
- `argus/runtime/checkpoint.py` — `MissionCheckpointer` (creates checkpoints)
- `argus/runtime/recovery.py` — `RecoveryManager` (recovers from checkpoints)

### What's Wrong

Checkpoint storage and recovery exist, but there is no dedicated **replay runner** that can deterministically re-execute a previous mission step-by-step for debugging, regression testing, or benchmarking.

### How to Fix

1. **Create `argus/runtime/replay.py`**:
   ```python
   class MissionReplayRunner:
       """Replays a previously executed mission from stored history."""

       def __init__(self, history_path: str):
           self.history = self._load_history(history_path)

       def replay(self, step_by_step: bool = False) -> ReplayReport:
           """Re-execute the mission using stored inputs and compare outputs."""
           ...

       def compare_results(self, original, replayed) -> DiffReport:
           """Compare original vs replayed results for regression detection."""
           ...
   ```

2. **Add `argus replay` CLI command** in `argus/cli/replay_cli.py`:
   ```
   argus replay <mission_id>           — replay a mission from history
   argus replay <mission_id> --diff    — replay and show differences
   argus replay <mission_id> --step    — step-by-step replay
   ```

3. **Write tests** in `tests/runtime/test_replay.py`:
   ```python
   def test_replay_produces_same_results(): ...
   def test_replay_diff_detects_changes(): ...
   ```

---

## 18. Section 76: Production Hardening

**Status**: ⚠️ PARTIAL  
**Priority**: P3  
**Affected Files**: Multiple across the codebase

### What's Wrong

Several production readiness items remain:
1. Credential Vault is missing (see Item #3)
2. Dual execution paths remain (see Item #13)
3. No production deployment configurations (Docker Compose, Helm charts)
4. 51,958 deprecation warnings (Pydantic V1 datetime parsing, legacy typing)

### How to Fix

1. **Implement Credential Vault** (Item #3)
2. **Unify execution paths** (Item #13)
3. **Create deployment configs**:
   - `docker/Dockerfile` — production Docker image
   - `docker/docker-compose.yml` — local development stack
4. **Fix deprecation warnings**:
   - Update Pydantic V1 datetime parsing to V2 syntax
   - Replace deprecated `typing` imports (e.g., `typing.List` → `list`, `typing.Dict` → `dict`)
5. **Add `argus doctor` CLI** that checks:
   - External tool availability (subfinder, httpx, katana, nuclei)
   - Configuration validity
   - Plugin health
   - Credential vault status

---

## 19. Section 78: Core Success Criteria

**Status**: ⚠️ PARTIAL  
**Priority**: P4 — Ongoing North Star  
**Affected Files**: Codebase-wide integration

### What's Wrong

All architectural building blocks exist and are integrated. The full autonomous end-to-end research pipeline (from mission creation through autonomous investigation to validated report) works but remains the long-term North Star. The separation between planning, investigation, hypothesis, evidence, validation, and report stages is implemented but not yet seamlessly automated across arbitrary unknown targets.

### How to Fix

This is the overarching vision rather than a specific bug. Progress depends on completing all items above, particularly:
1. Items #13 (Architectural Cleanup) — eliminate competing execution paths
2. Items #3 (Credential Vault) — enable authenticated research flows
3. Items #15-16 (Technology Packs) — enable technology-aware investigation
4. Items #5-6 (Scope Manager + Policy Engine) — strengthen safety guarantees

Once those are complete, build integration tests that exercise the full pipeline:
```python
def test_full_pipeline_recon_to_report():
    """Test the complete Argus pipeline from mission creation to report generation."""
    mission = Mission("test-target.example.com")
    runtime = AutonomousMissionRuntime(mission)
    report = runtime.execute_full_pipeline()
    assert report is not None
    assert len(report.findings) >= 0
    assert report.provenance is not None
```

---

## Quick Reference: File Change Summary

| File | Change Type | Items |
|:---|:---:|:---:|
| `argus/cli/app.py:71` | One-line fix | #1 |
| `tests/test_event_bus.py` | Rewrite | #2 |
| `argus/vault/` (new package) | Create | #3 |
| `README.md` | Create | #4 |
| `pyproject.toml` | Edit | #4 |
| `argus/authorization/scope.py` | Extend | #5 |
| `argus/policy/` (new package) | Create | #6 |
| `argus/config.py` | Replace | #7 |
| `argus/rules/` (new package) | Create | #8 |
| `argus/cli/*_cli.py` (multiple) | Fix/Implement | #9, #10, #11 |
| `argus/plugins/interfaces.py` | Extend | #12 |
| `argus/collectors/*.py` | Refactor | #12, #13 |
| `argus/scanning/engine.py` | Deprecate | #13 |
| `argus/core/models.py` | Delete | #14 |
| `argus/core/scheduler.py` | Delete | #14 |
| `argus/plugins/techpacks/` (new) | Create | #15 |
| `argus/planning/research_planner.py` | Extend | #16 |
| `argus/runtime/replay.py` (new) | Create | #17 |
