"""
Behavioral regression snapshots (characterization tests).

These lock the CURRENT observable behavior of the subsystems that the
architecture refactor will move/merge, so any unintended change is caught
immediately. They are the regression oracle for:

  * DAG / profile composition        -> protects planning template extraction
                                         and the scanning -> engines move.
  * tool_id -> collector resolution  -> protects unifying the three resolvers
                                         (ScanEngine.resolve_collector,
                                          PluginExecutorAdapter fallback,
                                          ToolRegistry aliases).
  * Mission dataclass field surface  -> protects the Mission decomposition.

If a change to behavior is *intentional* (e.g. merging the two CORS collectors
in Phase 4), regenerate the affected snapshot deliberately with:

    ARGUS_UPDATE_SNAPSHOTS=1 python -m pytest tests/regression -q

and review the resulting diff as part of that change.
"""
from __future__ import annotations

import dataclasses
import json
import os
import pathlib

from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.engine import ScanEngine

SNAP_DIR = pathlib.Path(__file__).parent / "snapshots"
_UPDATE = os.environ.get("ARGUS_UPDATE_SNAPSHOTS") == "1"

# Comprehensive id universe: canonical tool ids + the aliases that the three
# resolvers currently understand (registry alias dict + collector_class_map +
# PluginExecutorAdapter substring branches). Kept explicit so the snapshot is a
# stable, reviewable contract rather than something derived from private dicts.
_ALIAS_IDS = sorted(set("""
httpx httpx_toolkit live_host_detector live_hosts subfinder subdomain_enumerator
katana katana_crawler crawler nuclei vulnerability_scanner technology takeover
subdomain_takeover javascript info_disclosure information_disclosure access_control
idor path_traversal traversal lfi sql_injection sqli xss cross_site_scripting
command_injection cmdi rce ssrf server_side_request_forgery oauth oidc xml_parser
xml_parser_validation xxe deserialization deser pickle graphql_security
graphql_introspection websocket_security websocket cswsh request_smuggling smuggling
desync race_conditions race toctou business_logic mass_assignment ssti
template_injection cache_security cache_poison web_cache cors_security cors
header_security hsts csp file_upload upload api_security bola auth_bypass
authentication_bypass credential_attack brute_force mfa_bypass session_fixation
jwt_manipulation default_credentials prototype_pollution proto_pollution
client_side_attacks dom_clobbering open_redirect clickjacking authorization authz
authentication authn api business
""".split()))


def _qual(obj) -> str | None:
    if obj is None:
        return None
    t = type(obj)
    return f"{t.__module__}.{t.__name__}"


def _all_ids() -> list[str]:
    full = ScanDAG.create_for_profile("full")
    dag_ids = {t.tool_id for t in full.tasks} | {t.key for t in full.tasks}
    return sorted(set(_ALIAS_IDS) | dag_ids)


def _current_dag() -> dict:
    snap = {}
    for profile in ["full", "recon", "vuln", "quick"]:
        order = ScanDAG.create_for_profile(profile).get_execution_order()
        snap[profile] = [
            {
                "key": t.key,
                "tool_id": t.tool_id,
                "phase": t.phase,
                "priority": round(float(t.priority), 4),
                "dependencies": sorted(t.dependencies),
            }
            for t in order
        ]
    return snap


def _current_resolve() -> dict:
    eng = ScanEngine()
    out = {}
    for i in _all_ids():
        try:
            out[i] = _qual(eng.resolve_collector(ScanTask(key=i, title=i, tool_id=i)))
        except Exception as e:  # noqa: BLE001 - characterizing current behavior
            out[i] = f"ERROR:{type(e).__name__}"
    return out


def _current_fallback() -> dict:
    adapter = PluginExecutorAdapter()
    out = {}
    for i in _all_ids():
        try:
            out[i] = _qual(adapter._instantiate_specialist_fallback(i))
        except Exception as e:  # noqa: BLE001 - characterizing current behavior
            out[i] = f"ERROR:{type(e).__name__}"
    return out


def _current_mission() -> dict:
    fields = [{"name": f.name, "type": str(f.type)} for f in dataclasses.fields(Mission)]
    return {"fields": fields, "count": len(fields)}


def _assert_snapshot(name: str, current) -> None:
    path = SNAP_DIR / name
    if _UPDATE:
        path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        return
    assert path.exists(), f"Missing snapshot {path}; generate with ARGUS_UPDATE_SNAPSHOTS=1"
    expected = json.loads(path.read_text())
    assert current == expected, (
        f"Behavioral snapshot drift in {name}. If intentional, regenerate with "
        f"ARGUS_UPDATE_SNAPSHOTS=1 and review the diff."
    )


def test_dag_profiles_snapshot():
    _assert_snapshot("dag_profiles.json", _current_dag())


def test_resolve_collector_snapshot():
    _assert_snapshot("resolve_collector.json", _current_resolve())


def test_specialist_fallback_snapshot():
    _assert_snapshot("specialist_fallback.json", _current_fallback())


def test_mission_fields_snapshot():
    _assert_snapshot("mission_fields.json", _current_mission())
