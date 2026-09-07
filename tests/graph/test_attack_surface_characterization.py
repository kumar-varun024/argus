"""
Characterization test for AttackSurfaceGraphBuilder.

This is a CHARACTERIZATION test (V-02): the expected graphs were captured
from the implementation itself before its extraction from a monolithic
1,481-line module into argus.graph.attackSurface, not derived from an
external spec. It is evidence the extraction preserved behavior -- not
evidence that any individual node/edge produced is "correct" business logic.

45 scenarios: a broad sweep (one representative evidence item per category,
sections 2-29, sharing one graph exactly as a real mission run would), plus
isolated edge cases for every bespoke section and the shared resolve_lh
helper. Achieves 100% line/branch coverage of the original method's unique
logic, measured with `coverage run --branch` before the extraction; the
21 structurally-identical "generic vulnerability block" sections (9,11,
13-29) are proven byte-identical to the deep-dived path_traversal
representative via a separate AST fingerprint tool (category lists and
literal defaults), not via redundant per-section functional tests here.

If a change to behavior is intentional, regenerate deliberately with:

    ARGUS_UPDATE_SNAPSHOTS=1 python -m pytest tests/graph/test_attack_surface_characterization.py -q

and review the resulting diff as part of that change.
"""
from __future__ import annotations

import json
import os
import pathlib

from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from tests.graph import attackSurfaceEvidenceScenarios, attackSurfaceMissionScenarios

SNAP_PATH = pathlib.Path(__file__).parent / "snapshots" / "attack_surface_characterization.json"
_UPDATE = os.environ.get("ARGUS_UPDATE_SNAPSHOTS") == "1"


def _buildAllResults() -> dict:
    builder = AttackSurfaceGraphBuilder()
    results: dict = {}
    attackSurfaceEvidenceScenarios.runAll(builder, results)
    attackSurfaceMissionScenarios.runAll(builder, results)
    return results


def test_characterization_attack_surface_graph_builder():
    """45-scenario graph-equality oracle for AttackSurfaceGraphBuilder.

    Characterization test (V-02): pins current behavior captured before the
    1,286-line build_from_evidence method + 178-line build method were split
    into argus/graph/attackSurface/; not an assertion that any given
    node/edge mapping reflects an external spec.
    """
    results = _buildAllResults()
    if _UPDATE:
        SNAP_PATH.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
        return
    assert SNAP_PATH.exists(), f"Missing snapshot {SNAP_PATH}; generate with ARGUS_UPDATE_SNAPSHOTS=1"
    expected = json.loads(SNAP_PATH.read_text())
    assert results == expected, (
        "AttackSurfaceGraphBuilder behavior drifted. If intentional, regenerate with "
        "ARGUS_UPDATE_SNAPSHOTS=1 python -m pytest tests/graph/test_attack_surface_characterization.py -q "
        "and review the diff."
    )
