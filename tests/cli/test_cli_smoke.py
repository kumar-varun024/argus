"""
CLI smoke tests.

These are deliberately shallow but high-value: they guarantee that the CLI
*boots*. A large mocked unit-test suite can stay green even when the real
command-line entrypoint cannot start because of a missing/undeclared
dependency somewhere in its eager import chain
(cli.app -> core.mission -> runtime.mission -> reporting -> vector -> numpy).

If any of those imports break, these tests fail immediately.
"""
import subprocess
import sys

import pytest
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_app_imports():
    """The full CLI import chain must succeed (no missing deps)."""
    from argus.cli.app import app  # noqa: F401

    assert app is not None


def test_reporting_vector_import_chain():
    """
    Explicitly exercise the import chain that previously crashed the CLI
    (reporting -> vector_indexer -> vector -> embeddings -> numpy).
    """
    import numpy  # noqa: F401  — must be installed/declared

    from argus.reporting import vector_indexer  # noqa: F401
    from argus.vector import embeddings  # noqa: F401


def test_cli_help_exits_zero():
    """`argus --help` must return exit code 0 and list top-level commands."""
    from argus.cli.app import app

    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    # A few representative command namespaces should be advertised.
    for cmd in ("mission", "tools", "scan", "search"):
        assert cmd in result.output, f"'{cmd}' missing from --help output"


def test_cli_help_in_fresh_process():
    """
    Run `python -m argus.cli --help` in a brand-new interpreter.

    This is the strongest guard: it catches import-time failures (e.g. a
    dependency that is importable in the pytest session but not actually
    declared) that an in-process test could mask.
    """
    result = subprocess.run(
        [sys.executable, "-m", "argus.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"`python -m argus.cli --help` failed (exit {result.returncode})\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "Argus" in result.stdout


def test_cli_version_in_fresh_process():
    """`argus version` must boot and print a version in a fresh process."""
    result = subprocess.run(
        [sys.executable, "-m", "argus.cli", "version"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "Argus" in result.stdout or "v0" in result.stdout
