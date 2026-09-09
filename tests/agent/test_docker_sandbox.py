"""Spec tests for the hardened Docker sandbox (dockerSandbox).

Uses a fake runner so no real container runs. Proves the hardened `docker run`
argv is emitted, output is captured/truncated, timeouts kill the container, and
the executor is fail-closed when Docker is unavailable.
"""
from __future__ import annotations

import subprocess

import pytest

from argus.agent.dockerSandbox import (
    DEFAULT_IMAGE,
    DockerSandbox,
    SandboxConfig,
    SandboxResult,
    SandboxUnavailable,
)


class FakeRunner:
    def __init__(self, version_ok=True, result=(0, "out", "err"), raise_timeout_on_run=False):
        self.version_ok = version_ok
        self.result = result
        self.raise_timeout_on_run = raise_timeout_on_run
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        if argv[:2] == ["docker", "version"]:
            return (0 if self.version_ok else 1, "29.0.0" if self.version_ok else "", "")
        if argv[:2] == ["docker", "kill"]:
            return (0, "", "")
        if self.raise_timeout_on_run:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        return self.result


def test_build_run_argv_is_hardened():
    sb = DockerSandbox(runner=FakeRunner())
    argv = sb.buildRunArgv("httpx", ["-u", "https://example.com"], "argus-hunt-test")
    joined = " ".join(argv)
    for flag in ["--rm", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--read-only", "--user 65534:65534", "--pids-limit", "--memory", "--cpus", "--network"]:
        assert flag in joined, flag
    assert DEFAULT_IMAGE in argv
    # tool binary + args are the trailing tokens, not a shell string
    assert argv[-3:] == ["httpx", "-u", "https://example.com"]


def test_run_captures_output():
    sb = DockerSandbox(runner=FakeRunner(result=(0, "scan output", "")))
    res = sb.run("dig", ["+short", "example.com"])
    assert isinstance(res, SandboxResult)
    assert res.returncode == 0
    assert res.stdout == "scan output"
    assert res.timed_out is False


def test_run_fail_closed_when_docker_unavailable():
    sb = DockerSandbox(runner=FakeRunner(version_ok=False))
    with pytest.raises(SandboxUnavailable):
        sb.run("dig", ["+short", "example.com"])


def test_run_timeout_kills_container():
    fake = FakeRunner(raise_timeout_on_run=True)
    sb = DockerSandbox(runner=fake)
    res = sb.run("nmap", ["-sV", "example.com"], timeout=5.0)
    assert res.timed_out is True
    assert res.returncode == 124
    assert any(call[:2] == ["docker", "kill"] for call in fake.calls)


def test_output_is_truncated():
    huge = "A" * 500_000
    sb = DockerSandbox(runner=FakeRunner(result=(0, huge, "")))
    res = sb.run("curl", ["-s", "https://example.com"])
    assert len(res.stdout) <= 200_000


def test_custom_network_is_used():
    sb = DockerSandbox(config=SandboxConfig(network="argus-egress-scoped"), runner=FakeRunner())
    argv = sb.buildRunArgv("httpx", ["-u", "https://example.com"], "n")
    assert "argus-egress-scoped" in argv
