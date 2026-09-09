"""Isolated command executor: runs ONE allowlisted command inside a throwaway,
hardened Docker container. This is the real sandbox (the legacy
runtime.sandbox.Sandbox is a bare subprocess.run with no isolation and is NOT
used here).

Hardening: --rm, non-root user, all capabilities dropped, no-new-privileges,
read-only rootfs + tmpfs workdir, pids/memory/cpu caps, and a wall-clock timeout
after which the container is killed. Network egress is bound to the operator-
supplied network (which should be egress-filtered to in-scope hosts); scope is
already enforced deterministically by commandGate before anything reaches here,
so the network is defence in depth.

Fail-closed: if the Docker daemon or the tools image is unavailable, run() raises
SandboxUnavailable -- there is no host-subprocess fallback.
"""
from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

DEFAULT_IMAGE: str = "argus/hunt-tools:latest"
DEFAULT_TIMEOUT_SECONDS: float = 300.0
MAX_OUTPUT_CHARS: int = 200_000

# runner(argv, timeout) -> (returncode, stdout, stderr); injectable for tests.
Runner = Callable[[List[str], float], Tuple[int, str, str]]


@dataclass(frozen=True)
class SandboxConfig:
    image: str = DEFAULT_IMAGE
    network: str = "bridge"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 128
    default_timeout: float = DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True)
class SandboxResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


class SandboxUnavailable(RuntimeError):
    """Raised when Docker/the image is unavailable (fail-closed, no fallback)."""


def _defaultRunner(argv: List[str], timeout: float) -> Tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


class DockerSandbox:
    def __init__(self, config: Optional[SandboxConfig] = None, runner: Optional[Runner] = None):
        self._config = config or SandboxConfig()
        self._runner = runner or _defaultRunner

    def isAvailable(self) -> bool:
        try:
            code, _out, _err = self._runner(["docker", "version", "--format", "{{.Server.Version}}"], 10.0)
            return code == 0
        except Exception:
            return False

    def buildRunArgv(self, binary: str, args: List[str], container_name: str) -> List[str]:
        """The hardened `docker run` argv. Pure -> unit-testable. The tool binary
        and args are the trailing argv (never a shell string)."""
        cfg = self._config
        return [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", cfg.network,
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--pids-limit", str(cfg.pids_limit),
            "--memory", cfg.memory,
            "--cpus", cfg.cpus,
            cfg.image,
            binary, *args,
        ]

    def run(self, binary: str, args: List[str], timeout: Optional[float] = None) -> SandboxResult:
        if not self.isAvailable():
            raise SandboxUnavailable("Docker is unavailable; refusing to run (fail-closed).")
        timeout = timeout or self._config.default_timeout
        container_name = f"argus-hunt-{uuid.uuid4().hex[:12]}"
        argv = self.buildRunArgv(binary, args, container_name)
        try:
            code, stdout, stderr = self._runner(argv, timeout)
            return SandboxResult(stdout[:MAX_OUTPUT_CHARS], stderr[:MAX_OUTPUT_CHARS], code)
        except subprocess.TimeoutExpired:
            self._killQuietly(container_name)
            return SandboxResult("", f"Command timed out after {timeout}s.", returncode=124, timed_out=True)

    def _killQuietly(self, container_name: str) -> None:
        try:
            self._runner(["docker", "kill", container_name], 10.0)
        except Exception:
            pass
