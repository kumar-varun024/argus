import subprocess

from argus.runtime.base import Runtime


class LocalRuntime(Runtime):

    def run_command(
        self,
        executable: str,
        args: list[str] | None = None,
        stdin: str | None = None,
    ):

        if args is None:
            args = []

        result = subprocess.run(
            [executable, *args],
            input=stdin,
            text=True,
            capture_output=True,
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
