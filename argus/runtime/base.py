from abc import ABC, abstractmethod


class Runtime(ABC):

    @abstractmethod
    def run_command(
        self,
        executable: str,
        args: list[str] | None = None,
        stdin: str | None = None,
    ):
        pass
