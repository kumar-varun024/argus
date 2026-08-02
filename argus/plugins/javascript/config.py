from dataclasses import dataclass, field
from typing import List

@dataclass
class JavaScriptPluginConfig:
    enabled: bool = True
    parse_frameworks: bool = True
    max_file_size_kb: int = 5000
    timeout_seconds: int = 30
