from dataclasses import dataclass, field
from typing import List

@dataclass
class PluginManifest:
    name: str
    version: str
    author: str
    description: str
    entrypoint: str
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    minimum_argus_version: str = "1.0.0"
