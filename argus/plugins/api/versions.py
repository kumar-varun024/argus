from typing import List
from argus.plugins.api.resource_model import APIResource

class VersionDetector:
    def detect_versions(self, resources: List[APIResource]) -> set:
        versions = set()
        for r in resources:
            parts = [p for p in r.path.split('/') if p]
            if parts and parts[0].lower().startswith('v') and parts[0][1:].isdigit():
                versions.add(parts[0].lower())
        return versions
