from dataclasses import dataclass
from typing import List

@dataclass
class StorageLocation:
    type: str # Temporary, Permanent, CDN, S3
    path_pattern: str

class StorageAnalyzer:
    def infer_storage(self, paths: List[str]) -> List[StorageLocation]:
        locations = []
        for path in paths:
            lower = path.lower()
            if "tmp" in lower or "temp" in lower:
                locations.append(StorageLocation(type="Temporary", path_pattern=path))
            elif "s3" in lower or "bucket" in lower:
                locations.append(StorageLocation(type="S3", path_pattern=path))
            elif "cdn" in lower:
                locations.append(StorageLocation(type="CDN", path_pattern=path))
        return locations
