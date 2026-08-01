from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class APIOperation:
    method: str
    path: str
    resource_name: str
    is_bulk: bool = False
    is_async: bool = False
    authentication: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

class OperationAnalyzer:
    def extract_operations(self, endpoints: List[dict], resources: dict) -> List[APIOperation]:
        ops = []
        for ep in endpoints:
            method = ep.get("method", "GET")
            path = ep.get("path", "/")
            
            # Find matching resource
            res_name = "Unknown"
            for r_path, r in resources.items():
                if path.startswith(r_path):
                    res_name = r.name
                    
            is_bulk = method in ["PUT", "POST", "PATCH"] and "bulk" in path.lower()
            ops.append(APIOperation(
                method=method,
                path=path,
                resource_name=res_name,
                is_bulk=is_bulk,
                authentication=ep.get("auth", [])
            ))
        return ops
