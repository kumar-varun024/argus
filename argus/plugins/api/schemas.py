from typing import List
from argus.plugins.api.resource_model import APIResource, APICollection, APISingleton

class SchemaParser:
    def parse_endpoints(self, endpoints: List[dict]) -> dict:
        resources = {}
        for ep in endpoints:
            path = ep.get("path", "")
            # basic grouping
            parts = [p for p in path.split('/') if p]
            if not parts:
                continue
                
            # e.g., /users or /users/{id}
            is_collection = not ('{' in parts[-1] and '}' in parts[-1])
            base_name = parts[-2] if not is_collection and len(parts) > 1 else parts[-1]
            base_path = '/' + '/'.join(parts[:-1]) if not is_collection else path
            
            if base_path not in resources:
                if is_collection:
                    resources[base_path] = APICollection(name=base_name, path=base_path)
                else:
                    resources[base_path] = APISingleton(name=base_name, path=base_path)
        return resources
