from dataclasses import dataclass
from typing import List
from argus.plugins.api.resource_model import APIResource

@dataclass
class ResourceRelationship:
    parent: str
    child: str
    relationship_type: str # "owns", "references", "nested"

class RelationshipInferencer:
    def infer(self, resources: List[APIResource]) -> List[ResourceRelationship]:
        relationships = []
        paths = {r.path: r for r in resources}
        for r in resources:
            parts = [p for p in r.path.split('/') if p]
            # Naive nesting logic for /orgs/{org_id}/projects
            if len(parts) >= 3 and '{' in parts[-2] and '}' in parts[-2]:
                parent_path = '/' + '/'.join(parts[:-2])
                if parent_path in paths:
                    relationships.append(ResourceRelationship(
                        parent=paths[parent_path].name,
                        child=r.name,
                        relationship_type="owns"
                    ))
        return relationships
