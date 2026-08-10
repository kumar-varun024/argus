import os
import json
import dataclasses
from pathlib import Path
from typing import List, Optional
from argus.evidence.model import Evidence, ProvenanceData, EvidenceRelationship

class EvidenceManager:
    """Manages the persistence and retrieval of research evidence."""
    
    def __init__(self, storage_dir: str = "~/.argus/workspace/evidence"):
        self.storage_dir = Path(os.path.expanduser(storage_dir))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
    def _get_path(self, evidence_id: str) -> Path:
        return self.storage_dir / f"{evidence_id}.json"
        
    def save(self, evidence: Evidence) -> Evidence:
        """Persist evidence to JSON."""
        # Update timestamp
        import datetime
        evidence.updated_at = datetime.datetime.utcnow().isoformat()
        
        path = self._get_path(evidence.evidence_id)
        
        # Serialize dataclass
        data = dataclasses.asdict(evidence)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            
        return evidence
        
    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by ID."""
        path = self._get_path(evidence_id)
        if not path.exists():
            return None
            
        with open(path, "r") as f:
            data = json.load(f)
            
        # Reconstruct dataclass objects safely
        if 'provenance' in data and isinstance(data['provenance'], dict):
            data['provenance'] = ProvenanceData(**data['provenance'])
            
        if 'relationships' in data and isinstance(data['relationships'], list):
            data['relationships'] = [EvidenceRelationship(**r) if isinstance(r, dict) else r for r in data['relationships']]
            
        return Evidence(**data)
        
    def get_by_investigation(self, investigation_id: str) -> List[Evidence]:
        """Returns all evidence linked to a specific investigation."""
        results = []
        for file in self.storage_dir.glob("*.json"):
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    if data.get("investigation_id") == investigation_id:
                        # Reconstruct to Evidence
                        if 'provenance' in data and isinstance(data['provenance'], dict):
                            data['provenance'] = ProvenanceData(**data['provenance'])
                        if 'relationships' in data and isinstance(data['relationships'], list):
                            data['relationships'] = [EvidenceRelationship(**r) if isinstance(r, dict) else r for r in data['relationships']]
                        results.append(Evidence(**data))
            except Exception:
                pass
                
        return sorted(results, key=lambda x: x.created_at)

    def supersede(self, old_evidence_id: str, new_evidence: Evidence) -> Evidence:
        """Marks old evidence as superseded by new evidence."""
        old_ev = self.get(old_evidence_id)
        if old_ev:
            old_ev.status = "SUPERSEDED"
            old_ev.relationships.append(
                EvidenceRelationship(relationship_type="SUPERSEDED_BY", target_id=new_evidence.evidence_id, target_type="evidence")
            )
            self.save(old_ev)
            
            new_evidence.relationships.append(
                EvidenceRelationship(relationship_type="SUPERSEDES", target_id=old_evidence_id, target_type="evidence")
            )
            self.save(new_evidence)
            
        return new_evidence
