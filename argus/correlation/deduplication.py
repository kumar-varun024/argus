import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class EvidenceDeduplicator:
    """Removes duplicate evidence while maintaining provenance."""
    
    def deduplicate(self, evidence_list: List[Any]) -> List[Any]:
        """
        Deduplicates a list of evidence items.
        Preserves the first occurrence.
        """
        seen = set()
        unique = []
        for ev in evidence_list:
            # We assume evidence can be stringified or is hashable. 
            # In a more complex model, evidence might have an ID or specific fields.
            try:
                ev_str = str(ev)
                if ev_str not in seen:
                    seen.add(ev_str)
                    unique.append(ev)
                else:
                    logger.debug("Evidence deduplicated")
            except Exception:
                # If it can't be hashed/stringified easily, keep it
                unique.append(ev)
        
        return unique
