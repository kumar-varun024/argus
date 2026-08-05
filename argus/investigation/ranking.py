import logging
from typing import List, Optional, Union
from argus.investigation.models import Investigation, InvestigationPriority, InvestigationCategory

logger = logging.getLogger(__name__)

class InvestigationRanker:
    """Sorts and filters investigations for the Priority Engine."""
    
    @staticmethod
    def rank(
        investigations: List[Investigation], 
        highest_first: bool = True,
        category: Optional[Union[InvestigationCategory, str]] = None,
        priority: Optional[Union[InvestigationPriority, str]] = None,
        business_object: Optional[str] = None,
        workflow: Optional[str] = None,
        technology: Optional[str] = None
    ) -> List[Investigation]:
        """
        Filters and sorts a list of investigations deterministically.
        Supports filtering by Category, Priority, Business Object, Workflow, and Technology.
        Supports sorting by Highest First or Lowest First.
        """
        cat_val = category.value if isinstance(category, InvestigationCategory) else category
        prio_val = priority.value if isinstance(priority, InvestigationPriority) else priority

        filtered = []
        for inv in investigations:
            # Filter by Category
            if cat_val is not None:
                if inv.category.value.lower() != str(cat_val).lower():
                    continue

            # Filter by Priority
            if prio_val is not None:
                if inv.priority.value.lower() != str(prio_val).lower():
                    continue

            # Filter by Business Object
            if business_object is not None:
                bo_target = business_object.lower()
                bo_match = any(bo_target in bo.lower() for bo in inv.business_objects)
                if not bo_match:
                    continue

            # Filter by Workflow
            if workflow is not None:
                wf_target = workflow.lower()
                wf_match = any(wf_target in wf.lower() for wf in inv.workflows)
                if not wf_match:
                    continue

            # Filter by Technology
            if technology is not None:
                tech_target = technology.lower()
                all_techs = [t.lower() for t in (inv.technologies + inv.tags)]
                tech_meta = inv.metadata.get('technology') or inv.metadata.get('technologies') or []
                if isinstance(tech_meta, str):
                    all_techs.append(tech_meta.lower())
                elif isinstance(tech_meta, list):
                    all_techs.extend([str(t).lower() for t in tech_meta])
                
                tech_match = any(tech_target in t for t in all_techs)
                if not tech_match:
                    continue

            filtered.append(inv)
            
        # Sort by score, fallback to confidence, then by string ID to remain 100% deterministic
        filtered.sort(
            key=lambda x: (x.priority_score, x.confidence, str(x.id)),
            reverse=highest_first
        )
        
        logger.info(f"Ranking updated. Queue size: {len(filtered)}")
        return filtered
