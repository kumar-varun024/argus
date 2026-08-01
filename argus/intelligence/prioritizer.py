from typing import List
from argus.intelligence.models import Investigation

class InvestigationPrioritizer:
    
    PRIORITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"]
    
    def prioritize(self, investigations: List[Investigation]) -> List[Investigation]:
        """
        Assigns priority strings based on category, confidence, and affected objects.
        Then sorts the investigations from Critical to Informational.
        """
        for inv in investigations:
            inv.priority = self._calculate_priority(inv)
            
        # Sort investigations by severity (Critical first)
        def sort_key(i: Investigation):
            try:
                return self.PRIORITY_LEVELS.index(i.priority)
            except ValueError:
                return 99 # Push unknown priorities to bottom
                
        return sorted(investigations, key=sort_key)
        
    def _calculate_priority(self, inv: Investigation) -> str:
        # Heavily weigh confidence
        if inv.confidence >= 90:
            if inv.category in ["Authorization", "Authentication", "Business Logic"]:
                return "Critical"
            return "High"
            
        if inv.confidence >= 70:
            if inv.category in ["Authorization", "Authentication"]:
                return "High"
            return "Medium"
            
        if inv.confidence >= 40:
            return "Low"
            
        return "Informational"
