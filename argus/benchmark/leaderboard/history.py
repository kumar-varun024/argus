from typing import List, Dict, Any
from argus.benchmark.leaderboard.leaderboard import Leaderboard

class HistoryTracker:
    
    def __init__(self, leaderboard: Leaderboard):
        self.leaderboard = leaderboard
        
    def get_trend(self, dataset_id: str, limit: int = 10) -> Dict[str, Any]:
        """Extracts historical trend for a given dataset across multiple runs/versions."""
        entries = self.leaderboard.get_entries(dataset_id=dataset_id)
        
        # Sort by timestamp ascending to get chronological order
        entries = sorted(entries, key=lambda x: x.timestamp)[-limit:]
        
        if not entries:
            return {"status": "No historical data available"}
            
        trend_data = {
            "timestamps": [e.timestamp for e in entries],
            "overall_scores": [e.overall_score for e in entries],
            "coverage_scores": [e.coverage_score for e in entries],
            "investigation_scores": [e.investigation_score for e in entries],
            "false_positive_rates": [e.false_positive_score for e in entries],
            "runtimes": [e.runtime_score for e in entries],
            "argus_versions": [e.argus_version for e in entries]
        }
        
        return trend_data
