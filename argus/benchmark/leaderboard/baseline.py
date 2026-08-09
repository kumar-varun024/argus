from typing import Optional
from argus.benchmark.leaderboard.leaderboard import Leaderboard
from argus.benchmark.leaderboard.models import LeaderboardEntry

class BaselineResolver:
    
    def __init__(self, leaderboard: Leaderboard):
        self.leaderboard = leaderboard
        
    def resolve(self, dataset_id: str, baseline_id: Optional[str] = None, commit_sha: Optional[str] = None) -> Optional[LeaderboardEntry]:
        """Resolves the baseline entry to compare against."""
        
        if baseline_id:
            return self.leaderboard.get_by_id(baseline_id)
            
        entries = self.leaderboard.get_entries(dataset_id=dataset_id)
        if not entries:
            return None
            
        # If commit SHA provided, find the best score for that commit
        if commit_sha:
            commit_entries = [e for e in entries if e.commit_sha == commit_sha]
            if commit_entries:
                return commit_entries[0] # Sorted by score descending
                
        # Fallback to the latest successful run (highest score globally for dataset)
        return entries[0]
