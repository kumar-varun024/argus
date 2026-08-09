import json
import os
from typing import List, Optional
from dataclasses import asdict
from argus.benchmark.leaderboard.models import LeaderboardEntry

class Leaderboard:
    def __init__(self, storage_path: str = ".argus/leaderboard.json"):
        self.storage_path = storage_path
        self._entries: List[LeaderboardEntry] = []
        self._load()
        
    def _load(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, "r") as f:
                data = json.load(f)
                for item in data:
                    self._entries.append(LeaderboardEntry(**item))
                    
    def _save(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, "w") as f:
            json.dump([asdict(e) for e in self._entries], f, indent=2)
            
    def register(self, entry: LeaderboardEntry):
        # Prevent exact duplicates by ID
        if not any(e.id == entry.id for e in self._entries):
            self._entries.append(entry)
            self._save()
            
    def get_entries(self, dataset_id: Optional[str] = None, argus_version: Optional[str] = None, commit_sha: Optional[str] = None) -> List[LeaderboardEntry]:
        results = self._entries
        if dataset_id:
            results = [e for e in results if e.dataset_id == dataset_id]
        if argus_version:
            results = [e for e in results if e.argus_version == argus_version]
        if commit_sha:
            results = [e for e in results if e.commit_sha == commit_sha]
            
        # Sort by overall score descending
        return sorted(results, key=lambda x: x.overall_score, reverse=True)
        
    def get_by_id(self, entry_id: str) -> Optional[LeaderboardEntry]:
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None
