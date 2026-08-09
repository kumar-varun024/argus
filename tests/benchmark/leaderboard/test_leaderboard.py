import pytest
import os
from argus.benchmark.leaderboard.leaderboard import Leaderboard
from argus.benchmark.leaderboard.models import LeaderboardEntry

def test_leaderboard_registration_and_retrieval(tmp_path):
    storage = str(tmp_path / "lb.json")
    lb = Leaderboard(storage_path=storage)
    
    e1 = LeaderboardEntry(id="1", benchmark_id="b1", dataset_id="d1", dataset_version="1", argus_version="1", commit_sha="a", timestamp="2", overall_score=80.0)
    e2 = LeaderboardEntry(id="2", benchmark_id="b1", dataset_id="d1", dataset_version="1", argus_version="1", commit_sha="b", timestamp="1", overall_score=90.0)
    
    lb.register(e1)
    lb.register(e2)
    
    # Should sort by score descending
    entries = lb.get_entries(dataset_id="d1")
    assert len(entries) == 2
    assert entries[0].id == "2" # 90.0
    assert entries[1].id == "1" # 80.0
    
    # Check persistence
    lb2 = Leaderboard(storage_path=storage)
    entries2 = lb2.get_entries(dataset_id="d1")
    assert len(entries2) == 2
    assert entries2[0].id == "2"
