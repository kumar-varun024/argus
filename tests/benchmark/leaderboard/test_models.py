from argus.benchmark.leaderboard.models import LeaderboardEntry

def test_leaderboard_entry_creation():
    entry = LeaderboardEntry(
        id="test-1",
        benchmark_id="b1",
        dataset_id="d1",
        dataset_version="1.0",
        argus_version="12.0",
        commit_sha="abcdef",
        timestamp="2023-01-01T00:00:00Z",
        overall_score=95.0
    )
    
    assert entry.id == "test-1"
    assert entry.overall_score == 95.0
    assert entry.category_scores == {}
    assert entry.status == "completed"
