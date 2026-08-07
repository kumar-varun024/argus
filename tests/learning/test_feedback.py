"""Unit tests for argus.learning.feedback"""
import pytest
from argus.learning.feedback import FeedbackCollector, FeedbackSummarizer
from argus.learning.models import FeedbackEntry, FeedbackTag, FeedbackTargetType
from argus.learning.registry import LearningRegistry


def _make_registry(tmp_path):
    return LearningRegistry(storage_path=str(tmp_path / "lr.json"))


class TestFeedbackCollector:
    def test_submit_creates_entry(self, tmp_path):
        reg = _make_registry(tmp_path)
        collector = FeedbackCollector(reg)

        from argus.runtime.mission import Mission
        mission = Mission(target="test")

        entry = collector.submit(
            mission=mission,
            target_id="deadbeef-0000-0000-0000-000000000000",
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.HIGH_VALUE,
            comment="Good one",
            researcher="alice",
        )

        assert isinstance(entry, FeedbackEntry)
        assert entry.tag == FeedbackTag.HIGH_VALUE
        assert entry.researcher == "alice"
        assert entry.comment == "Good one"

    def test_submit_appends_to_mission_feedback(self, tmp_path):
        reg = _make_registry(tmp_path)
        collector = FeedbackCollector(reg)

        from argus.runtime.mission import Mission
        mission = Mission(target="test")
        assert mission.feedback == []

        collector.submit(
            mission=mission,
            target_id="aaaaaaaa-0000-0000-0000-000000000000",
            target_type=FeedbackTargetType.TASK,
            tag=FeedbackTag.FALSE_POSITIVE,
        )
        assert len(mission.feedback) == 1

    def test_submit_persists_to_registry(self, tmp_path):
        reg = _make_registry(tmp_path)
        collector = FeedbackCollector(reg)

        from argus.runtime.mission import Mission
        mission = Mission(target="test")

        collector.submit(
            mission=mission,
            target_id="bbbbbbbb-0000-0000-0000-000000000000",
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.DUPLICATE,
        )
        stored = reg.get_feedback("bbbbbbbb-0000-0000-0000-000000000000")
        assert len(stored) == 1
        assert stored[0].tag == FeedbackTag.DUPLICATE

    def test_submit_multiple_feedback_same_target(self, tmp_path):
        reg = _make_registry(tmp_path)
        collector = FeedbackCollector(reg)

        from argus.runtime.mission import Mission
        mission = Mission(target="test")
        tid = "cccccccc-0000-0000-0000-000000000000"

        for tag in [FeedbackTag.HIGH_VALUE, FeedbackTag.NEEDS_IMPROVEMENT]:
            collector.submit(mission=mission, target_id=tid,
                             target_type=FeedbackTargetType.INVESTIGATION, tag=tag)

        stored = reg.get_feedback(tid)
        assert len(stored) == 2


class TestFeedbackSummarizer:
    def _make_entries(self, tags):
        return [
            FeedbackEntry(
                mission_id="m", target_id="t",
                target_type=FeedbackTargetType.INVESTIGATION, tag=t
            )
            for t in tags
        ]

    def test_summarize_counts(self):
        entries = self._make_entries([
            FeedbackTag.HIGH_VALUE,
            FeedbackTag.HIGH_VALUE,
            FeedbackTag.FALSE_POSITIVE,
        ])
        summary = FeedbackSummarizer.summarize(entries)
        assert summary[FeedbackTag.HIGH_VALUE.value] == 2
        assert summary[FeedbackTag.FALSE_POSITIVE.value] == 1

    def test_summarize_empty(self):
        assert FeedbackSummarizer.summarize([]) == {}

    def test_useful_rate_all_positive(self):
        entries = self._make_entries([
            FeedbackTag.HIGH_VALUE, FeedbackTag.USEFUL_INVESTIGATION
        ])
        assert FeedbackSummarizer.useful_rate(entries) == pytest.approx(1.0)

    def test_useful_rate_none(self):
        entries = self._make_entries([FeedbackTag.FALSE_POSITIVE])
        assert FeedbackSummarizer.useful_rate(entries) == pytest.approx(0.0)

    def test_useful_rate_mixed(self):
        entries = self._make_entries([
            FeedbackTag.HIGH_VALUE, FeedbackTag.FALSE_POSITIVE,
            FeedbackTag.DUPLICATE, FeedbackTag.USEFUL_INVESTIGATION,
        ])
        assert FeedbackSummarizer.useful_rate(entries) == pytest.approx(0.5)

    def test_useful_rate_empty(self):
        assert FeedbackSummarizer.useful_rate([]) == 0.0

    def test_false_positive_rate(self):
        entries = self._make_entries([
            FeedbackTag.FALSE_POSITIVE, FeedbackTag.HIGH_VALUE,
        ])
        assert FeedbackSummarizer.false_positive_rate(entries) == pytest.approx(0.5)
