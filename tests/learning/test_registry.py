"""Unit tests for argus.learning.registry"""
import pytest
import json
from argus.learning.registry import LearningRegistry
from argus.learning.models import (
    LearningRecord, FeedbackEntry, FeedbackTag, FeedbackTargetType
)


def _make_reg(tmp_path):
    return LearningRegistry(storage_path=str(tmp_path / "lr.json"))


def _rec(mission_id):
    return LearningRecord(mission_id=mission_id)


def _entry(target_id, tag=FeedbackTag.HIGH_VALUE):
    return FeedbackEntry(
        mission_id="m1",
        target_id=target_id,
        target_type=FeedbackTargetType.INVESTIGATION,
        tag=tag,
    )


class TestLearningRegistry:
    def test_add_and_get_record(self, tmp_path):
        reg = _make_reg(tmp_path)
        reg.add_record(_rec("m1"))
        result = reg.get_record("m1")
        assert result is not None
        assert result.mission_id == "m1"

    def test_get_nonexistent_record_returns_none(self, tmp_path):
        reg = _make_reg(tmp_path)
        assert reg.get_record("nonexistent") is None

    def test_get_all_records(self, tmp_path):
        reg = _make_reg(tmp_path)
        reg.add_record(_rec("m1"))
        reg.add_record(_rec("m2"))
        records = reg.get_all_records()
        assert len(records) == 2
        ids = {r.mission_id for r in records}
        assert ids == {"m1", "m2"}

    def test_overwrite_record(self, tmp_path):
        reg = _make_reg(tmp_path)
        r1 = _rec("m1")
        reg.add_record(r1)
        r2 = LearningRecord(mission_id="m1", investigation_quality=0.9)
        reg.add_record(r2)
        stored = reg.get_record("m1")
        assert stored.investigation_quality == pytest.approx(0.9)

    def test_add_and_get_feedback(self, tmp_path):
        reg = _make_reg(tmp_path)
        entry = _entry("t1", FeedbackTag.FALSE_POSITIVE)
        reg.add_feedback(entry)
        stored = reg.get_feedback("t1")
        assert len(stored) == 1
        assert stored[0].tag == FeedbackTag.FALSE_POSITIVE

    def test_get_feedback_missing_target(self, tmp_path):
        reg = _make_reg(tmp_path)
        assert reg.get_feedback("nonexistent") == []

    def test_get_all_feedback(self, tmp_path):
        reg = _make_reg(tmp_path)
        reg.add_feedback(_entry("t1"))
        reg.add_feedback(_entry("t2"))
        all_fb = reg.get_all_feedback()
        assert len(all_fb) == 2

    def test_clear(self, tmp_path):
        reg = _make_reg(tmp_path)
        reg.add_record(_rec("m1"))
        reg.add_feedback(_entry("t1"))
        reg.clear()
        assert reg.get_all_records() == []
        assert reg.get_all_feedback() == []

    def test_persistence_round_trip(self, tmp_path):
        storage = str(tmp_path / "lr.json")
        reg1 = LearningRegistry(storage_path=storage)
        reg1.add_record(_rec("m1"))
        reg1.add_feedback(_entry("t1", FeedbackTag.HIGH_VALUE))

        # Load into a fresh registry pointing to same file
        reg2 = LearningRegistry(storage_path=storage)
        assert reg2.get_record("m1") is not None
        fb = reg2.get_feedback("t1")
        assert len(fb) == 1
        assert fb[0].tag == FeedbackTag.HIGH_VALUE

    def test_persistence_file_contents_are_valid_json(self, tmp_path):
        storage = str(tmp_path / "lr.json")
        reg = LearningRegistry(storage_path=storage)
        reg.add_record(_rec("m1"))
        with open(storage) as f:
            data = json.load(f)
        assert "records" in data
        assert "feedback" in data
        assert "m1" in data["records"]
