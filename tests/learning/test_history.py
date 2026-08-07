"""Unit tests for argus.learning.history"""
import pytest
from argus.learning.history import MissionHistoryStore
from argus.learning.registry import LearningRegistry
from argus.learning.models import LearningRecord
from argus.runtime.mission import Mission


def _make_store(tmp_path):
    reg = LearningRegistry(storage_path=str(tmp_path / "lr.json"))
    return MissionHistoryStore(reg), reg


class TestMissionHistoryStore:
    def test_record_mission_returns_learning_record(self, tmp_path):
        store, _ = _make_store(tmp_path)
        m = Mission(target="example.com")
        record = store.record_mission(m)
        assert isinstance(record, LearningRecord)
        assert record.mission_id == str(m.id)

    def test_record_is_persisted(self, tmp_path):
        store, reg = _make_store(tmp_path)
        m = Mission(target="example.com")
        store.record_mission(m)
        assert reg.get_record(str(m.id)) is not None

    def test_get_record_by_mission_id(self, tmp_path):
        store, _ = _make_store(tmp_path)
        m = Mission(target="example.com")
        store.record_mission(m)
        result = store.get_record(str(m.id))
        assert result is not None
        assert result.mission_id == str(m.id)

    def test_get_nonexistent_returns_none(self, tmp_path):
        store, _ = _make_store(tmp_path)
        assert store.get_record("does-not-exist") is None

    def test_get_all_records(self, tmp_path):
        store, _ = _make_store(tmp_path)
        m1 = Mission(target="a.com")
        m2 = Mission(target="b.com")
        store.record_mission(m1)
        store.record_mission(m2)
        records = store.get_all_records()
        assert len(records) == 2

    def test_investigation_quality_calculated(self, tmp_path):
        store, _ = _make_store(tmp_path)
        m = Mission(target="t")
        # Add investigations with known confidence
        from argus.investigation.models import Investigation, InvestigationCategory
        for conf in [0.6, 0.8]:
            inv = Investigation(
                title="T", summary="S", description="D",
                category=InvestigationCategory.AUTHORIZATION,
                confidence=conf,
            )
            m.investigations.add(inv)
        record = store.record_mission(m)
        assert record.investigation_quality == pytest.approx(0.7)

    def test_completed_and_failed_tasks_extracted(self, tmp_path):
        store, _ = _make_store(tmp_path)
        m = Mission(target="t")
        m.execution_history = [
            {"id": "t1", "status": "COMPLETED"},
            {"id": "t2", "status": "FAILED"},
        ]
        record = store.record_mission(m)
        assert len(record.completed_tasks) == 1
        assert len(record.failed_tasks) == 1

    def test_feedback_included_in_record(self, tmp_path):
        store, _ = _make_store(tmp_path)
        from argus.learning.models import FeedbackEntry, FeedbackTag, FeedbackTargetType
        m = Mission(target="t")
        entry = FeedbackEntry(
            mission_id=str(m.id),
            target_id="x",
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.HIGH_VALUE,
        )
        m.feedback.append(entry)
        record = store.record_mission(m)
        assert len(record.feedback) == 1
        assert record.feedback[0].tag == FeedbackTag.HIGH_VALUE
