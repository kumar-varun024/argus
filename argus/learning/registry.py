"""
Learning Registry.

In-memory + file-backed store for LearningRecord and FeedbackEntry objects.
Persistence is written to .argus/learning_history.json following the same
convention as the Tool Orchestrator's .argus/tool_history.json.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from argus.learning.models import FeedbackEntry, LearningRecord

logger = logging.getLogger(__name__)

_STORAGE_PATH = ".argus/learning_history.json"


def _default_serialiser(obj):
    """JSON serialiser that handles datetime and Pydantic models."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")


class LearningRegistry:
    """
    Centralized store for LearningRecord snapshots and FeedbackEntry objects.

    Records are keyed by mission_id.
    Feedback is keyed by target_id (investigation / hypothesis / task UUID).
    """

    def __init__(self, storage_path: str = _STORAGE_PATH):
        self._storage_path = storage_path
        self._records: Dict[str, LearningRecord] = {}
        self._feedback: Dict[str, List[FeedbackEntry]] = {}  # target_id → entries
        self._all_feedback: List[FeedbackEntry] = []
        self._load()

    # ------------------------------------------------------------------
    # LearningRecord operations
    # ------------------------------------------------------------------

    def add_record(self, record: LearningRecord) -> None:
        """Store or overwrite a LearningRecord for a mission."""
        self._records[record.mission_id] = record
        logger.info(f"Learning: Record stored for mission {record.mission_id}")
        self._save()

    def get_record(self, mission_id: str) -> Optional[LearningRecord]:
        """Retrieve the LearningRecord for a given mission, or None."""
        return self._records.get(mission_id)

    def get_all_records(self) -> List[LearningRecord]:
        """Return all stored LearningRecord objects."""
        return list(self._records.values())

    # ------------------------------------------------------------------
    # FeedbackEntry operations
    # ------------------------------------------------------------------

    def add_feedback(self, entry: FeedbackEntry) -> None:
        """Store a FeedbackEntry, indexed by its target_id."""
        if entry.target_id not in self._feedback:
            self._feedback[entry.target_id] = []
        self._feedback[entry.target_id].append(entry)
        self._all_feedback.append(entry)
        logger.info(
            f"Learning: Feedback received — tag={entry.tag.value} "
            f"target={entry.target_type.value}:{entry.target_id}"
        )
        self._save()

    def get_feedback(self, target_id: str) -> List[FeedbackEntry]:
        """Return all FeedbackEntry objects for a given target UUID."""
        return list(self._feedback.get(target_id, []))

    def get_all_feedback(self) -> List[FeedbackEntry]:
        """Return every FeedbackEntry across all targets."""
        return list(self._all_feedback)

    def clear(self) -> None:
        """Clear all in-memory data (does NOT delete the file)."""
        self._records.clear()
        self._feedback.clear()
        self._all_feedback.clear()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._storage_path) or ".", exist_ok=True)
            payload = {
                "records": {k: v.model_dump() for k, v in self._records.items()},
                "feedback": [e.model_dump() for e in self._all_feedback],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._storage_path, "w") as fh:
                json.dump(payload, fh, indent=2, default=_default_serialiser)
        except Exception as exc:
            logger.warning(f"Learning: Failed to persist registry: {exc}")

    def _load(self) -> None:
        if not os.path.exists(self._storage_path):
            return
        try:
            with open(self._storage_path) as fh:
                payload = json.load(fh)

            for mission_id, rec_data in payload.get("records", {}).items():
                self._records[mission_id] = LearningRecord.model_validate(rec_data)

            for entry_data in payload.get("feedback", []):
                entry = FeedbackEntry.model_validate(entry_data)
                if entry.target_id not in self._feedback:
                    self._feedback[entry.target_id] = []
                self._feedback[entry.target_id].append(entry)
                self._all_feedback.append(entry)

            logger.info(
                f"Learning: Registry loaded — "
                f"{len(self._records)} records, {len(self._all_feedback)} feedback entries"
            )
        except Exception as exc:
            logger.warning(f"Learning: Failed to load registry from {self._storage_path}: {exc}")


# Global singleton — modules import this directly when they don't need DI.
learning_registry = LearningRegistry()
