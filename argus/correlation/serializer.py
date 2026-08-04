import json
import uuid
import yaml
from datetime import datetime
from typing import List, Dict, Any

from argus.correlation.observation import Observation

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False


class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, 'dict'):
            return obj.dict()
        return super().default(obj)


class ObservationSerializer:
    """Handles serialization of Observation models across formats."""

    @staticmethod
    def to_dict(observation: Observation) -> Dict[str, Any]:
        """Convert an Observation to a standard dictionary with JSON-safe primitives."""
        # We parse it through JSON to ensure all enums/UUIDs/datetimes are properly cast
        return json.loads(json.dumps(observation.model_dump(), cls=_JSONEncoder))

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Observation:
        return Observation(**data)

    @staticmethod
    def to_json(observation: Observation) -> str:
        return json.dumps(ObservationSerializer.to_dict(observation))

    @staticmethod
    def from_json(data: str) -> Observation:
        return Observation(**json.loads(data))

    @staticmethod
    def to_yaml(observation: Observation) -> str:
        return yaml.dump(ObservationSerializer.to_dict(observation))

    @staticmethod
    def from_yaml(data: str) -> Observation:
        return Observation(**yaml.safe_load(data))

    @staticmethod
    def to_msgpack(observation: Observation) -> bytes:
        if not HAS_MSGPACK:
            raise ImportError("msgpack is not installed. Install it with `pip install msgpack`.")
        return msgpack.packb(ObservationSerializer.to_dict(observation), use_bin_type=True)

    @staticmethod
    def from_msgpack(data: bytes) -> Observation:
        if not HAS_MSGPACK:
            raise ImportError("msgpack is not installed. Install it with `pip install msgpack`.")
        unpacked = msgpack.unpackb(data, raw=False)
        return Observation(**unpacked)

    @staticmethod
    def to_protobuf(observation: Observation):
        """Placeholder for future Protocol Buffers support."""
        raise NotImplementedError("Protobuf serialization is planned for a future release.")
