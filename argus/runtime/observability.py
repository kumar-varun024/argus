import logging
import json
import re
from typing import Any, Dict

logger = logging.getLogger("argus.lifecycle")

SENSITIVE_PATTERNS = [
    re.compile(r'bearer\s+[\w\-]+\.[\w\-]+\.[\w\-]+', re.IGNORECASE), # JWT
    re.compile(r'api_?key[\s=:]+[\w\-]+', re.IGNORECASE),
    re.compile(r'password[\s=:]+[\w\-\.\!@#\$%\^&\*]+', re.IGNORECASE),
    re.compile(r'authorization[\s=:]+[\w\-]+', re.IGNORECASE),
    re.compile(r'cookie[\s=:]+[\w\-\.\=;]+', re.IGNORECASE)
]

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "apikey", "authorization", "cookie"}

def redact(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: "<REDACTED>" if k.lower() in SENSITIVE_KEYS else redact(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact(v) for v in data]
    elif isinstance(data, str):
        redacted_str = data
        for pattern in SENSITIVE_PATTERNS:
            redacted_str = pattern.sub("<REDACTED>", redacted_str)
        # Avoid dumping complete bodies
        if len(redacted_str) > 1000:
            redacted_str = redacted_str[:500] + "...<TRUNCATED>..." + redacted_str[-500:]
        return redacted_str
    return data

def log_lifecycle(event: str, mission_id: str, task_id: str = None, tool_id: str = None, **kwargs):
    payload = {
        "event": event,
        "mission_id": mission_id,
        **redact(kwargs)
    }
    if task_id:
        payload["task_id"] = task_id
    if tool_id:
        payload["tool_id"] = tool_id
        
    logger.info(f"LIFECYCLE: {json.dumps(payload)}")
