"""Access Control & IDOR Collector.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.access_control.models import (
    DEFAULT_ADMIN_PROBE_PATHS,
    HORIZONTAL_PATH_PATTERNS,
    QUERY_ID_PARAM_REGEX,
    VERTICAL_ADMIN_PATTERNS,
)
from argus.collectors.access_control.collector import (
    AccessControlCollector,
)
__all__ = [
    "AccessControlCollector",
    "DEFAULT_ADMIN_PROBE_PATHS",
    "HORIZONTAL_PATH_PATTERNS",
    "QUERY_ID_PARAM_REGEX",
    "VERTICAL_ADMIN_PATTERNS",
]
