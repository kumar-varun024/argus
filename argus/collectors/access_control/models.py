"""access_control: Data models, enums, and constants."""
from __future__ import annotations

import re


HORIZONTAL_PATH_PATTERNS = [
    re.compile(r"/(?:(?:api(?:/v\d+)?/)?|(?:[a-zA-Z0-9_\-]+/)+)?(?:users?|accounts?|profiles?|orders?|invoices?|customers?|documents?|items?|patients?|members?)/([^/?#]+)", re.IGNORECASE),
    re.compile(r"/(?:[a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+|\d+)(?:/|$|\?)", re.IGNORECASE),
]

QUERY_ID_PARAM_REGEX = re.compile(
    r"[?&](?:id|ids|user_id|userId|account_id|accountId|order_id|orderId|uid|doc_id|docId|customer_id)(?:\[\])?=([^&#]+)",
    re.IGNORECASE,
)

VERTICAL_ADMIN_PATTERNS = [
    re.compile(r"/(?:api(?:/v\d+)?)?/(?:admin|management|superuser|root|system|settings/admin|dashboard/admin)(?:/.*)?$", re.IGNORECASE),
    re.compile(r"/(?:admin|dashboard|management|console|superuser|root|system-settings)(?:/.*)?$", re.IGNORECASE),
]

DEFAULT_ADMIN_PROBE_PATHS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/api/admin/users",
    "/api/admin/system",
    "/management/users",
]
