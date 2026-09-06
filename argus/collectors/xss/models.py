"""XSS syntactic-context enum and module-level probe constants."""
from __future__ import annotations

from enum import Enum
from typing import List, Set


class XSSContext(Enum):
    """Enumeration of HTML syntactic contexts where user reflection can occur."""

    HTML_BODY = "html_body"
    ATTRIBUTE_DOUBLE = "attribute_double"
    ATTRIBUTE_SINGLE = "attribute_single"
    ATTRIBUTE_UNQUOTED = "attribute_unquoted"
    SCRIPT_STRING_DOUBLE = "script_string_double"
    SCRIPT_STRING_SINGLE = "script_string_single"
    SCRIPT_BLOCK = "script_block"
    URL_ATTRIBUTE = "url_attribute"
    COMMENT = "comment"
    UNKNOWN = "unknown"


# Standard probe routes and common parameters for XSS discovery
DEFAULT_XSS_PROBE_ROUTES: List[str] = [
    "/search",
    "/view",
    "/profile",
    "/feedback",
    "/contact",
    "/comments",
    "/login",
    "/post",
    "/messages",
    "/api/search",
    "/api/feedback",
    "/api/comments",
]

COMMON_XSS_PARAMS: Set[str] = {
    "q", "query", "search", "name", "user", "username", "msg", "message",
    "comment", "feedback", "text", "title", "content", "redirect", "url",
    "next", "return", "callback", "email", "author", "input", "data", "id",
}

