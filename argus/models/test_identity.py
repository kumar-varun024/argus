from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import base64
from typing import Dict, Any, List, Optional
import uuid
import copy


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthType(str, Enum):
    BEARER = "BEARER"
    BASIC = "BASIC"
    API_KEY = "API_KEY"
    COOKIE = "COOKIE"
    OAUTH2 = "OAUTH2"
    CUSTOM = "CUSTOM"
    NONE = "NONE"


@dataclass
class TestIdentity:
    """Represents an authentication identity/role used for security testing."""
    __test__ = False

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    role: str = "user"
    roles: List[str] = field(default_factory=list)
    auth_type: AuthType = AuthType.NONE
    credentials: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    is_active: bool = True
    login_url: Optional[str] = None
    login_payload: Optional[Dict[str, Any]] = None
    login_type: str = "json"
    token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def __post_init__(self):
        if isinstance(self.auth_type, str):
            try:
                self.auth_type = AuthType(self.auth_type.upper())
            except ValueError:
                self.auth_type = AuthType.CUSTOM
        if not self.roles and self.role:
            self.roles = [self.role]

    def get_auth_headers(self) -> Dict[str, str]:
        """Constructs headers needed to authenticate requests for this identity."""
        res_headers = dict(self.headers)

        if self.auth_type == AuthType.BEARER:
            token = self.token or self.credentials.get("token") or self.credentials.get("bearer")
            if token and "Authorization" not in res_headers and "authorization" not in res_headers:
                res_headers["Authorization"] = f"Bearer {token}"
        elif self.auth_type == AuthType.BASIC:
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            if (username or password) and "Authorization" not in res_headers and "authorization" not in res_headers:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
                res_headers["Authorization"] = f"Basic {encoded}"
        elif self.auth_type == AuthType.API_KEY:
            key_name = self.credentials.get("key_header") or self.metadata.get("key_header") or "X-API-Key"
            key_val = self.credentials.get("api_key") or self.credentials.get("key") or self.token
            if key_val and key_name not in res_headers:
                res_headers[key_name] = str(key_val)
        elif self.auth_type == AuthType.OAUTH2:
            token = self.token or self.credentials.get("access_token") or self.credentials.get("token")
            if token and "Authorization" not in res_headers and "authorization" not in res_headers:
                res_headers["Authorization"] = f"Bearer {token}"

        return res_headers

    def get_cookies(self) -> Dict[str, str]:
        """Returns the active session cookies for this identity."""
        return dict(self.cookies)

    def update_session(
        self,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        token: Optional[str] = None,
    ) -> None:
        """Updates cookies, headers, and token, refreshing updated_at timestamp."""
        if cookies:
            self.cookies.update(cookies)
        if headers:
            self.headers.update(headers)
        if token is not None:
            self.token = token
            if self.auth_type in (AuthType.BEARER, AuthType.OAUTH2):
                self.headers["Authorization"] = f"Bearer {token}"
        self.updated_at = _utc_now()

    def clone(self, new_id: Optional[str] = None, **overrides) -> TestIdentity:
        """Creates a deep copy of this TestIdentity with optional overrides."""
        data = copy.deepcopy(self.to_dict())
        data["id"] = new_id or str(uuid.uuid4())
        data.update(overrides)
        return TestIdentity.from_dict(data)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes identity into a dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "roles": list(self.roles),
            "auth_type": self.auth_type.value if isinstance(self.auth_type, AuthType) else str(self.auth_type),
            "credentials": dict(self.credentials),
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "is_active": self.is_active,
            "login_url": self.login_url,
            "login_payload": dict(self.login_payload) if self.login_payload is not None else None,
            "login_type": self.login_type,
            "token": self.token,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TestIdentity:
        """Deserializes identity from a dictionary."""
        d = dict(data)
        if "auth_type" in d and isinstance(d["auth_type"], str):
            try:
                d["auth_type"] = AuthType(d["auth_type"].upper())
            except ValueError:
                d["auth_type"] = AuthType.CUSTOM
        return cls(**d)
