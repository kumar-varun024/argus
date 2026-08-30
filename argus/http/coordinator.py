"""
Multi-Identity Session Coordinator.

Manages multiple isolated AuthenticatedHttpClient instances for differential
security testing across user roles, unauthenticated sessions, and authorization boundaries.
"""
from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.models.test_identity import TestIdentity

logger = logging.getLogger(__name__)


@dataclass
class MultiIdentityComparison:
    """Represents the structured comparison of responses from two distinct identities."""
    primary_identity_id: str
    secondary_identity_id: Optional[str]
    primary_response: HttpResponse
    secondary_response: HttpResponse
    status_match: bool
    body_match: bool
    length_difference: int
    body_similarity: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class MultiIdentitySessionCoordinator:
    """
    Coordinates simultaneous, isolated HTTP sessions across multiple TestIdentities.
    Guarantees independent cookie jars, distinct auth headers, and session boundaries.
    """

    def __init__(
        self,
        clients: Optional[Dict[str, AuthenticatedHttpClient]] = None,
        default_client: Optional[AuthenticatedHttpClient] = None,
        verify_ssl: bool = False,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        max_retries: int = 2,
        backoff_factor: float = 0.3,
        follow_redirects: bool = True,
    ):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.proxy = proxy
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.follow_redirects = follow_redirects

        self._clients: Dict[str, AuthenticatedHttpClient] = dict(clients or {})
        self._unauth_client: Optional[AuthenticatedHttpClient] = default_client

    def __enter__(self) -> "MultiIdentitySessionCoordinator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()

    def close_all(self) -> None:
        """Closes all managed HTTP clients and releases connections."""
        for client in self._clients.values():
            try:
                client.close()
            except Exception as e:
                logger.debug(f"Error closing client: {e}")
        self._clients.clear()

        if self._unauth_client:
            try:
                self._unauth_client.close()
            except Exception as e:
                logger.debug(f"Error closing unauth client: {e}")
            self._unauth_client = None

    def get_client_for_identity(self, identity: TestIdentity) -> AuthenticatedHttpClient:
        """
        Retrieves or initializes a dedicated, isolated AuthenticatedHttpClient
        for the given TestIdentity.
        """
        ident_id = identity.id
        if ident_id not in self._clients:
            client = AuthenticatedHttpClient(
                identity=identity,
                proxy=self.proxy,
                verify_ssl=self.verify_ssl,
                timeout=self.timeout,
                max_retries=self.max_retries,
                backoff_factor=self.backoff_factor,
                follow_redirects=self.follow_redirects,
                headers=identity.get_auth_headers(),
                cookies=identity.get_cookies(),
            )
            self._clients[ident_id] = client
        return self._clients[ident_id]

    def get_unauthenticated_client(self) -> AuthenticatedHttpClient:
        """Retrieves or initializes a dedicated client without credentials/cookies."""
        if self._unauth_client is None:
            self._unauth_client = AuthenticatedHttpClient(
                identity=None,
                proxy=self.proxy,
                verify_ssl=self.verify_ssl,
                timeout=self.timeout,
                max_retries=self.max_retries,
                backoff_factor=self.backoff_factor,
                follow_redirects=self.follow_redirects,
            )
        return self._unauth_client

    def register_identity(self, identity: TestIdentity) -> AuthenticatedHttpClient:
        """Explicitly registers and initializes a client for an identity."""
        return self.get_client_for_identity(identity)

    def execute_as(
        self,
        identity: Optional[TestIdentity],
        mission: Any,
        method: str,
        url: str,
        **kwargs,
    ) -> HttpResponse:
        """
        Executes an HTTP request using the specified identity's isolated session.
        If identity is None, executes using the unauthenticated client.
        """
        if identity is None:
            client = self.get_unauthenticated_client()
            return client.request(mission=mission, method=method, url=url, identity=None, **kwargs)

        client = self.get_client_for_identity(identity)
        return client.request(mission=mission, method=method, url=url, identity=identity, **kwargs)

    def execute_across_identities(
        self,
        mission: Any,
        method: str,
        url: str,
        identities: Optional[List[TestIdentity]] = None,
        **kwargs,
    ) -> Dict[str, HttpResponse]:
        """
        Dispatches the identical HTTP request across all specified identities
        (or all identities in mission.test_identities).
        """
        idents = identities
        if idents is None:
            idents = getattr(mission, "test_identities", []) or []

        if not idents:
            # Fallback to unauthenticated baseline request
            resp = self.execute_as(None, mission, method, url, **kwargs)
            return {"unauthenticated": resp}

        results: Dict[str, HttpResponse] = {}
        for ident in idents:
            results[ident.id] = self.execute_as(ident, mission, method, url, **kwargs)
        return results

    def execute_comparison(
        self,
        mission: Any,
        method: str,
        url: str,
        primary_identity: TestIdentity,
        secondary_identity: Optional[TestIdentity] = None,
        **kwargs,
    ) -> MultiIdentityComparison:
        """
        Executes a differential request between a primary identity and secondary (or unauth) identity,
        computing status and body similarity metrics.
        """
        primary_resp = self.execute_as(primary_identity, mission, method, url, **kwargs)
        secondary_resp = self.execute_as(secondary_identity, mission, method, url, **kwargs)

        status_match = (primary_resp.status_code == secondary_resp.status_code)

        raw_p = primary_resp.raw_body if primary_resp.raw_body is not None else (primary_resp.body or "")
        raw_s = secondary_resp.raw_body if secondary_resp.raw_body is not None else (secondary_resp.body or "")

        body_match = (raw_p == raw_s)
        length_diff = abs(len(raw_p) - len(raw_s))

        # Compute similarity ratio
        if raw_p == raw_s:
            similarity = 1.0
        elif not raw_p or not raw_s:
            similarity = 0.0
        else:
            # Limit difflib calculation size to prevent performance bottlenecks on large payloads
            sample_p = raw_p[:5000]
            sample_s = raw_s[:5000]
            similarity = difflib.SequenceMatcher(None, sample_p, sample_s).ratio()

        secondary_id = secondary_identity.id if secondary_identity else "unauthenticated"

        return MultiIdentityComparison(
            primary_identity_id=primary_identity.id,
            secondary_identity_id=secondary_id,
            primary_response=primary_resp,
            secondary_response=secondary_resp,
            status_match=status_match,
            body_match=body_match,
            length_difference=length_diff,
            body_similarity=similarity,
            metadata={
                "method": method,
                "url": url,
                "primary_role": primary_identity.role,
                "secondary_role": secondary_identity.role if secondary_identity else "unauthenticated",
            },
        )

    def authenticate_all(self, mission: Any) -> Dict[str, HttpResponse]:
        """
        Executes automated authentication / login flows for all configured identities in the mission.
        """
        results: Dict[str, HttpResponse] = {}
        identities: List[TestIdentity] = getattr(mission, "test_identities", []) or []

        for ident in identities:
            if ident.login_url or ident.credentials:
                client = self.get_client_for_identity(ident)
                resp = client.login(mission, identity=ident)
                results[ident.id] = resp

        return results
