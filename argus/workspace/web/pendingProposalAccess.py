"""Access checks for the local, read-only pending-proposal feed."""

import hmac
import os

from fastapi import HTTPException, Request


PENDING_PROPOSAL_HEADERS = {"Cache-Control": "no-store"}
_DEFAULT_HOSTS = "127.0.0.1:8000,localhost:8000"


def _configured_operators() -> dict[str, str]:
    raw = os.getenv("ARGUS_OPERATOR_TOKENS", "")
    if not raw.strip():
        token = os.getenv("ARGUS_OPERATOR_TOKEN", "")
        operator_id = os.getenv("ARGUS_OPERATOR_ID", "local_user").strip()
        return {operator_id: token} if operator_id and token else {}

    operators: dict[str, str] = {}
    tokens: set[str] = set()
    for entry in raw.split(","):
        identity, _, token = entry.partition(":")
        identity, token = identity.strip(), token.strip()
        if not identity or not token or identity in operators or token in tokens:
            return {}
        operators[identity] = token
        tokens.add(token)
    return operators


def require_pending_proposal_operator(request: Request) -> str:
    allowed_hosts = {host.strip().lower() for host in os.getenv("ARGUS_ALLOWED_HOSTS", _DEFAULT_HOSTS).split(",")
                     if host.strip()}
    hosts = request.headers.getlist("host")
    if len(hosts) != 1 or hosts[0].lower() not in allowed_hosts:
        raise HTTPException(403, "Host header not allowed.", headers=PENDING_PROPOSAL_HEADERS)

    credentials = request.headers.getlist("authorization")
    if len(credentials) == 1:
        scheme, _, bearer = credentials[0].partition(" ")
        if scheme.lower() == "bearer" and bearer:
            for identity, expected in _configured_operators().items():
                if hmac.compare_digest(bearer.encode(), expected.encode()):
                    return identity
    raise HTTPException(401, "Valid operator bearer credential required.", headers=PENDING_PROPOSAL_HEADERS)
