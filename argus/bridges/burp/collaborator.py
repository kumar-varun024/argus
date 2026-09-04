"""Burp Collaborator / OAST Client for Out-Of-Band Application Security Testing."""

import logging
import secrets
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_COLLABORATOR_DOMAIN = "oastify.com"


class BurpCollaboratorClient:
    """Client for generating Burp Collaborator payloads and polling OAST interactions."""

    def __init__(
        self,
        server_domain: str = DEFAULT_COLLABORATOR_DOMAIN,
        secret_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self.server_domain = server_domain
        self.secret_key = secret_key
        self.api_url = api_url
        self.timeout = timeout

    def generate_payload(
        self,
        server_domain: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a unique Burp Collaborator / OAST payload domain.

        Args:
            server_domain: Collaborator server domain (default: oastify.com).
            secret_key: Optional secret polling key.

        Returns:
            Dict containing payload_domain, secret_key, token, and server_domain.
        """
        domain = (server_domain or self.server_domain).strip(".")
        token = secrets.token_hex(15)
        key = secret_key or self.secret_key or secrets.token_urlsafe(24)
        payload_domain = f"{token}.{domain}"

        logger.info("Generated Collaborator payload domain: %s", payload_domain)
        return {
            "status": "generated",
            "payload_domain": payload_domain,
            "token": token,
            "secret_key": key,
            "server_domain": domain,
        }

    def poll_interactions(
        self,
        payload_domain: str,
        api_url: Optional[str] = None,
        secret_key: Optional[str] = None,
        server_domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Poll interaction events (DNS, HTTP, SMTP) for a Collaborator payload domain.

        Args:
            payload_domain: The payload domain to check interactions for.
            api_url: Optional override of Burp REST API or Collaborator polling endpoint.
            secret_key: Secret polling key associated with the payload.
            server_domain: Collaborator server domain.

        Returns:
            Dict containing interactions list and count.
        """
        domain = server_domain or self.server_domain
        key = secret_key or self.secret_key
        target_api_url = api_url or self.api_url

        interactions: List[Dict[str, Any]] = []

        if target_api_url:
            endpoint = f"{target_api_url.rstrip('/')}/v0.1/collaborator/interactions"
            headers: Dict[str, str] = {"Accept": "application/json"}
            if key:
                headers["Authorization"] = f"Bearer {key}"
                headers["X-API-Key"] = key
            params = {"payload_domain": payload_domain}

            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(endpoint, headers=headers, params=params)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            interactions = data
                        elif isinstance(data, dict):
                            interactions = data.get("interactions") or data.get("events") or []
                        return {
                            "status": "success",
                            "payload_domain": payload_domain,
                            "count": len(interactions),
                            "interactions": interactions,
                        }
                    else:
                        return {
                            "status": "error",
                            "payload_domain": payload_domain,
                            "status_code": resp.status_code,
                            "error": f"API returned status {resp.status_code}: {resp.text}",
                            "interactions": [],
                            "count": 0,
                        }
            except httpx.RequestError as e:
                logger.warning("Collaborator poll request error for %s: %s", payload_domain, e)
                return {
                    "status": "error",
                    "payload_domain": payload_domain,
                    "error": f"Connection error: {str(e)}",
                    "interactions": [],
                    "count": 0,
                }
            except Exception as e:
                return {
                    "status": "error",
                    "payload_domain": payload_domain,
                    "error": f"Unexpected error: {str(e)}",
                    "interactions": [],
                    "count": 0,
                }

        if key and domain:
            collab_url = f"https://{domain}/burpresults"
            params = {"key": key}
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(collab_url, params=params)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, list):
                                interactions = data
                            elif isinstance(data, dict):
                                interactions = data.get("responses", [])
                        except Exception:
                            interactions = []
                        return {
                            "status": "success",
                            "payload_domain": payload_domain,
                            "count": len(interactions),
                            "interactions": interactions,
                        }
            except Exception as e:
                logger.debug("Direct collaborator poll error (%s): %s", collab_url, e)

        return {
            "status": "success",
            "payload_domain": payload_domain,
            "count": len(interactions),
            "interactions": interactions,
        }
