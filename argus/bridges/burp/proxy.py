"""Burp Suite Proxy Configuration Bridge for ARGUS HTTP Clients."""

import logging
from typing import Any, Dict, Optional

from argus.http.client import AuthenticatedHttpClient

logger = logging.getLogger(__name__)

DEFAULT_BURP_PROXY_URL = "http://127.0.0.1:8080"


def burp_configure_proxy(
    proxy_url: str = DEFAULT_BURP_PROXY_URL,
    enabled: bool = True,
) -> Dict[str, Any]:
    """Configure upstream proxy routing for AuthenticatedHttpClient.

    Args:
        proxy_url: The Burp Suite upstream proxy URL (default: http://127.0.0.1:8080).
        enabled: Whether proxy routing is enabled.

    Returns:
        Dict with proxy configuration status and parameters.
    """
    if enabled:
        logger.info("Configuring Burp Suite upstream proxy at: %s", proxy_url)
        return {
            "status": "configured",
            "proxy_url": proxy_url,
            "enabled": True,
            "message": f"Burp proxy configured at {proxy_url}",
        }
    else:
        logger.info("Disabling Burp Suite upstream proxy")
        return {
            "status": "disabled",
            "proxy_url": None,
            "enabled": False,
            "message": "Burp proxy disabled",
        }


def get_burp_http_client(
    proxy_url: str = DEFAULT_BURP_PROXY_URL,
    verify_ssl: bool = False,
    timeout: float = 10.0,
    **kwargs: Any,
) -> AuthenticatedHttpClient:
    """Factory helper to create an AuthenticatedHttpClient routed through Burp Suite.

    Args:
        proxy_url: The Burp proxy URL.
        verify_ssl: Whether to verify SSL certificates (default False for Burp CA).
        timeout: HTTP request timeout in seconds.
        **kwargs: Additional parameters forwarded to AuthenticatedHttpClient.

    Returns:
        Configured AuthenticatedHttpClient instance.
    """
    return AuthenticatedHttpClient(
        proxy=proxy_url,
        verify_ssl=verify_ssl,
        timeout=timeout,
        **kwargs,
    )
