"""Burp Suite REST API Scanner Client for active scanning and status polling."""

import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BURP_API_URL = "http://127.0.0.1:1337"


class BurpScannerClient:
    """Client for controlling Burp Suite Professional / Enterprise REST API."""

    def __init__(
        self,
        api_url: str = DEFAULT_BURP_API_URL,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def launch_scan(
        self,
        urls: List[str],
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        scan_configurations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Launch an active scan via Burp REST API (POST /v0.1/scan).

        Args:
            urls: Target URLs to scan.
            api_url: Optional override of Burp REST API URL.
            api_key: Optional override of API key.
            scan_configurations: Optional scan configuration list.

        Returns:
            Dict containing scan initiation status and scan_id.
        """
        target_api_url = (api_url or self.api_url).rstrip("/")
        effective_key = api_key if api_key is not None else self.api_key

        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
            headers["X-API-Key"] = effective_key

        payload = {
            "urls": urls,
            "scan_configurations": scan_configurations or [],
        }

        endpoint = f"{target_api_url}/v0.1/scan"
        logger.info("Launching Burp scan at %s for URLs: %s", endpoint, urls)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(endpoint, json=payload, headers=headers)

                if response.status_code in (200, 201, 202):
                    loc = response.headers.get("Location") or response.headers.get("location") or ""
                    scan_id = ""
                    if loc:
                        scan_id = loc.rstrip("/").split("/")[-1]

                    try:
                        resp_data = response.json()
                        if isinstance(resp_data, dict):
                            scan_id = str(resp_data.get("scan_id") or resp_data.get("id") or scan_id)
                    except Exception:
                        pass

                    if not scan_id:
                        scan_id = "1"

                    return {
                        "status": "initiated",
                        "scan_id": scan_id,
                        "urls": urls,
                        "location": loc,
                        "status_code": response.status_code,
                    }
                else:
                    return {
                        "status": "error",
                        "status_code": response.status_code,
                        "error": f"Burp API returned HTTP {response.status_code}: {response.text}",
                        "urls": urls,
                    }
        except httpx.RequestError as e:
            logger.warning("Burp API request error at %s: %s", endpoint, e)
            return {
                "status": "error",
                "error": f"Connection error connecting to Burp REST API at {target_api_url}: {str(e)}",
                "urls": urls,
            }
        except Exception as e:
            logger.error("Unexpected error launching Burp scan: %s", e)
            return {
                "status": "error",
                "error": f"Unexpected error: {str(e)}",
                "urls": urls,
            }

    def poll_scan(
        self,
        scan_id: str,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Poll status and issues of an active scan (GET /v0.1/scan/{scan_id}).

        Args:
            scan_id: The ID of the scan to poll.
            api_url: Optional override of Burp REST API URL.
            api_key: Optional override of API key.

        Returns:
            Dict containing scan status, progress, and issue list.
        """
        target_api_url = (api_url or self.api_url).rstrip("/")
        effective_key = api_key if api_key is not None else self.api_key

        headers: Dict[str, str] = {
            "Accept": "application/json",
        }
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
            headers["X-API-Key"] = effective_key

        endpoint = f"{target_api_url}/v0.1/scan/{scan_id}"
        logger.info("Polling Burp scan %s at %s", scan_id, endpoint)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(endpoint, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    scan_status = data.get("scan_status", "unknown")
                    progress = data.get("progress_percentage", 0)
                    issue_events = data.get("issue_events", [])
                    issues = [ev.get("issue", ev) for ev in issue_events if isinstance(ev, dict)]

                    return {
                        "status": "success",
                        "scan_id": scan_id,
                        "scan_status": scan_status,
                        "progress_percentage": progress,
                        "issue_count": len(issues),
                        "issues": issues,
                        "raw_data": data,
                    }
                else:
                    return {
                        "status": "error",
                        "scan_id": scan_id,
                        "status_code": response.status_code,
                        "error": f"Burp API returned HTTP {response.status_code}: {response.text}",
                    }
        except httpx.RequestError as e:
            logger.warning("Burp API request error polling scan %s: %s", scan_id, e)
            return {
                "status": "error",
                "scan_id": scan_id,
                "error": f"Connection error connecting to Burp REST API at {target_api_url}: {str(e)}",
            }
        except Exception as e:
            logger.error("Unexpected error polling Burp scan %s: %s", scan_id, e)
            return {
                "status": "error",
                "scan_id": scan_id,
                "error": f"Unexpected error: {str(e)}",
            }

    def cancel_scan(
        self,
        scan_id: str,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel an active scan (DELETE /v0.1/scan/{scan_id}).

        Args:
            scan_id: The ID of the scan to cancel.
            api_url: Optional override of Burp REST API URL.
            api_key: Optional override of API key.

        Returns:
            Dict containing cancellation status.
        """
        target_api_url = (api_url or self.api_url).rstrip("/")
        effective_key = api_key if api_key is not None else self.api_key

        headers: Dict[str, str] = {}
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
            headers["X-API-Key"] = effective_key

        endpoint = f"{target_api_url}/v0.1/scan/{scan_id}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.delete(endpoint, headers=headers)
                return {
                    "status": "cancelled" if response.status_code in (200, 204) else "error",
                    "scan_id": scan_id,
                    "status_code": response.status_code,
                }
        except Exception as e:
            return {
                "status": "error",
                "scan_id": scan_id,
                "error": str(e),
            }
