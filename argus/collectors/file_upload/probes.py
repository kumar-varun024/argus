"""file_upload: HTTP probe dispatch."""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Optional

from argus.http.client import AuthenticatedHttpClient
from argus.collectors.file_upload.models import FileUploadProbe, FileUploadResponse

logger = logging.getLogger(__name__)


class FileUploadProber:
    """
    Executes multipart/form-data HTTP upload requests and secondary web shell
    verification requests using AuthenticatedHttpClient.
    """

    def __init__(self, client: Optional[Any] = None, timeout: float = 10.0):
        self.client = client or AuthenticatedHttpClient(timeout=timeout)
        self.timeout = timeout

    def execute_upload(
        self,
        mission: Any,
        target_url: str,
        probe: FileUploadProbe,
        field_name: Optional[str] = None,
    ) -> FileUploadResponse:
        """
        Dispatches a multipart/form-data upload request containing the probe payload.
        """
        actual_field = field_name or probe.form_field_name or "file"
        content_bytes = probe.content.encode("utf-8") if isinstance(probe.content, str) else probe.content

        # Build files tuple for multipart request: (filename, file_content, content_type)
        files = {
            actual_field: (probe.filename, content_bytes, probe.content_type)
        }

        data = dict(probe.extra_fields) if probe.extra_fields else None

        start_time = time.time()
        try:
            if hasattr(self.client, "post"):
                import inspect
                sig = inspect.signature(self.client.post)
                if "mission" in sig.parameters:
                    raw_resp = self.client.post(
                        mission=mission,
                        url=target_url,
                        files=files,
                        data=data,
                        timeout=self.timeout,
                        action="file_upload_probe",
                    )
                else:
                    raw_resp = self.client.post(
                        target_url,
                        files=files,
                        data=data,
                        timeout=self.timeout,
                    )
            elif hasattr(self.client, "request"):
                raw_resp = self.client.request(
                    "POST",
                    target_url,
                    files=files,
                    data=data,
                    timeout=self.timeout,
                )
            else:
                raw_resp = None

            elapsed = time.time() - start_time

            if raw_resp is None:
                return FileUploadResponse(
                    status_code=0,
                    elapsed=elapsed,
                    error="Client returned None or unsupported method",
                )

            body_str = getattr(raw_resp, "body", "") or getattr(raw_resp, "raw_body", "") or ""
            headers_dict = dict(getattr(raw_resp, "headers", {}) or {})

            response = FileUploadResponse(
                status_code=getattr(raw_resp, "status_code", 0) or 0,
                headers=headers_dict,
                body=body_str,
                elapsed=elapsed,
                error=getattr(raw_resp, "error", None),
                raw_http_response=raw_resp,
            )

            # If upload succeeded (200/201/204), check for storage path / URL and verify web shell
            if response.status_code in (200, 201, 202, 204):
                self._extract_storage_information(response, target_url, probe.filename)
                if response.storage_url and probe.canary_token:
                    self._check_web_shell_reachability(mission, response, probe.canary_token)

            return response

        except Exception as e:
            elapsed = time.time() - start_time
            logger.warning(f"FileUploadProber: Error probing {target_url}: {e}")
            return FileUploadResponse(
                status_code=0,
                elapsed=elapsed,
                error=str(e),
            )

    def _extract_storage_information(
        self,
        response: FileUploadResponse,
        target_url: str,
        filename: str,
    ) -> None:
        """Extracts file location / storage URL / server path from response body & headers."""
        body = response.body
        headers = response.headers

        # 1. Location header
        loc = headers.get("location") or headers.get("Location")
        if loc:
            response.storage_url = urllib.parse.urljoin(target_url, loc)

        # 2. JSON response parsing
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                # Prioritize explicit URL keys first
                for key in ("file_url", "download_url", "url", "location", "link", "src"):
                    if key in data and isinstance(data[key], str) and data[key].strip():
                        val = data[key].strip()
                        if val.startswith("http://") or val.startswith("https://"):
                            response.storage_url = val
                        elif not val.startswith(("/var/", "/tmp/", "/home/", "/app/", "/opt/", "/srv/", "/usr/", "/etc/", "C:\\", "D:\\")):
                            response.storage_url = urllib.parse.urljoin(target_url, val)
                        break

                # Check filesystem path keys and record disclosed server paths
                for path_key in ("path", "filepath", "file_path", "storage_path", "server_path", "destination", "saved_to", "absolute_path"):
                    if path_key in data and isinstance(data[path_key], str) and data[path_key].strip():
                        path_val = data[path_key].strip()
                        if (
                            path_val.startswith(("/", "\\", "C:", "D:", "E:"))
                            or re.search(r'(/var/|/tmp/|/home/|/app/|/srv/|/opt/|/usr/|/etc/|[A-Za-z]:\\)', path_val)
                        ):
                            response.storage_path_disclosed = path_val
                        elif not response.storage_url:
                            # Relative path acting as storage URL fallback
                            response.storage_url = urllib.parse.urljoin(target_url, path_val)
        except Exception:
            pass

        # Also check regex for filesystem path disclosure in response body if not found in JSON
        if not response.storage_path_disclosed and body:
            fp_match = re.search(r'((?:/[a-zA-Z0-9_\-\.]+)+/(?:uploads?|tmp|var|www|public|storage|media)/[a-zA-Z0-9_\-\.]+)', body)
            if fp_match:
                response.storage_path_disclosed = fp_match.group(1)

        # 3. HTML / Regex extraction for URL containing filename or upload paths
        if not response.storage_url and body:
            clean_fn = os.path.basename(filename).split("%00")[0].split("\x00")[0]
            if clean_fn:
                # Look for href/src with upload paths
                pattern = rf'(?:href|src|url)=["\']([^"\']*{re.escape(clean_fn)}[^"\']*)["\']'
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    response.storage_url = urllib.parse.urljoin(target_url, m.group(1))

        # 4. Default predictable upload paths if not explicitly given
        if not response.storage_url and response.status_code in (200, 201):
            clean_fn = os.path.basename(filename).split("%00")[0].split("\x00")[0]
            if clean_fn and ("upload" in body.lower() or "success" in body.lower() or "created" in body.lower()):
                # Test predictable relative path e.g. /uploads/shell.php
                parsed = urllib.parse.urlparse(target_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                response.storage_url = f"{base}/uploads/{clean_fn}"

    def _check_web_shell_reachability(
        self,
        mission: Any,
        response: FileUploadResponse,
        canary_token: str,
    ) -> None:
        """Attempts a secondary GET request to verify whether uploaded file is accessible/executable."""
        if not response.storage_url:
            return

        try:
            if hasattr(self.client, "get"):
                import inspect
                sig = inspect.signature(self.client.get)
                if "mission" in sig.parameters:
                    get_resp = self.client.get(
                        mission=mission,
                        url=response.storage_url,
                        timeout=self.timeout,
                        action="file_upload_shell_verify",
                    )
                else:
                    get_resp = self.client.get(
                        response.storage_url,
                        timeout=self.timeout,
                    )
            elif hasattr(self.client, "request"):
                get_resp = self.client.request(
                    "GET",
                    response.storage_url,
                    timeout=self.timeout,
                )
            else:
                get_resp = None

            if get_resp and getattr(get_resp, "status_code", 0) in (200, 206):
                response.web_shell_status_code = getattr(get_resp, "status_code", 0)
                get_body = getattr(get_resp, "body", "") or getattr(get_resp, "raw_body", "") or ""
                response.web_shell_body = get_body

                # Check if canary token is reflected in GET response
                if canary_token and canary_token in get_body:
                    response.is_reflected = True
                    # Check if executed (canary present without raw <?php or <% source tags)
                    if "<?" not in get_body and "<%" not in get_body:
                        response.web_shell_executed = True
                    else:
                        response.web_shell_executed = False

        except Exception as e:
            logger.debug(f"FileUploadProber: Secondary shell reachability check failed: {e}")
