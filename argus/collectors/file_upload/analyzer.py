"""file_upload: Response analysis."""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from typing import Optional

from argus.collectors.file_upload.models import FileUploadProbe, FileUploadResponse, FileUploadResult, FileUploadSeverity, FileUploadTechnique


class FileUploadAnalyzer:
    """
    Evaluates file upload probe outcomes, performs rigorous path disclosure analysis,
    verifies canary execution, and applies strict false positive rejection.
    """

    # Server storage path patterns
    PATH_PATTERNS = [
        re.compile(r'(/var/www/(?:html/)?[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
        re.compile(r'(/usr/share/nginx/[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
        re.compile(r'(/home/[a-zA-Z0-9_\-]+/public_html/[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
        re.compile(r'(/app/(?:uploads/|static/)?[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
        re.compile(r'([A-Za-z]:\\inetpub\\wwwroot\\[a-zA-Z0-9_\-\\.]+)', re.IGNORECASE),
        re.compile(r'([A-Za-z]:\\Windows\\(?:Temp\\)?[a-zA-Z0-9_\-\\.]+)', re.IGNORECASE),
        re.compile(r'((?:https?://)?(?:[a-zA-Z0-9_\-]+\.)*s3(?:\.[a-zA-Z0-9_\-]+)?\.amazonaws\.com/[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
        re.compile(r'((?:https?://)?storage\.googleapis\.com/[a-zA-Z0-9_\-./]+)', re.IGNORECASE),
    ]

    # Error message information disclosure patterns
    ERROR_PATTERNS = [
        re.compile(r'(Fatal error:.*in\s+([/\\]\S+)\s+on line\s+\d+)', re.IGNORECASE),
        re.compile(r'(Exception in thread.*|Traceback \(most recent call last\):)', re.IGNORECASE),
        re.compile(r'(System\.Web\.HttpException.*|Microsoft VBScript runtime error)', re.IGNORECASE),
        re.compile(r'(org\.apache\.catalina\..*|java\.lang\.NullPointerException)', re.IGNORECASE),
        re.compile(r'(FileUploadException:.*|Invalid file extension:.*)', re.IGNORECASE),
    ]

    # Rejection keywords indicating proper file validation
    REJECTION_PATTERNS = [
        re.compile(r'file type (?:is )?not allowed', re.IGNORECASE),
        re.compile(r'invalid (?:file )?extension', re.IGNORECASE),
        re.compile(r'only (?:images|png|jpg|pdf) are allowed', re.IGNORECASE),
        re.compile(r'disallowed (?:mime|file) type', re.IGNORECASE),
        re.compile(r'executable files are forbidden', re.IGNORECASE),
        re.compile(r'upload rejected', re.IGNORECASE),
        re.compile(r'unsupported media type', re.IGNORECASE),
    ]

    def __init__(self):
        pass

    def detect_storage_path_disclosure(self, body: str) -> Optional[str]:
        """Detects physical file system or cloud storage paths leaked in the response."""
        if not body:
            return None
        for pat in self.PATH_PATTERNS:
            m = pat.search(body)
            if m:
                return m.group(1)
        return None

    def detect_error_disclosure(self, body: str) -> Optional[str]:
        """Detects stack traces, framework backtraces, and error disclosures."""
        if not body:
            return None
        for pat in self.ERROR_PATTERNS:
            m = pat.search(body)
            if m:
                return m.group(0)[:300]
        return None

    def is_false_positive(
        self,
        probe: FileUploadProbe,
        response: FileUploadResponse,
    ) -> bool:
        """
        Applies strict false positive suppression rules:
        1. Benign probes are never reported.
        2. Network timeout / zero status are rejected.
        3. 400/403/415/422 with validation error messages are rejected, UNLESS error disclosure / stack trace is present.
        4. Filename reflection in error messages without upload or info disclosure is rejected.
        5. Randomized UUID renaming without storage reachability or execution.
        """
        # 1. Benign probe
        if probe.is_benign:
            return True

        # 2. Network timeout / zero status
        if response.status_code == 0 or response.error:
            return True

        # Check for error or storage path disclosure before rejecting error status codes
        body = response.body or ""
        has_error_disclosure = bool(self.detect_error_disclosure(body))
        has_path_disclosure = bool(self.detect_storage_path_disclosure(body)) or bool(response.storage_path_disclosed)

        # 3. Explicit HTTP error status code with rejection pattern
        if response.status_code in (400, 401, 403, 404, 405, 415, 422, 500):
            if not has_error_disclosure and not has_path_disclosure:
                body_lower = body.lower()
                for pat in self.REJECTION_PATTERNS:
                    if pat.search(body_lower):
                        return True
                # If 403/415 without any storage/reflection, definitely rejected
                if response.status_code in (403, 415) and not response.is_reflected and not response.storage_path_disclosed:
                    return True

        # 4. Filename reflected only in an error message without acceptance and without info disclosure
        if response.status_code >= 400 and not response.web_shell_executed and not response.storage_url:
            if not has_error_disclosure and not has_path_disclosure:
                return True

        # 5. Randomized UUID renaming check: if server returned 200/201 but completely renamed
        # the file to a safe UUID with safe non-executable extension, and web shell check failed
        if response.status_code in (200, 201) and not response.web_shell_executed and not response.is_reflected:
            dest_ext = None
            if response.storage_url:
                parsed_u = urllib.parse.urlparse(response.storage_url)
                dest_ext = os.path.splitext(parsed_u.path)[1].lower()
            elif body:
                # Check for UUID pattern with extension in body
                uuid_match = re.search(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\.[a-zA-Z0-9]+)', body)
                if uuid_match:
                    dest_ext = uuid_match.group(1).lower()
                else:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            for k in ("url", "file_url", "path", "location"):
                                if k in data and isinstance(data[k], str):
                                    ext = os.path.splitext(urllib.parse.urlparse(data[k]).path)[1].lower()
                                    if ext:
                                        dest_ext = ext
                                        break
                    except Exception:
                        pass

            safe_exts = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".bin", ".dat"}
            if dest_ext and dest_ext in safe_exts:
                return True

        return False

    def evaluate_probe(
        self,
        probe: FileUploadProbe,
        response: FileUploadResponse,
        target_url: str,
    ) -> Optional[FileUploadResult]:
        """
        Evaluates a file upload probe and response to produce a calibrated FileUploadResult finding.
        """
        if self.is_false_positive(probe, response):
            return None

        # Check storage path disclosure
        path_disclosed = self.detect_storage_path_disclosure(response.body) or response.storage_path_disclosed
        error_disclosed = self.detect_error_disclosure(response.body)

        # Evaluate finding severity, CWE, CVSS, and description based on technique & outcome
        technique = probe.technique if isinstance(probe.technique, str) else probe.technique.value
        strategy = probe.strategy if isinstance(probe.strategy, str) else probe.strategy.value
        target_rt = probe.target_runtime if isinstance(probe.target_runtime, str) else probe.target_runtime.value

        # Default properties
        cwe_id = "CWE-434"
        cvss_score = 9.8
        severity = FileUploadSeverity.CRITICAL.value
        template_id = f"file-upload-{technique.replace('_', '-')}"
        confidence = 0.95

        # 1. Web shell execution verified (Canary executed on server)
        if response.web_shell_executed:
            title = f"Arbitrary File Upload & Web Shell Execution ({target_rt.upper()})"
            desc = (
                f"Successfully uploaded and executed an arbitrary {target_rt.upper()} script at {target_url}. "
                f"The safe canary token '{probe.canary_token}' was verified and executed at {response.storage_url}."
            )
            severity = FileUploadSeverity.CRITICAL.value
            cvss_score = 9.8
            cwe_id = "CWE-434"

        # If HTTP response indicates failure/error status (>= 400), evaluate as info disclosure (CWE-200)
        elif response.status_code >= 400:
            if path_disclosed or error_disclosed:
                title = f"File Upload Information Disclosure on {target_url}"
                desc = (
                    f"File upload interaction on {target_url} disclosed internal server storage paths or stack traces: "
                    f"{path_disclosed or error_disclosed}"
                )
                severity = FileUploadSeverity.MEDIUM.value
                cvss_score = 5.3
                cwe_id = "CWE-200"
                technique = FileUploadTechnique.STORAGE_PATH_DISCLOSURE.value
            else:
                return None

        # 2. Unrestricted executable file accepted (200/201 without validation)
        elif technique == FileUploadTechnique.UNRESTRICTED_UPLOAD.value:
            title = f"Unrestricted File Upload: {probe.filename} on {target_url}"
            desc = (
                f"The endpoint at {target_url} accepted an executable file ({probe.filename}) "
                f"with Content-Type '{probe.content_type}' without server-side extension or content validation."
            )
            severity = FileUploadSeverity.CRITICAL.value
            cvss_score = 9.8
            cwe_id = "CWE-434"

        # 3. MIME type bypass accepted
        elif technique == FileUploadTechnique.MIME_TYPE_BYPASS.value:
            title = f"MIME Type Bypass File Upload: {probe.filename}"
            desc = (
                f"The endpoint at {target_url} allowed uploading an executable file ({probe.filename}) "
                f"by spoofing the Content-Type header to '{probe.content_type}'."
            )
            severity = FileUploadSeverity.HIGH.value
            cvss_score = 8.1
            cwe_id = "CWE-436"

        # 4. Double extension bypass accepted
        elif technique == FileUploadTechnique.DOUBLE_EXTENSION_BYPASS.value:
            title = f"Double Extension Bypass: {probe.filename}"
            desc = (
                f"The endpoint at {target_url} accepted a dangerous double extension filename ({probe.filename}), "
                f"allowing bypass of extension blacklists."
            )
            severity = FileUploadSeverity.HIGH.value
            cvss_score = 8.1
            cwe_id = "CWE-436"

        # 5. Polyglot magic bytes accepted
        elif technique == FileUploadTechnique.POLYGLOT_MAGIC_BYTES.value:
            title = f"Polyglot Magic Bytes Upload: {probe.filename}"
            desc = (
                f"The endpoint at {target_url} accepted a polyglot file ({probe.filename}) combining valid image/document "
                f"magic byte headers with embedded executable code."
            )
            severity = FileUploadSeverity.HIGH.value
            cvss_score = 8.1
            cwe_id = "CWE-436"

        # 6. Path traversal in filename
        elif technique == FileUploadTechnique.PATH_TRAVERSAL_FILENAME.value:
            title = f"Path Traversal in Upload Filename: {probe.filename}"
            desc = (
                f"The endpoint at {target_url} accepted directory traversal sequences in the upload filename ({probe.filename}), "
                f"allowing arbitrary file placement across the file system."
            )
            severity = FileUploadSeverity.HIGH.value
            cvss_score = 8.1
            cwe_id = "CWE-22"

        # 7. Null byte injection
        elif technique == FileUploadTechnique.NULL_BYTE_INJECTION.value:
            title = f"Null Byte Injection in Upload Filename: {probe.filename}"
            desc = (
                f"The endpoint at {target_url} accepted a null-byte poisoned filename ({probe.filename}), "
                f"allowing truncation and bypass of extension validation."
            )
            severity = FileUploadSeverity.HIGH.value
            cvss_score = 8.1
            cwe_id = "CWE-434"

        # 8. Storage Path or Error Disclosure only
        elif path_disclosed or error_disclosed:
            title = f"File Upload Information Disclosure on {target_url}"
            desc = (
                f"File upload interaction on {target_url} disclosed internal server storage paths or stack traces: "
                f"{path_disclosed or error_disclosed}"
            )
            severity = FileUploadSeverity.MEDIUM.value
            cvss_score = 5.3
            cwe_id = "CWE-200"
            technique = FileUploadTechnique.STORAGE_PATH_DISCLOSURE.value

        else:
            title = f"File Upload Vulnerability: {probe.filename}"
            desc = f"File upload probe ({probe.filename}) succeeded on {target_url}."

        evidence_snippet = response.body[:250] if response.body else f"HTTP {response.status_code}"

        return FileUploadResult(
            template_id=template_id,
            technique=technique,
            vulnerability_type=probe.technique,
            mutation_strategy=strategy,
            filename=probe.filename,
            content_type=probe.content_type,
            severity=severity,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            description=desc,
            evidence_snippet=evidence_snippet,
            target_url=target_url,
            storage_path=path_disclosed,
            uploaded_file_url=response.storage_url,
            canary_token=probe.canary_token,
            target_runtime=target_rt,
            status_code=response.status_code,
            confidence=confidence,
            is_valid_finding=True,
        )
