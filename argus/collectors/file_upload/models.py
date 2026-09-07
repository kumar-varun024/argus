"""file_upload: Data models, enums, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Union

from argus.collectors.toolkit.enums import Severity
from argus.http.client import HttpResponse


FileUploadSeverity = Severity

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
