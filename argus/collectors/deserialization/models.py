"""deserialization: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


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
