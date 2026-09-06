"""SSTI enums, probe/result dataclasses, and error/RCE signature maps."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union

from argus.collectors.toolkit.enums import Severity

SSTISeverity = Severity


class SSTITechnique(str, Enum):
    """Enumeration of SSTI detection techniques."""
    ARITHMETIC_PROBE = "arithmetic_probe"
    DECISION_TREE_ROUTING = "decision_tree_routing"
    SANDBOX_ESCAPE_RCE = "sandbox_escape_rce"
    BLIND_TIME_BASED = "blind_time_based"
    ERROR_BASED_FINGERPRINT = "error_based_fingerprint"


# Backwards compatibility aliases
SSTITechnique.ARITHMETIC_POLYGLOT = SSTITechnique.ARITHMETIC_PROBE  # type: ignore[attr-defined]
SSTITechnique.ENGINE_DIFFERENTIAL = SSTITechnique.DECISION_TREE_ROUTING  # type: ignore[attr-defined]
SSTITechnique.SANDBOX_ESCAPE = SSTITechnique.SANDBOX_ESCAPE_RCE  # type: ignore[attr-defined]
SSTITechnique.TIME_BLIND_DELAY = SSTITechnique.BLIND_TIME_BASED  # type: ignore[attr-defined]


class SSTIEngineFamily(str, Enum):
    """Enumeration of supported template engines and families."""
    PYTHON_JINJA2 = "jinja2"
    PYTHON_MAKO = "mako"
    PYTHON_TORNADO = "tornado"
    PYTHON_DJANGO = "django"
    JAVA_FREEMARKER = "freemarker"
    JAVA_VELOCITY = "velocity"
    JAVA_THYMELEAF = "thymeleaf"
    JAVA_PEBBLE = "pebble"
    JAVA_SPEL = "spel"
    PHP_TWIG = "twig"
    PHP_SMARTY = "smarty"
    PHP_BLADE = "blade"
    RUBY_ERB = "erb"
    NODE_PUG = "pug"
    NODE_EJS = "ejs"
    NODE_HANDLEBARS = "handlebars"
    NODE_DUST = "dust"
    GO_TEMPLATE = "go"
    GENERIC = "generic"


# Engine aliases
SSTIEngineFamily.JINJA2 = SSTIEngineFamily.PYTHON_JINJA2  # type: ignore[attr-defined]
SSTIEngineFamily.MAKO = SSTIEngineFamily.PYTHON_MAKO  # type: ignore[attr-defined]
SSTIEngineFamily.TORNADO = SSTIEngineFamily.PYTHON_TORNADO  # type: ignore[attr-defined]
SSTIEngineFamily.DJANGO = SSTIEngineFamily.PYTHON_DJANGO  # type: ignore[attr-defined]
SSTIEngineFamily.FREEMARKER = SSTIEngineFamily.JAVA_FREEMARKER  # type: ignore[attr-defined]
SSTIEngineFamily.VELOCITY = SSTIEngineFamily.JAVA_VELOCITY  # type: ignore[attr-defined]
SSTIEngineFamily.THYMELEAF = SSTIEngineFamily.JAVA_THYMELEAF  # type: ignore[attr-defined]
SSTIEngineFamily.PEBBLE = SSTIEngineFamily.JAVA_PEBBLE  # type: ignore[attr-defined]
SSTIEngineFamily.SPEL = SSTIEngineFamily.JAVA_SPEL  # type: ignore[attr-defined]
SSTIEngineFamily.TWIG = SSTIEngineFamily.PHP_TWIG  # type: ignore[attr-defined]
SSTIEngineFamily.SMARTY = SSTIEngineFamily.PHP_SMARTY  # type: ignore[attr-defined]
SSTIEngineFamily.BLADE = SSTIEngineFamily.PHP_BLADE  # type: ignore[attr-defined]
SSTIEngineFamily.ERB = SSTIEngineFamily.RUBY_ERB  # type: ignore[attr-defined]
SSTIEngineFamily.PUG = SSTIEngineFamily.NODE_PUG  # type: ignore[attr-defined]
SSTIEngineFamily.EJS = SSTIEngineFamily.NODE_EJS  # type: ignore[attr-defined]
SSTIEngineFamily.HANDLEBARS = SSTIEngineFamily.NODE_HANDLEBARS  # type: ignore[attr-defined]
SSTIEngineFamily.DUST = SSTIEngineFamily.NODE_DUST  # type: ignore[attr-defined]


class SSTIMutationStrategy(str, Enum):
    """Enumeration of SSTI evasion, mutation, and bypass strategies."""
    STRING_CONCAT_ENCODING = "string_concat_encoding"
    ATTRIBUTE_INDIRECTION = "attribute_indirection"
    COMMENT_TAG_VARIATION = "comment_tag_variation"
    FILTER_WHITESPACE_BYPASS = "filter_whitespace_bypass"
    OBJECT_CLASSLOADER_NAVIGATION = "object_classloader_navigation"


# Mutation aliases
SSTIMutationStrategy.STRING_CONCATENATION_ENCODING = SSTIMutationStrategy.STRING_CONCAT_ENCODING  # type: ignore[attr-defined]
SSTIMutationStrategy.ATTRIBUTE_PROPERTY_INDIRECTION = SSTIMutationStrategy.ATTRIBUTE_INDIRECTION  # type: ignore[attr-defined]
SSTIMutationStrategy.COMMENT_DELIMITER_VARIATION = SSTIMutationStrategy.COMMENT_TAG_VARIATION  # type: ignore[attr-defined]


@dataclass
class SSTIProbe:
    """Represents a specific SSTI probe to inject."""
    url: str
    method: str = "GET"
    parameter: str = ""
    parameter_type: str = "query"  # "query", "body", "json", "path", "header"
    payload: str = ""
    technique: Union[SSTITechnique, str] = SSTITechnique.ARITHMETIC_PROBE
    engine: Union[SSTIEngineFamily, str] = SSTIEngineFamily.GENERIC
    mutation_strategy: Optional[Union[SSTIMutationStrategy, str]] = None
    expected_canary: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None
    json_body: Optional[Any] = None
    timeout: float = 10.0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SSTIProbeResponse:
    """Represents the response from executing an SSTI probe."""
    probe: SSTIProbe
    status_code: int = 200
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    success: bool = True
    raw_response: Optional[Any] = None


@dataclass
class SSTIResult:
    """Represents the structured finding from SSTI analysis."""
    technique: str
    engine: str
    payload: str
    parameter: str
    parameter_type: str
    target_url: str
    status_code: int = 200
    matched_signature: str = ""
    evidence_snippet: str = ""
    severity: str = SSTISeverity.HIGH
    confidence: float = 0.90
    template_id: str = "ssti"
    cwe_id: str = "CWE-1336"
    cvss_score: float = 8.2
    mutation_strategy: Optional[str] = None
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    expected_canary: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Signature Catalogs
# =============================================================================

# Error-based template engine stack trace / syntax error signatures
SSTI_ERROR_SIGNATURES: Dict[str, Tuple[str, re.Pattern]] = {
    "jinja2": (
        "jinja2",
        re.compile(
            r"(?:jinja2\.exceptions\.(?:TemplateSyntaxError|TemplateRuntimeError|UndefinedError|TemplateNotFound)|jinja2\.exceptions|\bTemplateSyntaxError: unexpected\b)",
            re.IGNORECASE,
        ),
    ),
    "twig": (
        "twig",
        re.compile(
            r"(?:Twig\\Error\\(?:SyntaxError|RuntimeError|LoaderError)|Twig_Error_Syntax|Unexpected token\s*\"|\bTwig\\|\bTwigException\b)",
            re.IGNORECASE,
        ),
    ),
    "smarty": (
        "smarty",
        re.compile(
            r"(?:SmartyCompilerException|Smarty error:|Syntax Error in template\s*\"|\$smarty\.template_object|unknown tag\s*\"|\bSmarty_Internal_Template\b)",
            re.IGNORECASE,
        ),
    ),
    "freemarker": (
        "freemarker",
        re.compile(
            r"(?:freemarker\.core\.(?:ParseException|InvalidReferenceException|NonStringException|UnexpectedTypeException)|freemarker\.template\.TemplateModelException|\bFreeMarker template error\b|\bFreeMarker error\b)",
            re.IGNORECASE,
        ),
    ),
    "velocity": (
        "velocity",
        re.compile(
            r"(?:org\.apache\.velocity\.exception\.(?:ParseErrorException|MethodInvocationException|ResourceNotFoundException)|VelocityException|\bVelocity rendering error\b)",
            re.IGNORECASE,
        ),
    ),
    "spel": (
        "spel",
        re.compile(
            r"(?:org\.springframework\.expression\.spel\.(?:SpelEvaluationException|SpelParseException)|EL100[0-9]E|EL10[0-9]{2}E|\bSpEL evaluation exception\b)",
            re.IGNORECASE,
        ),
    ),
    "mako": (
        "mako",
        re.compile(
            r"(?:mako\.exceptions\.(?:SyntaxException|CompileException|RuntimeException)|mako\.template\.Template|\bMako Error\b)",
            re.IGNORECASE,
        ),
    ),
    "django": (
        "django",
        re.compile(
            r"(?:django\.template\.exceptions\.(?:TemplateSyntaxError|TemplateDoesNotExist)|Invalid filter:|django\.template\.base\.VariableDoesNotExistException)",
            re.IGNORECASE,
        ),
    ),
    "thymeleaf": (
        "thymeleaf",
        re.compile(
            r"(?:org\.thymeleaf\.exceptions\.(?:TemplateProcessingException|TemplateEngineException|TemplateInputException)|Thymeleaf template error|\bThymeleaf\b.*Exception)",
            re.IGNORECASE,
        ),
    ),
    "pebble": (
        "pebble",
        re.compile(
            r"(?:com\.mitchellbosecke\.pebble\.error\.PebbleException|PebbleException)",
            re.IGNORECASE,
        ),
    ),
    "pug": (
        "pug",
        re.compile(
            r"(?:Pug:SyntaxError|Jade:SyntaxError|Cannot read property.*of undefined.*pug|pug:\d+)",
            re.IGNORECASE,
        ),
    ),
    "ejs": (
        "ejs",
        re.compile(
            r"(?:ejs:SyntaxError|Error: Could not find matching close tag|ejs:\d+|\bEJS compilation error\b)",
            re.IGNORECASE,
        ),
    ),
    "handlebars": (
        "handlebars",
        re.compile(
            r"(?:Error: Parse error on line|Handlebars: Error|\bHandlebars\.Compile\b)",
            re.IGNORECASE,
        ),
    ),
    "dust": (
        "dust",
        re.compile(
            r"(?:Dust: Syntax error|dust\.compileFn|Expected.*in dust template)",
            re.IGNORECASE,
        ),
    ),
    "erb": (
        "erb",
        re.compile(
            r"(?:syntax error, unexpected.*\b(?:ERB|erb)\b|ActionView::Template::Error|\b(?-i:ERB::Compiler::Error)\b)",
            re.IGNORECASE,
        ),
    ),
}

# RCE / Process Execution Signatures
SSTI_RCE_OUTPUT_SIGNATURES: Dict[str, re.Pattern] = {
    "posix_id": re.compile(
        r"(?:uid=\d+\([a-zA-Z0-9_\-.]+\)\s+gid=\d+\([a-zA-Z0-9_\-.]+\)|uid=\d+\s+gid=\d+)",
        re.IGNORECASE,
    ),
    "posix_uname": re.compile(
        r"\b(?:Linux|Darwin|FreeBSD|OpenBSD|NetBSD|SunOS)\s+[\w\.\-]+\s+\d+\.\d+[\w\.\-]*",
        re.IGNORECASE,
    ),
    "posix_passwd": re.compile(
        r"root:[x*]:0:0:.*?:(?:/root|/bin/(?:bash|sh|zsh|dash|nologin))",
        re.MULTILINE,
    ),
    "posix_whoami": re.compile(
        r"^(?:root|daemon|bin|nobody|www-data|nginx|apache|app|user|admin|ubuntu|ec2-user|runner)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "windows_whoami": re.compile(
        r"\b(?:nt authority\\(?:system|network service|local service)|[a-zA-Z0-9_\-\.]+\\[a-zA-Z0-9_\-\.]+)\b",
        re.IGNORECASE,
    ),
    "windows_dir": re.compile(
        r"(?:Volume in drive [A-Z] is|Volume Serial Number is [0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}|Directory of [A-Z]:\\)",
        re.IGNORECASE,
    ),
    "java_process": re.compile(
        r"(?:java\.lang\.ProcessBuilder|java\.lang\.UNIXProcess|java\.lang\.ProcessImpl|java\.lang\.Runtime)",
        re.IGNORECASE,
    ),
}


# =============================================================================
# Payload Generator
# =============================================================================

