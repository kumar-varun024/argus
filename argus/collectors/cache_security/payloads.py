"""cache_security: Payload generation."""
from __future__ import annotations

import copy
import json
import random
import string
import uuid
from typing import List, Optional

from argus.collectors.cache_security.models import CacheMutationStrategy, CacheProbe, CacheVulnerabilityType


class CacheSecurityPayloadGenerator:
    """
    Generates tailored payload vectors and applies mutation strategies
    for Web Cache Poisoning and Web Cache Deception auditing.
    """

    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "Forwarded",
        "X-Forwarded-Prefix",
        "X-Forwarded-Port",
        "X-HTTP-Host-Override",
        "Base-Url",
    ]

    UNKEYED_PARAMS = [
        "utm_source",
        "utm_content",
        "utm_campaign",
        "utm_medium",
        "fbclid",
        "gclid",
        "_ga",
        "callback",
        "cb",
        "jsonp",
    ]

    WCD_EXTENSIONS = [
        ".css",
        ".js",
        ".png",
        ".svg",
        ".json",
        ".ico",
        ".woff2",
        ".avif",
        ".webp",
    ]

    WCD_DELIMITERS = [
        "/nonexistent.css",
        ";test.js",
        "/test.css",
        "%0A.css",
        "%00.js",
        "%23.css",
        "..;/static/style.css",
        "%2e%2e%2fstyle.css",
    ]

    def __init__(self, canary_domain_suffix: str = "argus-security.local"):
        self.canary_domain_suffix = canary_domain_suffix

    def generate_canary(self, prefix: str = "canary") -> str:
        """Generates a randomized canary token."""
        rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}_{rand_str}"

    def build_unkeyed_header_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for unkeyed header injection."""
        token = canary or self.generate_canary("wcp_hdr")
        canary_host = f"{token}.{self.canary_domain_suffix}"
        probes: List[CacheProbe] = []

        # 1. X-Forwarded-Host
        probes.append(CacheProbe(
            probe_id=f"hdr_xfh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Host": canary_host},
            canary=token,
            vector_name="X-Forwarded-Host",
            payload_value=canary_host,
        ))

        # 2. X-Forwarded-Scheme
        probes.append(CacheProbe(
            probe_id=f"hdr_xfs_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Scheme": "http"},
            canary="http://",
            vector_name="X-Forwarded-Scheme",
            payload_value="http",
        ))

        # 3. X-Forwarded-Proto
        probes.append(CacheProbe(
            probe_id=f"hdr_xfp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Proto": "http"},
            canary="http://",
            vector_name="X-Forwarded-Proto",
            payload_value="http",
        ))

        # 4. X-Original-URL
        probes.append(CacheProbe(
            probe_id=f"hdr_xou_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Original-URL": f"/{token}_path"},
            canary=f"{token}_path",
            vector_name="X-Original-URL",
            payload_value=f"/{token}_path",
        ))

        # 5. X-Rewrite-URL
        probes.append(CacheProbe(
            probe_id=f"hdr_xru_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Rewrite-URL": f"/{token}_rewrite"},
            canary=f"{token}_rewrite",
            vector_name="X-Rewrite-URL",
            payload_value=f"/{token}_rewrite",
        ))

        # 6. X-Host
        probes.append(CacheProbe(
            probe_id=f"hdr_xh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Host": canary_host},
            canary=token,
            vector_name="X-Host",
            payload_value=canary_host,
        ))

        # 7. Forwarded (RFC 7239)
        probes.append(CacheProbe(
            probe_id=f"hdr_fwd_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"Forwarded": f"host={canary_host};proto=http"},
            canary=token,
            vector_name="Forwarded",
            payload_value=f"host={canary_host};proto=http",
        ))

        # 8. X-Forwarded-Prefix
        probes.append(CacheProbe(
            probe_id=f"hdr_xfprefix_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Prefix": f"//{canary_host}"},
            canary=token,
            vector_name="X-Forwarded-Prefix",
            payload_value=f"//{canary_host}",
        ))

        # 9. X-Forwarded-Port
        probes.append(CacheProbe(
            probe_id=f"hdr_xfport_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Port": "1337"},
            canary=":1337",
            vector_name="X-Forwarded-Port",
            payload_value="1337",
        ))

        # 10. X-HTTP-Host-Override
        probes.append(CacheProbe(
            probe_id=f"hdr_xhho_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-HTTP-Host-Override": canary_host},
            canary=token,
            vector_name="X-HTTP-Host-Override",
            payload_value=canary_host,
        ))

        # 11. Base-Url
        probes.append(CacheProbe(
            probe_id=f"hdr_baseurl_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"Base-Url": f"https://{canary_host}/"},
            canary=token,
            vector_name="Base-Url",
            payload_value=f"https://{canary_host}/",
        ))

        return probes

    def build_unkeyed_param_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for unkeyed query parameters and parameter cloaking."""
        token = canary or self.generate_canary("wcp_param")
        probes: List[CacheProbe] = []

        # 1. Standard unkeyed query parameters
        for param in ["utm_content", "utm_source", "fbclid", "gclid", "_ga"]:
            probes.append(CacheProbe(
                probe_id=f"param_{param}_{token}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
                strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
                params={param: token},
                canary=token,
                vector_name=param,
                payload_value=token,
            ))

        # 2. Unkeyed JSONP callbacks
        for jsonp_param in ["callback", "cb", "jsonp"]:
            probes.append(CacheProbe(
                probe_id=f"jsonp_{jsonp_param}_{token}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
                strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
                params={jsonp_param: f"alert_{token}"},
                canary=f"alert_{token}",
                vector_name=jsonp_param,
                payload_value=f"alert_{token}",
            ))

        # 3. Parameter Cloaking: Semicolon Delimiter (?k=1;u=2)
        probes.append(CacheProbe(
            probe_id=f"cloak_semi_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"k": f"1;utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_semicolon",
            payload_value=f"k=1;utm_content={token}",
        ))

        # 4. Parameter Cloaking: Double Question Mark (?k=1?u=2)
        probes.append(CacheProbe(
            probe_id=f"cloak_qmark_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"k": f"1?utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_qmark",
            payload_value=f"k=1?utm_content={token}",
        ))

        # 5. Parameter Cloaking: URL-encoded Delimiter (%26)
        probes.append(CacheProbe(
            probe_id=f"cloak_encamp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            params={"k": f"1%26utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_encoded_amp",
            payload_value=f"k=1%26utm_content={token}",
        ))

        # 6. Parameter Cloaking: Hash Delimiter (%23)
        probes.append(CacheProbe(
            probe_id=f"cloak_hash_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.PATH_DELIMITER_VARIATIONS,
            params={"utm_content": f"{token}%23k=1"},
            canary=token,
            vector_name="parameter_cloaking_hash",
            payload_value=f"utm_content={token}%23k=1",
        ))

        # 7. HTTP Parameter Pollution (HPP)
        probes.append(CacheProbe(
            probe_id=f"cloak_hpp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"p": "clean", "p_canary": token},
            canary=token,
            vector_name="http_parameter_pollution",
            payload_value=f"p=clean&p={token}",
            metadata={"hpp_param": "p", "hpp_canary": token},
        ))

        return probes

    def build_cache_deception_probes(self, base_url: str, is_auth: bool = True) -> List[CacheProbe]:
        """Builds probes for Web Cache Deception (path extensions and delimiter variations)."""
        probes: List[CacheProbe] = []

        # Standard static extension variations
        for ext in self.WCD_EXTENSIONS:
            suffix = f"/nonexistent{ext}"
            probes.append(CacheProbe(
                probe_id=f"wcd_ext_{ext.strip('.')}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
                strategy=CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS,
                path_suffix=suffix,
                vector_name=f"wcd_extension_{ext}",
                payload_value=suffix,
                is_auth_required=is_auth,
                metadata={"extension": ext},
            ))

        # Delimiter matrix probes
        for delim in self.WCD_DELIMITERS:
            clean_name = delim.replace("/", "_").replace(".", "_").replace(";", "_").replace("%", "_")
            probes.append(CacheProbe(
                probe_id=f"wcd_delim_{clean_name}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
                strategy=CacheMutationStrategy.PATH_DELIMITER_VARIATIONS,
                path_suffix=delim,
                vector_name=f"wcd_delimiter_{delim}",
                payload_value=delim,
                is_auth_required=is_auth,
                metadata={"delimiter": delim},
            ))

        return probes

    def build_normalization_flaw_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for cache key normalization flaws (FAT GET, method override, folded headers)."""
        token = canary or self.generate_canary("norm_canary")
        probes: List[CacheProbe] = []

        # 1. FAT GET: Form URL-encoded body
        probes.append(CacheProbe(
            probe_id=f"fat_get_form_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"utm_content={token}&x=1",
            canary=token,
            vector_name="FAT_GET_urlencoded",
            payload_value=f"utm_content={token}&x=1",
        ))

        # 2. FAT GET: JSON body
        probes.append(CacheProbe(
            probe_id=f"fat_get_json_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"canary": token, "utm_source": token}),
            canary=token,
            vector_name="FAT_GET_json",
            payload_value=json.dumps({"canary": token}),
        ))

        # 3. Method Override: X-HTTP-Method-Override
        probes.append(CacheProbe(
            probe_id=f"method_override_xhmo_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"X-HTTP-Method-Override": "POST", "Content-Type": "application/json"},
            body=json.dumps({"override_token": token}),
            canary=token,
            vector_name="X-HTTP-Method-Override",
            payload_value="POST",
        ))

        # 4. Method Override: X-Method-Override
        probes.append(CacheProbe(
            probe_id=f"method_override_xmo_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"X-Method-Override": "POST"},
            canary="POST",
            vector_name="X-Method-Override",
            payload_value="POST",
        ))

        # 5. Method Override: _method query parameter
        probes.append(CacheProbe(
            probe_id=f"method_override_param_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            params={"_method": "POST"},
            canary=token,
            vector_name="_method_param",
            payload_value="POST",
        ))

        # 6. Duplicate folded headers: X-Forwarded-Host
        canary_host = f"{token}.{self.canary_domain_suffix}"
        probes.append(CacheProbe(
            probe_id=f"dup_header_xfh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            headers={"X-Forwarded-Host": f"legitimate.local, {canary_host}"},
            canary=token,
            vector_name="duplicate_folded_X-Forwarded-Host",
            payload_value=f"legitimate.local, {canary_host}",
        ))

        return probes

    def apply_mutation(self, probe: CacheProbe, strategy: CacheMutationStrategy) -> CacheProbe:
        """Applies a specific mutation strategy to an existing probe."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = strategy

        if strategy == CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION:
            nonce = uuid.uuid4().hex[:10]
            mutated.params["__argus_cb"] = nonce
            mutated.headers["X-Argus-Buster"] = nonce

        elif strategy == CacheMutationStrategy.PATH_DELIMITER_VARIATIONS:
            if not mutated.path_suffix:
                mutated.path_suffix = ";argus=1.css"
            elif not mutated.path_suffix.startswith(";"):
                mutated.path_suffix = f";{mutated.path_suffix.lstrip('/')}"

        elif strategy == CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION:
            # Invert header name casing and path casing
            new_headers = {}
            for k, v in mutated.headers.items():
                new_headers[k.upper() if random.random() > 0.5 else k.lower()] = v
            mutated.headers = new_headers

        elif strategy == CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING:
            # Add tab indirection or comma chaining to headers
            new_headers = {}
            for k, v in mutated.headers.items():
                new_headers[k] = f"{v};version=1"
            mutated.headers = new_headers

        elif strategy == CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS:
            mutated.headers["Accept"] = "text/css,*/*;q=0.1"

        return mutated

    def generate_all_probes(self, base_url: str, canary: Optional[str] = None, is_auth: bool = False) -> List[CacheProbe]:
        """Generates all multi-vector probes for a target URL."""
        probes: List[CacheProbe] = []
        probes.extend(self.build_unkeyed_header_probes(base_url, canary))
        probes.extend(self.build_unkeyed_param_probes(base_url, canary))
        probes.extend(self.build_cache_deception_probes(base_url, is_auth=is_auth))
        probes.extend(self.build_normalization_flaw_probes(base_url, canary))
        return probes
