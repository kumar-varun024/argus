"""api_security: Payload generation."""
from __future__ import annotations

import copy
import re
import time
import urllib.parse
import uuid
from typing import List, Union

from argus.collectors.api_security.models import APIMutationStrategy, APIProbe, APIVulnerabilityType


class APISecurityPayloadGenerator:
    """
    Generates multi-vector API security probes covering 6 detection modes:
    - Parameter Tampering
    - Mass Assignment
    - Rate Limiting Bypass
    - BOLA / IDOR
    - Excessive Data Exposure
    - Method Tampering

    Applies 5 mutation/evasion strategies:
    - Content-Type Switching
    - Parameter Pollution
    - Header-Based Auth Bypass
    - Version Downgrade
    - Encoding Variations
    """

    def __init__(self) -> None:
        self._counter = 0

    def generate_canary(self, prefix: str = "ARGUS_API") -> str:
        """Generates a unique, traceable canary token for validation."""
        self._counter += 1
        return f"{prefix}_{int(time.time())}_{self._counter}_{uuid.uuid4().hex[:8]}"

    def generate_parameter_tampering_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Parameter Tampering:
        - Price tampering (0.01, -50.00, 0, extreme floats)
        - Quantity tampering (-1, 0, -99)
        - Discount tampering (100, 999)
        - Role / privilege parameter tampering (admin, superuser)
        """
        probes: List[APIProbe] = []
        canary = self.generate_canary("CANARY_PRICE")

        # 1. Price tampering in JSON body (POST / PUT / PATCH)
        probes.append(
            APIProbe(
                probe_id="param_tamper_price_negative",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json_data={"item_id": 101, "price": -50.00, "quantity": 1, "canary": canary},
                tested_parameter="price",
                original_value=50.00,
                tampered_value=-50.00,
                canary_token=canary,
            )
        )
        probes.append(
            APIProbe(
                probe_id="param_tamper_price_fractional",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json_data={"item_id": 101, "price": 0.01, "amount": 0.01, "quantity": 1},
                tested_parameter="price",
                original_value=100.00,
                tampered_value=0.01,
            )
        )

        # 2. Quantity tampering (negative/zero)
        probes.append(
            APIProbe(
                probe_id="param_tamper_qty_negative",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json_data={"product_id": 42, "quantity": -5, "price": 25.00},
                tested_parameter="quantity",
                original_value=1,
                tampered_value=-5,
            )
        )

        # 3. Discount / percentage tampering in query parameters (GET)
        probes.append(
            APIProbe(
                probe_id="param_tamper_discount_query",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                params={"discount": 100, "discount_percent": 100, "promo": "ALLFREE"},
                tested_parameter="discount",
                original_value=0,
                tampered_value=100,
            )
        )

        # 4. Role / privilege escalation tampering
        probes.append(
            APIProbe(
                probe_id="param_tamper_role_query",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                params={"role": "admin", "tier": "enterprise"},
                tested_parameter="role",
                original_value="user",
                tampered_value="admin",
            )
        )

        return probes

    def generate_mass_assignment_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Mass Assignment:
        Injects privileged and unauthorized attributes into request bodies
        (isAdmin, is_admin, role, balance, permissions, verified, tier).
        """
        probes: List[APIProbe] = []
        canary = self.generate_canary("CANARY_MASS_ASSIGN")

        privileged_payloads = [
            ("isAdmin", True, {"username": f"user_{uuid.uuid4().hex[:6]}", "email": "test@example.com", "isAdmin": True}),
            ("is_admin", True, {"username": f"user_{uuid.uuid4().hex[:6]}", "email": "test@example.com", "is_admin": True}),
            ("role", "admin", {"username": f"user_{uuid.uuid4().hex[:6]}", "email": "test@example.com", "role": "admin"}),
            ("role", "superuser", {"username": f"user_{uuid.uuid4().hex[:6]}", "email": "test@example.com", "role": "superuser"}),
            ("balance", 999999, {"account_id": "1001", "balance": 999999, "credit": 999999}),
            ("permissions", ["*"], {"user_id": 1, "permissions": ["*"], "canary": canary}),
            ("verified", True, {"email": "test@example.com", "verified": True, "email_verified": True}),
            ("tier", "enterprise", {"organization": "Corp", "tier": "enterprise", "plan": "unlimited"}),
        ]

        for param_name, param_val, body in privileged_payloads:
            probes.append(
                APIProbe(
                    probe_id=f"mass_assign_{param_name}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    json_data=body,
                    tested_parameter=param_name,
                    tampered_value=param_val,
                    canary_token=canary if "canary" in body else "",
                )
            )

        # Also probe PUT and PATCH methods for profile update mass assignment
        probes.append(
            APIProbe(
                probe_id="mass_assign_patch_role",
                target_url=endpoint_url,
                method="PATCH",
                vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json_data={"role": "administrator", "is_admin": True},
                tested_parameter="role",
                tampered_value="administrator",
            )
        )

        return probes

    def generate_rate_limiting_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Rate Limiting Bypass:
        - Burst sequence testing (15 requests)
        - Header rotation (X-Forwarded-For, Client-IP, X-Real-IP, X-Originating-IP)
        """
        probes: List[APIProbe] = []

        # 1. Direct burst probe without headers
        probes.append(
            APIProbe(
                probe_id="rate_limit_burst_standard",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.RATE_LIMITING_BYPASS,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Accept": "application/json"},
                burst_count=15,
                tested_parameter="rate_limiting",
            )
        )

        # 2. Burst with IP spoofing header rotation
        probes.append(
            APIProbe(
                probe_id="rate_limit_bypass_xff_rotation",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.RATE_LIMITING_BYPASS,
                strategy=APIMutationStrategy.HEADER_AUTH_BYPASS,
                headers={
                    "Accept": "application/json",
                    "X-Forwarded-For": "198.51.100.1",
                    "X-Real-IP": "198.51.100.1",
                    "Client-IP": "198.51.100.1",
                },
                burst_count=15,
                tested_parameter="X-Forwarded-For",
                metadata={"rotate_ip": True},
            )
        )

        return probes

    def generate_bola_idor_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Broken Object Level Authorization (BOLA / IDOR):
        - Numeric ID manipulation in path (/users/1 -> /users/2, /users/0)
        - Query parameter ID manipulation (?user_id=2, ?id=1)
        - Differential unauthenticated and secondary identity probes
        """
        probes: List[APIProbe] = []

        # 1. Path-based IDOR mutation if URL has an entity ID
        parsed = urllib.parse.urlparse(endpoint_url)
        path = parsed.path
        id_match = re.search(r"/(\d+)(?:/|$)", path)
        if id_match:
            orig_id = id_match.group(1)
            next_id = str(int(orig_id) + 1)
            tampered_path = re.sub(rf"/{orig_id}(/|$)", rf"/{next_id}\1", path)
            tampered_url = urllib.parse.urlunparse(parsed._replace(path=tampered_path))
            probes.append(
                APIProbe(
                    probe_id="bola_idor_path_increment",
                    target_url=tampered_url,
                    method="GET",
                    vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Accept": "application/json"},
                    tested_parameter="path_id",
                    original_value=orig_id,
                    tampered_value=next_id,
                )
            )
            # Try ID = 0 or 1 (admin / root object)
            tampered_path_root = re.sub(rf"/{orig_id}(/|$)", r"/1\1", path)
            tampered_url_root = urllib.parse.urlunparse(parsed._replace(path=tampered_path_root))
            probes.append(
                APIProbe(
                    probe_id="bola_idor_path_root_id",
                    target_url=tampered_url_root,
                    method="GET",
                    vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Accept": "application/json"},
                    tested_parameter="path_id",
                    original_value=orig_id,
                    tampered_value="1",
                )
            )
        else:
            # Endpoint path does not contain numeric ID, append resource subpaths
            for subpath in ("/1", "/2", "/users/1", "/users/2", "/orders/1001", "/accounts/1"):
                test_url = endpoint_url.rstrip("/") + subpath
                probes.append(
                    APIProbe(
                        probe_id=f"bola_idor_subpath_{subpath.strip('/').replace('/', '_')}",
                        target_url=test_url,
                        method="GET",
                        vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
                        strategy=APIMutationStrategy.STANDARD,
                        headers={"Accept": "application/json"},
                        tested_parameter="id",
                        tampered_value=subpath,
                    )
                )

        # 2. Query parameter IDOR probes
        for param_id in ("user_id", "id", "account_id", "order_id", "profile_id"):
            probes.append(
                APIProbe(
                    probe_id=f"bola_idor_param_{param_id}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Accept": "application/json"},
                    params={param_id: 2},
                    tested_parameter=param_id,
                    original_value=1,
                    tampered_value=2,
                )
            )

        return probes

    def generate_excessive_data_exposure_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Excessive Data Exposure:
        Inspects API responses for sensitive fields (tokens, passwords, PII, internal IDs, configs).
        """
        probes: List[APIProbe] = []

        # 1. Standard GET probe to audit response serialization schema
        probes.append(
            APIProbe(
                probe_id="excessive_data_get",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Accept": "application/json"},
                tested_parameter="response_body",
            )
        )

        # 2. Common profile/user/config endpoints
        for subpath in ("/profile", "/user", "/me", "/users", "/config", "/debug", "/status"):
            test_url = endpoint_url.rstrip("/") + subpath
            probes.append(
                APIProbe(
                    probe_id=f"excessive_data_subpath_{subpath.strip('/')}",
                    target_url=test_url,
                    method="GET",
                    vulnerability_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Accept": "application/json"},
                    tested_parameter="response_body",
                )
            )

        return probes

    def generate_method_tampering_probes(self, endpoint_url: str) -> List[APIProbe]:
        """
        Generates probes for Method Tampering:
        - Unexpected HTTP methods (PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE)
        - Method override headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method)
        """
        probes: List[APIProbe] = []

        # 1. Direct HTTP method mutations
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"):
            probes.append(
                APIProbe(
                    probe_id=f"method_tamper_direct_{method.lower()}",
                    target_url=endpoint_url,
                    method=method,
                    vulnerability_type=APIVulnerabilityType.METHOD_TAMPERING,
                    strategy=APIMutationStrategy.STANDARD,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    json_data={"action": "update", "test": True} if method in ("PUT", "PATCH") else None,
                    tested_parameter="http_method",
                    original_value="GET",
                    tampered_value=method,
                )
            )

        # 2. Method override headers over POST/GET
        for header_name, override_method in (
            ("X-HTTP-Method-Override", "PUT"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Method-Override", "PATCH"),
            ("X-HTTP-Method", "DELETE"),
        ):
            probes.append(
                APIProbe(
                    probe_id=f"method_tamper_override_{header_name.lower().replace('-', '_')}_{override_method.lower()}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=APIVulnerabilityType.METHOD_TAMPERING,
                    strategy=APIMutationStrategy.HEADER_AUTH_BYPASS,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        header_name: override_method,
                    },
                    json_data={"action": "override_test", "role": "admin"},
                    tested_parameter=header_name,
                    original_value="POST",
                    tampered_value=override_method,
                )
            )

        return probes

    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[APIProbe]:
        """Generates benign baseline probes to establish normal behavior and prevent false positives."""
        return [
            APIProbe(
                probe_id="benign_baseline_get",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Accept": "application/json"},
                is_benign=True,
                tested_parameter="baseline",
            ),
            APIProbe(
                probe_id="benign_baseline_post",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
                strategy=APIMutationStrategy.STANDARD,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json_data={"item_id": 101, "price": 50.00, "quantity": 1},
                is_benign=True,
                tested_parameter="baseline",
            ),
        ]

    def apply_mutation(self, probe: APIProbe, strategy: Union[APIMutationStrategy, str]) -> APIProbe:
        """
        Applies a mutation strategy to an existing API probe:
        1. CONTENT_TYPE_SWITCHING: Converts JSON to form-url, XML, or multipart
        2. PARAMETER_POLLUTION: Injects duplicate keys or array values
        3. HEADER_AUTH_BYPASS: Injects spoofed gateway and bypass headers
        4. VERSION_DOWNGRADE: Rewrites URL paths /v2/ -> /v1/ or injects version headers
        5. ENCODING_VARIATIONS: URL-encodes or Unicode-escapes keys/values
        """
        strat_enum = APIMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        mutated = copy.deepcopy(probe)
        mutated.strategy = strat_enum
        mutated.probe_id = f"{probe.probe_id}_{strat_enum.value}"

        if strat_enum == APIMutationStrategy.CONTENT_TYPE_SWITCHING:
            if mutated.json_data and isinstance(mutated.json_data, dict):
                # Switch JSON to form-urlencoded or XML
                if "application/json" in mutated.headers.get("Content-Type", ""):
                    mutated.headers["Content-Type"] = "application/x-www-form-urlencoded"
                    mutated.data = urllib.parse.urlencode(
                        {k: str(v) for k, v in mutated.json_data.items() if not isinstance(v, (dict, list))}
                    )
                    mutated.json_data = None

        elif strat_enum == APIMutationStrategy.PARAMETER_POLLUTION:
            # Add duplicate query parameters or array in JSON
            if mutated.params:
                # Duplicate param in query string
                for k, v in list(mutated.params.items()):
                    mutated.params[f"{k}_dup"] = v
            if mutated.json_data and isinstance(mutated.json_data, dict):
                # Wrap parameter in array
                new_json = {}
                for k, v in mutated.json_data.items():
                    if k == mutated.tested_parameter:
                        new_json[k] = [v, "admin" if isinstance(v, str) else v]
                    else:
                        new_json[k] = v
                mutated.json_data = new_json

        elif strat_enum == APIMutationStrategy.HEADER_AUTH_BYPASS:
            # Inject spoofed gateway IP and rewrite headers
            mutated.headers["X-Forwarded-For"] = "127.0.0.1"
            mutated.headers["X-Originating-IP"] = "127.0.0.1"
            mutated.headers["X-Remote-IP"] = "127.0.0.1"
            mutated.headers["X-Client-IP"] = "127.0.0.1"
            mutated.headers["X-Custom-IP-Authorization"] = "127.0.0.1"
            mutated.headers["X-Original-URL"] = urllib.parse.urlparse(mutated.target_url).path
            mutated.headers["X-Rewrite-URL"] = urllib.parse.urlparse(mutated.target_url).path

        elif strat_enum == APIMutationStrategy.VERSION_DOWNGRADE:
            # Downgrade URL /v2/ -> /v1/, /v3/ -> /v1/, or add version header
            parsed = urllib.parse.urlparse(mutated.target_url)
            path = parsed.path
            if "/v2/" in path:
                path = path.replace("/v2/", "/v1/")
            elif "/v3/" in path:
                path = path.replace("/v3/", "/v1/")
            elif "/latest/" in path:
                path = path.replace("/latest/", "/v1/")
            mutated.target_url = urllib.parse.urlunparse(parsed._replace(path=path))
            mutated.headers["X-API-Version"] = "1.0"
            mutated.headers["Accept"] = "application/vnd.api+json;version=1.0, application/json"

        elif strat_enum == APIMutationStrategy.ENCODING_VARIATIONS:
            # URL-encode or Unicode escape parameters in query or JSON
            if mutated.params:
                new_params = {}
                for k, v in mutated.params.items():
                    if isinstance(v, str):
                        # URL encode
                        new_params[urllib.parse.quote(k)] = urllib.parse.quote(v)
                    else:
                        new_params[k] = v
                mutated.params = new_params
            if mutated.json_data and isinstance(mutated.json_data, dict):
                # Unicode escape string values
                new_json = {}
                for k, v in mutated.json_data.items():
                    if isinstance(v, str):
                        escaped = "".join(f"\\u{ord(c):04x}" for c in v)
                        new_json[k] = escaped
                    else:
                        new_json[k] = v
                mutated.json_data = new_json

        return mutated

    def generate_all_probes(self, endpoint_url: str = "https://example.com/api/v1/resource") -> List[APIProbe]:
        """
        Compiles a comprehensive probe list across all 6 detection modes and 5 mutation strategies.
        """
        all_probes: List[APIProbe] = []

        # 0. Benign baselines
        all_probes.extend(self.generate_benign_baseline_probes(endpoint_url))

        # 1. Parameter Tampering probes
        pt_probes = self.generate_parameter_tampering_probes(endpoint_url)
        all_probes.extend(pt_probes)
        for p in pt_probes[:2]:
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.CONTENT_TYPE_SWITCHING))
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.PARAMETER_POLLUTION))

        # 2. Mass Assignment probes
        ma_probes = self.generate_mass_assignment_probes(endpoint_url)
        all_probes.extend(ma_probes)
        for p in ma_probes[:2]:
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.ENCODING_VARIATIONS))
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.CONTENT_TYPE_SWITCHING))

        # 3. Rate Limiting probes
        rl_probes = self.generate_rate_limiting_probes(endpoint_url)
        all_probes.extend(rl_probes)

        # 4. BOLA / IDOR probes
        bola_probes = self.generate_bola_idor_probes(endpoint_url)
        all_probes.extend(bola_probes)
        for p in bola_probes[:2]:
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.HEADER_AUTH_BYPASS))
            all_probes.append(self.apply_mutation(p, APIMutationStrategy.VERSION_DOWNGRADE))

        # 5. Excessive Data Exposure probes
        ede_probes = self.generate_excessive_data_exposure_probes(endpoint_url)
        all_probes.extend(ede_probes)

        # 6. Method Tampering probes
        mt_probes = self.generate_method_tampering_probes(endpoint_url)
        all_probes.extend(mt_probes)

        return all_probes
