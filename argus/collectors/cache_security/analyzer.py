"""cache_security: Response analysis."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from argus.collectors.cache_security.models import CacheEngineFamily, CacheProbe, CacheProbeResponse, CacheSecurityResult, CacheSecuritySeverity, CacheStatus, CacheVulnerabilityType, SENSITIVE_PII_PATTERNS


class CacheSecurityAnalyzer:
    """
    Evaluates HTTP responses, parses cache lifecycles, fingerprints CDN engines,
    and applies strict false positive suppression rules.
    """

    @staticmethod
    def analyze_cache_lifecycle(headers: Dict[str, str]) -> Tuple[CacheStatus, CacheEngineFamily, Optional[int]]:
        """
        Parses response headers to determine CacheStatus, CacheEngineFamily, and Age integer.
        """
        h = {k.lower(): str(v) for k, v in headers.items()}

        # 1. Age header parsing
        age_val: Optional[int] = None
        if "age" in h:
            try:
                age_val = int(h["age"].strip())
            except (ValueError, TypeError):
                age_val = None

        # 2. CDN & Engine Fingerprinting
        engine = CacheEngineFamily.GENERIC
        server = h.get("server", "").lower()
        via = h.get("via", "").lower()

        if "cf-cache-status" in h or "cf-ray" in h or "cloudflare" in server:
            engine = CacheEngineFamily.CLOUDFLARE
        elif "x-amz-cf-id" in h or "x-amz-cf-pop" in h or "cloudfront" in via or "cloudfront" in h.get("x-cache", "").lower():
            engine = CacheEngineFamily.CLOUDFRONT
        elif "x-akamai-request-id" in h or "x-check-cacheable" in h or "akamaighost" in server:
            engine = CacheEngineFamily.AKAMAI
        elif "x-served-by" in h or "x-timer" in h or "fastly" in via:
            engine = CacheEngineFamily.FASTLY
        elif "x-varnish" in h or "varnish" in via or "varnish" in server:
            engine = CacheEngineFamily.VARNISH
        elif "nginx" in server or "x-cache-status" in h:
            engine = CacheEngineFamily.NGINX
        elif "ats" in server or "apachetrafficserver" in via or "ats" in h.get("x-cache", "").lower():
            engine = CacheEngineFamily.APACHE_TRAFFIC_SERVER

        # 3. Cache Status Evaluation
        status = CacheStatus.UNKNOWN

        # Cloudflare CF-Cache-Status
        if "cf-cache-status" in h:
            cf_stat = h["cf-cache-status"].strip().upper()
            if cf_stat in ("HIT", "STALE", "REVALIDATED", "UPDATING"):
                status = CacheStatus.HIT
            elif cf_stat in ("MISS", "EXPIRED"):
                status = CacheStatus.MISS
            elif cf_stat in ("BYPASS", "DYNAMIC"):
                status = CacheStatus.BYPASS
            else:
                status = CacheStatus.UNKNOWN

        # X-Cache (CloudFront, Squid, ATS, Custom Nginx)
        elif "x-cache" in h:
            xc = h["x-cache"].strip().upper()
            if "HIT" in xc or "TCP_HIT" in xc or "TCP_REFRESH_HIT" in xc:
                status = CacheStatus.HIT
            elif "MISS" in xc or "TCP_MISS" in xc:
                status = CacheStatus.MISS
            elif "BYPASS" in xc:
                status = CacheStatus.BYPASS

        # X-Cache-Status (Nginx)
        elif "x-cache-status" in h:
            xcs = h["x-cache-status"].strip().upper()
            if xcs in ("HIT", "REVALIDATED", "UPDATING"):
                status = CacheStatus.HIT
            elif xcs in ("MISS", "EXPIRED"):
                status = CacheStatus.MISS
            elif xcs in ("BYPASS",):
                status = CacheStatus.BYPASS

        # X-Varnish (Varnish returns two IDs on hit, e.g. "12345 67890")
        elif "x-varnish" in h:
            parts = h["x-varnish"].strip().split()
            if len(parts) >= 2:
                status = CacheStatus.HIT
            else:
                status = CacheStatus.MISS

        # Monotonic Age progression fallback
        if status == CacheStatus.UNKNOWN:
            if age_val is not None and age_val > 0:
                status = CacheStatus.HIT
            elif "cache-control" in h:
                cc = h["cache-control"].lower()
                if "no-store" in cc or "private" in cc:
                    status = CacheStatus.BYPASS
                elif "public" in cc or "max-age" in cc or "s-maxage" in cc:
                    status = CacheStatus.MISS

        return status, engine, age_val

    @staticmethod
    def detect_pii(content: str) -> Tuple[bool, List[str]]:
        """Scans content for sensitive tokens and user credentials."""
        if not content:
            return False, []
        matches: List[str] = []
        for label, pattern in SENSITIVE_PII_PATTERNS:
            found = pattern.findall(content)
            if found:
                matches.append(f"{label}:{len(found)}")
        return len(matches) > 0, matches

    @classmethod
    def evaluate_unkeyed_header_poisoning(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Unkeyed Header Poisoning."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        # False Positive Filter 1: WAF rate limit or server error on perturbed
        if perturbed.status_code in (429, 403, 503):
            return None

        # False Positive Filter 2: Injected canary was not reflected or did not alter redirect
        canary = probe.canary
        canary_reflected_perturbed = (
            perturbed.canary_in_body
            or perturbed.canary_in_headers
            or (perturbed.location_header and canary in perturbed.location_header)
        )
        if not canary_reflected_perturbed:
            return None

        # False Positive Filter 3: Uncached reflection (Replay is MISS or does not contain canary)
        canary_persisted_replay = (
            replay.canary_in_body
            or replay.canary_in_headers
            or (replay.location_header and canary in replay.location_header)
        )
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
            or (baseline.age is not None and replay.age is not None and replay.age >= baseline.age)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        # False Positive Filter 4: Global Dynamic Reflection (Canary appears in fresh control request B2)
        canary_in_control = (
            control.canary_in_body
            or control.canary_in_headers
            or (control.location_header and canary in control.location_header)
        )
        if canary_in_control:
            return None

        # Confirmed finding
        snippet = replay.raw_body[:250] if replay.canary_in_body else str(replay.headers)[:250]
        severity = CacheSecuritySeverity.CRITICAL.value if "Host" in probe.vector_name or "Prefix" in probe.vector_name or "Original-URL" in probe.vector_name else CacheSecuritySeverity.HIGH.value
        cvss_score = 9.8 if severity == CacheSecuritySeverity.CRITICAL.value else 8.2

        return CacheSecurityResult(
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "unkeyed_header",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
                "age": replay.age,
            },
        )

    @classmethod
    def evaluate_unkeyed_param_poisoning(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Unkeyed Query Parameters and Parameter Cloaking."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        if perturbed.status_code in (429, 403, 503):
            return None

        canary = probe.canary
        canary_reflected_perturbed = perturbed.canary_in_body or perturbed.canary_in_headers
        if not canary_reflected_perturbed:
            return None

        canary_persisted_replay = replay.canary_in_body or replay.canary_in_headers
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        # Reject global dynamic echo
        if control.canary_in_body or control.canary_in_headers:
            return None

        snippet = replay.raw_body[:250]
        is_cloaking = probe.vulnerability_type == CacheVulnerabilityType.PARAMETER_CLOAKING
        vuln_type = CacheVulnerabilityType.PARAMETER_CLOAKING if is_cloaking else CacheVulnerabilityType.UNKEYED_PARAM_POISONING
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.2

        return CacheSecurityResult(
            vulnerability_type=vuln_type,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "unkeyed_param",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )

    @classmethod
    def evaluate_web_cache_deception(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Web Cache Deception."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        # Rejection Filter 1: Must succeed on perturbed and replay
        if perturbed.status_code != 200 or replay.status_code != 200:
            return None

        # Rejection Filter 2: Public static asset with NO sensitive data
        # If perturbed or replay has no sensitive PII/tokens, reject false positive!
        if not (perturbed.pii_detected and replay.pii_detected):
            return None

        # Rejection Filter 3: Unauthenticated replay must be cached (HIT)
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )
        if not is_cached_hit:
            return None

        # Rejection Filter 4: If unauthenticated control also returns PII, the endpoint is public (not an authenticated leak)
        if control.pii_detected:
            return None

        snippet = replay.raw_body[:250]
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.5

        return CacheSecurityResult(
            vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-524",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "web_cache_deception",
                "pii_matches": replay.pii_matches,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )

    @classmethod
    def evaluate_normalization_flaws(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for FAT GET and Method Override normalization flaws."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        if perturbed.status_code in (429, 403, 503):
            return None

        canary = probe.canary
        canary_reflected_perturbed = perturbed.canary_in_body or perturbed.canary_in_headers
        if not canary_reflected_perturbed:
            return None

        canary_persisted_replay = replay.canary_in_body or replay.canary_in_headers
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        if control.canary_in_body or control.canary_in_headers:
            return None

        snippet = replay.raw_body[:250]
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.2

        return CacheSecurityResult(
            vulnerability_type=probe.vulnerability_type,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "normalization_flaw",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )
