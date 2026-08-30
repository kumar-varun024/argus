"""
Adversarial stress tests and edge case verification for InformationDisclosureCollector and SecretExtractor.
"""
import gzip
import json
import os
import time
import pytest
from unittest.mock import MagicMock

from argus.collectors.information_disclosure import (
    InformationDisclosureCollector,
    SecretExtractor,
    DEFAULT_WORDLIST,
)
from argus.runtime.mission import Mission
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse


class MockHttpClient:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requested_urls = []

    def get(self, mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        self.requested_urls.append(target_url)
        if target_url in self.routes:
            status_code, body = self.routes[target_url]
            return HttpResponse(
                success=(status_code == 200),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
            )
        return HttpResponse(success=False, status_code=404, error="Not Found", url=target_url)


# ============================================================================
# 1. Malformed JSON in Actuator Endpoints & Robustness
# ============================================================================

def test_adversarial_malformed_json_truncated():
    """Verify parser handles truncated / broken JSON without crashing."""
    extractor = SecretExtractor()
    broken_json = '{"activeProfiles": ["prod", "db": {"password": "inval'
    res = extractor.extract(broken_json)
    assert isinstance(res, dict)
    assert "secrets" in res
    assert "internal_domains" in res


def test_adversarial_json_primitive_roots_and_mixed_types():
    """Verify JSON parser handles non-dict/list roots, primitive arrays, None values, and booleans."""
    extractor = SecretExtractor()
    json_cases = [
        '12345',
        '"just a string"',
        'true',
        'null',
        '[1, 2, 3, null, false, "simple_string", {"nested_key": 42}]',
        '{"empty_list": [], "empty_dict": {}, "null_val": null, "bool_val": true}',
        '{"api_key": null, "db_password": false, "auth_token": true, "secret": 12345}',
    ]
    for case in json_cases:
        res = extractor.extract(case)
        assert isinstance(res, dict)
        assert "secrets" in res


def test_adversarial_deeply_nested_json():
    """Verify parser handles deeply nested JSON (e.g. 150 levels) without blowing Python stack."""
    extractor = SecretExtractor()
    nested = {"key_deep": "superSecretNestedVal123"}
    for i in range(150):
        nested = {f"level_{i}": nested}
    payload = json.dumps(nested)
    
    start_time = time.time()
    res = extractor.extract(payload)
    duration = time.time() - start_time
    assert duration < 1.0
    assert isinstance(res, dict)


# ============================================================================
# 2. Binary / Non-UTF-8 Payloads / Heap Dumps
# ============================================================================

def test_adversarial_binary_null_bytes_and_high_entropy():
    """Verify SecretExtractor and collector safely handle binary strings, null bytes, and non-UTF-8 representations."""
    extractor = SecretExtractor()
    
    # 1. Null bytes mixed with valid secret
    mixed_binary = "prefix\x00\x01\x02 AIzaSyD-1234567890abcdefghijklmnopqrstu\x00\x00\x00suffix"
    res = extractor.extract(mixed_binary)
    secret_vals = [s["value"] for s in res["secrets"]]
    assert "AIzaSyD-1234567890abcdefghijklmnopqrstu" in secret_vals

    # 2. Pure random bytes string representation
    random_bytes = os.urandom(50000).decode("latin-1")
    res_rand = extractor.extract(random_bytes)
    assert isinstance(res_rand, dict)


def test_adversarial_simulated_heapdump_payload():
    """Verify collector handles a mock /actuator/heapdump binary payload."""
    hprof_header = b"JAVA PROFILE 1.0.2\x00\x00\x00\x04" + os.urandom(10000)
    
    mock_client = MockHttpClient({
        "https://example.com/actuator/heapdump": (200, hprof_header)
    })
    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=["/actuator/heapdump"])
    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert evidence[0].metadata["path"] == "/actuator/heapdump"
    assert evidence[0].severity == "high"


def test_adversarial_gzip_compressed_body():
    """Verify collector handles gzip payload gracefully without crashing."""
    raw_data = gzip.compress(b"DB_PASSWORD=GzipSecretPass123\nINTERNAL=backend.corp.local")
    mock_client = MockHttpClient({
        "https://example.com/backup.gz": (200, raw_data)
    })
    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=["backup.gz"])
    evidence = collector.collect(mission)
    assert len(evidence) == 1


# ============================================================================
# 3. Massive Response Bodies & ReDoS Resistance
# ============================================================================

def test_adversarial_massive_body_performance_2mb():
    """Verify SecretExtractor parses a 2MB payload in < 2.0 seconds."""
    extractor = SecretExtractor()
    
    # 2MB of realistic mixed text + scattered secrets
    chunk = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 50
        + "\nDATABASE_URL=postgres://app_user:StrongPass987@postgres.internal.corp:5432/app_db\n"
        + "Some more random configuration text with key=value pairs\n"
    )
    payload = chunk * 400  # ~2.5 MB
    
    start_time = time.time()
    res = extractor.extract(payload, target_domain="example.com")
    duration = time.time() - start_time

    assert duration < 2.0, f"Extraction took {duration:.2f}s, expected < 2.0s"
    assert "postgres.internal.corp" in res["internal_domains"]
    assert any(s["type"] == "database_connection_string" for s in res["secrets"])


def test_adversarial_redos_pathological_patterns():
    """Verify regexes do not suffer from catastrophic backtracking under pathological patterns."""
    extractor = SecretExtractor()
    
    pathological_cases = [
        # Repeated dots / domain-like patterns
        "a." * 5000 + "internal",
        "https://" + "a." * 2000 + "corp.local",
        # Repeated prefix without valid key
        "AIza" * 5000,
        "sk_live_" * 5000,
        "ghp_" * 5000,
        "eyJ" * 5000,
        # Long unclosed quotes / whitespace
        "password = " + " " * 10000 + "secret",
        "api_key = '" + "a" * 10000,
        "DATABASE_URL=postgres://" + "user:" * 2000 + "@localhost",
        # Huge line without newlines
        "x" * 200000,
    ]

    for case in pathological_cases:
        t0 = time.time()
        res = extractor.extract(case)
        elapsed = time.time() - t0
        assert elapsed < 0.5, f"ReDoS suspected on pattern, took {elapsed:.2f}s"
        assert isinstance(res, dict)


# ============================================================================
# 4. Mixed Lines, Comments, Multiple Secrets, False Positives
# ============================================================================

def test_adversarial_multiple_secrets_on_single_line():
    """Verify multiple secrets on a single line are all extracted."""
    extractor = SecretExtractor()
    line = (
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        f"STRIPE_KEY=sk_live_{'51ABC1234567890abcdefghijklm'} "
        "INTERNAL_HOST=api.service.internal"
    )
    res = extractor.extract(line)
    types = {s["type"] for s in res["secrets"]}
    assert "aws_access_key_id" in types
    assert "aws_secret_access_key" in types
    assert "stripe_secret_key" in types
    assert "api.service.internal" in res["internal_domains"]


def test_adversarial_commented_and_prefixed_lines():
    """Verify credentials on commented lines (e.g. .env templates) are extracted."""
    extractor = SecretExtractor()
    content = """
    # DB_PASSWORD=CommentedPass123
    // password=SlashCommentPass
    /* api_key=BlockCommentApiKey123456 */
    -- db_password=SqlCommentPass
    """
    res = extractor.extract(content)
    secret_vals = [s["value"] for s in res["secrets"]]
    assert "CommentedPass123" in secret_vals
    assert "SlashCommentPass" in secret_vals
    assert "BlockCommentApiKey123456" in secret_vals
    assert "SqlCommentPass" in secret_vals


def test_adversarial_password_false_positives_and_placeholders():
    """Verify common false positive strings like null, false, empty are not extracted as passwords."""
    extractor = SecretExtractor()
    content = """
    password=null
    passwd=none
    db_password=true
    pwd=false
    password=""
    password=''
    password=
    """
    res = extractor.extract(content)
    secret_vals = [s["value"] for s in res["secrets"]]
    assert len(secret_vals) == 0


def test_adversarial_passwords_with_special_characters():
    """Verify passwords with special characters (@, $, !, %, &, +, =) are captured properly."""
    extractor = SecretExtractor()
    content = """
    DB_PASSWORD=ComplexP@ssw0rd$2026!
    SECRET_KEY=Abc+123/Xyz=
    DATABASE_URL=postgres://user:P%40ssw0rd@db.internal:5432/app
    """
    res = extractor.extract(content)
    secret_vals = [s["value"] for s in res["secrets"]]
    assert "ComplexP@ssw0rd$2026!" in secret_vals
    assert "db.internal" in res["internal_domains"]


# ============================================================================
# 5. Tricky URL Formats & Normalization
# ============================================================================

def test_adversarial_url_normalization_variations():
    """Verify base URL extraction and path joining handle tricky URL formats gracefully."""
    collector = InformationDisclosureCollector()
    
    test_cases = [
        ("https://example.com/", "https://example.com"),
        ("https://example.com///", "https://example.com"),
        ("http://example.com:8080/path/to/app?query=1#hash", "http://example.com:8080"),
        ("example.com", "https://example.com"),
        ("sub.example.com:9443/v1/api", "https://sub.example.com:9443"),
        ("http://192.168.1.10:8000/", "http://192.168.1.10:8000"),
        ("https://user:pass@example.com/app", "https://user:pass@example.com"),
    ]
    
    for raw, expected in test_cases:
        norm = collector._normalize_base_url(raw)
        assert norm == expected, f"Failed for {raw}: got {norm}, expected {expected}"


def test_adversarial_candidate_extraction_with_dirty_inputs():
    """Verify candidate URL extraction handles None, empty, dicts with missing keys, and invalid items."""
    collector = InformationDisclosureCollector()
    
    mission = Mission(target="example.com")
    mission.live_hosts = [
        None,
        "",
        "   ",
        {},
        {"url": ""},
        {"host": None},
        {"url": "https://host1.example.com"},
        "https://host2.example.com:8080",
    ]
    mission.endpoints = [
        None,
        {},
        {"path": "/api/v1"},
        {"url": "https://host3.example.com/api/v2"},
    ]
    mission.subdomains = [
        None,
        "",
        {},
        {"hostname": "host4.example.com"},
        "host5.example.com",
    ]
    
    candidates = collector._extract_candidate_base_urls(mission)
    assert "https://host1.example.com" in candidates
    assert "https://host2.example.com:8080" in candidates
    assert "https://host3.example.com" in candidates
    assert "https://host4.example.com" in candidates
    assert "https://host5.example.com" in candidates
    assert "" not in candidates
    assert "None" not in candidates


def test_adversarial_path_probing_url_joining():
    """Verify path probing joins base URLs and paths without double slashes or missing slashes."""
    mock_client = MockHttpClient()
    collector = InformationDisclosureCollector(http_client=mock_client)
    
    mission = Mission(target="example.com")
    
    # Path with leading slash
    collector._probe_path(mission, "https://example.com/", "/actuator/env")
    assert mock_client.requested_urls[-1] == "https://example.com/actuator/env"

    # Path without leading slash
    collector._probe_path(mission, "https://example.com/", ".env")
    assert mock_client.requested_urls[-1] == "https://example.com/.env"

    # Base without trailing slash + path with leading slash
    collector._probe_path(mission, "https://example.com", "/phpinfo.php")
    assert mock_client.requested_urls[-1] == "https://example.com/phpinfo.php"

    # Base without trailing slash + path without leading slash
    collector._probe_path(mission, "https://example.com", ".git/config")
    assert mock_client.requested_urls[-1] == "https://example.com/.git/config"


# ============================================================================
# 6. Mission Resilience & None Attribute Safety
# ============================================================================

def test_adversarial_collector_resilience_null_mission_attributes():
    """Verify collector runs cleanly when mission attributes are None or empty."""
    mock_client = MockHttpClient()
    collector = InformationDisclosureCollector(http_client=mock_client)
    
    class EmptyMission:
        pass
    
    empty_mission = EmptyMission()
    # Should not throw AttributeError or TypeError
    res = collector.collect(empty_mission)
    assert res == []


def test_adversarial_collector_resilience_missing_graph():
    """Verify collector executes and emits Evidence even if attack_surface_graph is None."""
    mock_client = MockHttpClient({
        "https://example.com/.env": (200, "DB_PASSWORD=Pass123\nINTERNAL_HOST=api.internal.corp")
    })
    
    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = []  # list instead of EvidenceStore
    mission.vulnerabilities = None  # None vulnerabilities
    mission.subdomains = None  # None subdomains
    mission.attack_surface_graph = None  # None graph

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert evidence[0].category == "information_disclosure"
    assert "api.internal.corp" in evidence[0].metadata["internal_domains"]
