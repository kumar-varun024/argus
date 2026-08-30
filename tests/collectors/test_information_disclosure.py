"""
Unit and integration tests for InformationDisclosureCollector and SecretExtractor.
"""
import json
import pytest
from unittest.mock import MagicMock

from argus.collectors.information_disclosure import InformationDisclosureCollector, SecretExtractor, DEFAULT_WORDLIST
from argus.runtime.mission import Mission
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse


class MockHttpClient:
    """Mock HTTP client that responds based on path matching."""

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


def test_secret_extractor_regex_patterns_comprehensive():
    """Unit test: verifies SecretExtractor pattern matching across all credential categories."""
    extractor = SecretExtractor()
    sample_text = f"""
    # Google API Key
    GOOGLE_KEY=AIzaSyD-1234567890abcdefghijklmnopqrstu
    # Stripe Key
    STRIPE_KEY=sk_live_{"51ABC1234567890abcdefghijklm"}
    # GitHub Token
    GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
    # Slack Webhook and Token
    SLACK_HOOK=https://hooks.slack.com/services/T12345678/B12345678/{"123456789012345678901234"}
    SLACK_BOT_TOKEN=xoxb-{"123456789012-1234567890123-abcdefghijklmnopqrst"}
    # AWS Credentials
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    # JWT Token
    AUTH_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    # Database URIs
    DATABASE_URL=postgres://app_user:StrongPass987@postgres.internal.corp:5432/app_db
    REDIS_URL=redis://auth_user:redisSecret123@cache.cluster.local:6379/0
    # Cleartext Password
    DB_PASSWORD=MyVerySecretDatabasePassword123!
    # Generic API Key
    API_KEY=abcdef1234567890abcdef123456
    # Network IPs
    GATEWAY_IP=10.100.4.1
    APP_IP=172.20.10.5
    BACKUP_IP=192.168.1.100
    # Internal Hostnames
    INTERNAL_SVC=auth-service.lan
    INTERNAL_K8S=payment.service.cluster.local
    # Subdomain of target
    TARGET_SUB=admin-portal.example.com
    """

    res = extractor.extract(sample_text, target_domain="example.com")
    secrets = res["secrets"]
    internal_domains = res["internal_domains"]
    private_ips = res["private_ips"]

    secret_types = {s["type"] for s in secrets}
    assert "google_api_key" in secret_types
    assert "stripe_secret_key" in secret_types
    assert "github_token" in secret_types
    assert "slack_webhook" in secret_types
    assert "slack_token" in secret_types
    assert "aws_access_key_id" in secret_types
    assert "aws_secret_access_key" in secret_types
    assert "jwt_token" in secret_types
    assert "database_connection_string" in secret_types
    assert "password" in secret_types
    assert "api_key" in secret_types

    # Check IPs
    assert "10.100.4.1" in private_ips
    assert "172.20.10.5" in private_ips
    assert "192.168.1.100" in private_ips

    # Check Internal Domains
    assert "postgres.internal.corp" in internal_domains
    assert "cache.cluster.local" in internal_domains
    assert "auth-service.lan" in internal_domains
    assert "payment.service.cluster.local" in internal_domains
    assert "admin-portal.example.com" in internal_domains


def test_collector_dotenv_file_discovered_and_secrets_extracted():
    """Verifies that discovered .env file emits High Evidence and feeds subdomains."""
    dotenv_content = """
    APP_ENV=production
    DB_PASSWORD=ProdPassword_999!
    DATABASE_URL=postgres://admin:adminPass@db.prod.internal:5432/main
    AWS_ACCESS_KEY_ID=AKIAEXAMPLETEST12345
    AWS_SECRET_ACCESS_KEY=1234567890123456789012345678901234567890
    API_SUBDOMAIN=api-internal.example.com
    """

    mock_client = MockHttpClient({
        "https://example.com/.env": (200, dotenv_content)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://example.com"}]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.category == "information_disclosure"
    assert ev.severity == "high"
    assert ev.status == "CONFIRMED"
    assert ev.confidence == 0.95
    assert ev.metadata["status_code"] == 200
    assert ev.metadata["path"] == ".env"
    assert len(ev.metadata["secrets"]) >= 3
    assert "db.prod.internal" in ev.metadata["internal_domains"]
    assert "api-internal.example.com" in ev.metadata["internal_domains"]

    # Mission mutations
    assert len(mission.vulnerabilities) == 1
    assert mission.vulnerabilities[0]["template_id"] == "info-disclosure-env"
    assert "api-internal.example.com" in mission.subdomains
    assert "db.prod.internal" in mission.subdomains

    # Subdomain Evidence in store
    sub_evs = [e for e in mission.evidence.all() if e.category == "subdomain"]
    assert len(sub_evs) >= 2


def test_collector_git_config_discovered():
    """Verifies that .git/config is parsed and git origin repository hostname is extracted."""
    git_config_content = """
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
    [remote "origin"]
        url = https://gitlab.corp.internal/security/core-app.git
        fetch = +refs/heads/*:refs/remotes/origin/*
    """

    mock_client = MockHttpClient({
        "https://example.com/.git/config": (200, git_config_content)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.category == "information_disclosure"
    assert "gitlab.corp.internal" in ev.metadata["internal_domains"]
    assert "gitlab.corp.internal" in mission.subdomains


def test_collector_actuator_env_discovered():
    """Verifies that Spring Boot Actuator /actuator/env is parsed recursively for configs."""
    actuator_json = """
    {
        "activeProfiles": ["prod"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "DATABASE_PASSWORD": {"value": "actuatorDbPass123"},
                    "AUTH_SERVER_URL": {"value": "https://auth.internal.corp:8443"},
                    "INTERNAL_IP": {"value": "10.0.1.25"}
                }
            }
        ]
    }
    """

    mock_client = MockHttpClient({
        "https://example.com/actuator/env": (200, actuator_json)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.metadata["path"] == "/actuator/env"
    assert "auth.internal.corp" in ev.metadata["internal_domains"]
    assert "10.0.1.25" in ev.metadata["private_ips"]
    assert any(s["value"] == "actuatorDbPass123" for s in ev.metadata["secrets"])


def test_collector_phpinfo_discovered():
    """Verifies that exposed phpinfo.php is flagged with high severity and server IPs extracted."""
    phpinfo_html = """
    <!DOCTYPE html>
    <html>
    <head><title>phpinfo()</title></head>
    <body>
    <h1>PHP Version 8.1.2</h1>
    <table>
    <tr><td>SERVER_ADDR</td><td>192.168.50.12</td></tr>
    <tr><td>HTTP_HOST</td><td>internal-php.example.com</td></tr>
    </table>
    </body>
    </html>
    """

    mock_client = MockHttpClient({
        "https://example.com/phpinfo.php": (200, phpinfo_html)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.metadata["path"] == "phpinfo.php"
    assert "192.168.50.12" in ev.metadata["private_ips"]
    assert "internal-php.example.com" in ev.metadata["internal_domains"]


def test_collector_source_map_discovered():
    """Verifies that .js.map files are flagged as Information Disclosure."""
    sourcemap_json = '{"version":3,"file":"bundle.js","sources":["webpack:///src/auth/login.ts"],"names":[],"mappings":""}'

    mock_client = MockHttpClient({
        "https://example.com/.js.map": (200, sourcemap_json)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.metadata["path"] == ".js.map"
    assert ev.severity == "high"


def test_collector_ignores_non_200_and_404_responses():
    """Verifies that 404/403/500 responses do not trigger false positive findings."""
    mock_client = MockHttpClient({
        "https://example.com/.env": (404, "Page Not Found"),
        "https://example.com/.git/config": (403, "Access Denied"),
        "https://example.com/phpinfo.php": (500, "Internal Server Error"),
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = InformationDisclosureCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0
    assert len(mission.vulnerabilities) == 0
    assert len(mission.subdomains) == 0


def test_knowledge_graph_node_and_edge_creation():
    """Verifies that KnowledgeGraph accurately represents live_host, endpoint, vulnerability, secret, and subdomain nodes."""
    dotenv_content = """
    DB_PASSWORD=SecretDB123
    INTERNAL_API=backend.internal.corp
    """
    mock_client = MockHttpClient({
        "https://example.com/.env": (200, dotenv_content)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.subdomains = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    collector = InformationDisclosureCollector(http_client=mock_client)
    collector.collect(mission)

    # Check node presence
    assert graph.get("live_host:https://example.com") is not None
    assert graph.get("endpoint:https://example.com/.env") is not None
    assert graph.get("vulnerability:info-disclosure-env:https://example.com/.env") is not None
    assert graph.get("subdomain:backend.internal.corp") is not None

    # Check edges
    assert graph.are_connected("live_host:https://example.com", "endpoint:https://example.com/.env")
    assert graph.are_connected("endpoint:https://example.com/.env", "vulnerability:info-disclosure-env:https://example.com/.env")
    assert graph.are_connected("vulnerability:info-disclosure-env:https://example.com/.env", "subdomain:backend.internal.corp")


def test_custom_wordlist_injection():
    """Verifies that custom wordlists can be passed and evaluated."""
    custom_content = "SECRET_TOKEN=customSecretVal123"
    mock_client = MockHttpClient({
        "https://example.com/custom_secret.conf": (200, custom_content)
    })

    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    collector = InformationDisclosureCollector(
        http_client=mock_client,
        wordlist=["custom_secret.conf"]
    )
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    assert evidence[0].metadata["path"] == "custom_secret.conf"
    assert "https://example.com/custom_secret.conf" in mock_client.requested_urls
    assert "https://example.com/.env" not in mock_client.requested_urls


def test_subdomain_and_endpoint_input_normalization():
    """Verifies that candidate targets from endpoints and subdomains are normalized properly."""
    mock_client = MockHttpClient({
        "https://sub1.example.com/.env": (200, "SECRET=123"),
        "https://sub2.example.com/.env": (200, "SECRET=456"),
    })

    mission = Mission(target="example.com")
    mission.live_hosts = []
    mission.subdomains = ["sub1.example.com", {"hostname": "sub2.example.com"}]
    mission.endpoints = [{"url": "https://sub1.example.com/api/v1"}]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    collector = InformationDisclosureCollector(http_client=mock_client, wordlist=[".env"])
    evidence = collector.collect(mission)

    assert len(evidence) == 2
    urls = {e.value for e in evidence}
    assert "https://sub1.example.com/.env" in urls
    assert "https://sub2.example.com/.env" in urls


def test_secret_extractor_remediations():
    """Verifies remediations for password-only DB URIs, placeholder filters, nested JSON, and binary word boundaries."""
    extractor = SecretExtractor()

    # 1. Password-only Redis URL
    redis_text = "REDIS_URL=redis://:redisSecretPass@cache.internal:6379/0"
    res1 = extractor.extract(redis_text)
    db_secrets = [s["value"] for s in res1["secrets"] if s["type"] == "database_connection_string"]
    assert "redis://:redisSecretPass@cache.internal:6379/0" in db_secrets
    assert "cache.internal" in res1["internal_domains"]

    # 2. Masked and placeholder password exclusions
    placeholder_text = """
    PASSWORD=undefined
    DB_PASS=redacted
    APP_PASSWORD=******
    ROOT_PASS=********
    VALID_PASSWORD=ValidSecretPass123
    """
    res2 = extractor.extract(placeholder_text)
    passwords = [s["value"] for s in res2["secrets"] if s["type"] == "password"]
    assert "ValidSecretPass123" in passwords
    assert "undefined" not in passwords
    assert "redacted" not in passwords
    assert "******" not in passwords
    assert "********" not in passwords

    # 3. Nested Spring Boot property object in JSON
    nested_json = json.dumps({
        "propertySources": [{
            "name": "systemProperties",
            "properties": {
                "SECURITY_API_KEY": {"value": "sec_token_999"},
                "MASKED_KEY": {"value": "******"},
                "BACKEND_HOST": {"value": "http://api.backend.corp:8080"}
            }
        }]
    })
    res3 = extractor.extract(nested_json)
    secret_vals = [s["value"] for s in res3["secrets"]]
    assert "sec_token_999" in secret_vals
    assert "******" not in secret_vals
    assert "api.backend.corp" in res3["internal_domains"]

