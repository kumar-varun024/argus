import os
import pytest
from unittest.mock import patch

from argus.runtime.mission import Mission, _derive_default_scope
from argus.authorization.scope import ScopeResolver, ScopeState
from argus.runtime.manager import mission_manager
from argus.collectors.subfinder import SubfinderCollector, _extract_host
from argus.collectors.httpx import HttpxCollector, _derive_host_dict
from argus.collectors.katana import KatanaCollector, _derive_endpoint_dict
from argus.collectors.nuclei import NucleiCollector
from argus.scanning.engine import ScanEngine
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.models import CollectorStatus
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence


def test_complex_url_scope_derivation_and_matching():
    target = "http://user:pass@sub.domain.co.uk:8443/api/v1?x=1#frag"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert "sub.domain.co.uk" in m.scope
    assert "*.sub.domain.co.uk" in m.scope

    # Verify matching
    d1 = resolver.check_scope(target, m.id)
    assert d1.decision == ScopeState.IN_SCOPE

    d2 = resolver.check_scope("https://sub.domain.co.uk/other/path", m.id)
    assert d2.decision == ScopeState.IN_SCOPE

    d3 = resolver.check_scope("http://api.sub.domain.co.uk:8443/test", m.id)
    assert d3.decision == ScopeState.IN_SCOPE

    d4 = resolver.check_scope("http://domain.co.uk", m.id)
    assert d4.decision == ScopeState.OUT_OF_SCOPE


def test_ipv4_with_port():
    target = "127.0.0.1:8080"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert m.scope == ["127.0.0.1"]
    assert resolver.check_scope("127.0.0.1:8080", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://127.0.0.1:8080/api", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("127.0.0.1", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("127.0.0.2:8080", m.id).decision == ScopeState.OUT_OF_SCOPE


def test_ipv6_with_port_bracket_notation():
    target = "[::1]:9000"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert m.scope == ["::1"]
    assert resolver.check_scope("[::1]:9000", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://[::1]:9000/api", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("::1", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("::2", m.id).decision == ScopeState.OUT_OF_SCOPE


def test_ipv6_global_with_port():
    target = "[2001:db8::1]:443"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert m.scope == ["2001:db8::1"]
    assert resolver.check_scope("[2001:db8::1]:443", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://[2001:db8::1]:443/v1", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("2001:db8::1", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("2001:db8::2", m.id).decision == ScopeState.OUT_OF_SCOPE


def test_cidr_scope_matching():
    target = "10.0.0.0/24"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert m.scope == ["10.0.0.0/24"]
    assert resolver.check_scope("10.0.0.1", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("10.0.0.254", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://10.0.0.50:8080/test", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("10.0.1.1", m.id).decision == ScopeState.OUT_OF_SCOPE

    # Subnet /28 (192.168.1.0 - 192.168.1.15)
    m2 = Mission(target="192.168.1.0/28")
    mission_manager._active_missions[m2.id] = m2
    assert m2.scope == ["192.168.1.0/28"]
    assert resolver.check_scope("192.168.1.5", m2.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("192.168.1.15", m2.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("192.168.1.16", m2.id).decision == ScopeState.OUT_OF_SCOPE


def test_adversarial_lookalike_and_suffix():
    target = "example.com"
    m = Mission(target=target)
    mission_manager._active_missions[m.id] = m
    resolver = ScopeResolver()

    assert resolver.check_scope("evilexample.com", m.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("example.com.attacker.com", m.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("notexample.com", m.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("attacker-example.com", m.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("http://evilexample.com:8080/api", m.id).decision == ScopeState.OUT_OF_SCOPE

    # Legitimate
    assert resolver.check_scope("example.com", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("sub.example.com", m.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("a.b.c.example.com", m.id).decision == ScopeState.IN_SCOPE


def test_path_empty_recon_fallbacks():
    with patch.dict(os.environ, {"PATH": ""}):
        m = Mission(target="http://api.example.com:8080/v1/users?role=admin")
        mission_manager._active_missions[m.id] = m

        subfinder = SubfinderCollector()
        subfinder.collect(m)
        assert m.subdomains == ["api.example.com"]
        assert m.evidence.count() >= 1

        httpx = HttpxCollector()
        httpx.collect(m)
        assert len(m.live_hosts) == 1
        lh = m.live_hosts[0]
        assert lh["host"] == "api.example.com"
        assert lh["port"] == 8080
        assert lh["scheme"] == "http"
        assert lh["url"] == "http://api.example.com:8080"

        katana = KatanaCollector()
        katana.collect(m)
        assert len(m.endpoints) == 1
        ep = m.endpoints[0]
        assert ep["path"] == "/v1/users"
        assert ep["params"] == {"role": "admin"}
        assert ep["url"] == "http://api.example.com:8080/v1/users"

        nuclei = NucleiCollector()
        ev = nuclei.collect(m)
        assert ev == []
        assert m.vulnerabilities == []


def test_downstream_collectors_under_path_empty():
    from argus.http.client import AuthenticatedHttpClient, HttpResponse
    def fast_request(self, *args, **kwargs):
        return HttpResponse(success=False, error="Connection refused", url="", method="GET")

    with patch.object(AuthenticatedHttpClient, "request", fast_request):
        with patch.dict(os.environ, {"PATH": ""}):
            m = Mission(target="http://api.example.com:8080/v1/users?id=1")
            mission_manager._active_missions[m.id] = m
            engine = ScanEngine()
            result = engine.run(m)

            failed_cols = [f"{cr.task_key} ({cr.error})" for cr in result.collector_results if getattr(cr.status, "value", str(cr.status)) == "FAILED"]
            assert result.status == "COMPLETED"
            assert result.collectors_failed == 0, f"Failed collectors: {failed_cols}"
            assert result.collectors_skipped == 0
            assert result.collectors_run == 26

