"""
Unit and integration tests for EnvironmentDetector and Mission environment state.
"""

import socket
from unittest.mock import MagicMock, patch

import httpx
import pytest

from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.mission import Mission, MissionState
from argus.runtime.mission_runtime import AutonomousMissionRuntime
from argus.runtime.state_machine import MissionStateMachine
from argus.utils.environment import EnvironmentDetector


class MockEngine:
    """Mock engine for runtime components."""

    def __getattr__(self, name):
        if name in ("queue_manager",):
            return MockEngine()

        def _mock(*args, **kwargs):
            if name == "is_complete":
                return True
            return None

        return _mock


def test_default_external_tools_list():
    """Verify DEFAULT_EXTERNAL_TOOLS contains all standard external tools."""
    expected_tools = ["subfinder", "httpx", "nuclei", "katana", "dnsx", "node", "npm"]
    assert EnvironmentDetector.DEFAULT_EXTERNAL_TOOLS == expected_tools


def test_cloud_metadata_endpoints_configuration():
    """Verify CLOUD_METADATA_ENDPOINTS contains AWS, GCP, and Azure configurations."""
    endpoints = EnvironmentDetector.CLOUD_METADATA_ENDPOINTS
    assert "aws" in endpoints
    assert "gcp" in endpoints
    assert "azure" in endpoints

    assert "169.254.169.254" in endpoints["aws"]["url"]
    assert endpoints["gcp"]["headers"].get("Metadata-Flavor") == "Google"
    assert endpoints["azure"]["headers"].get("Metadata") == "true"


def test_check_tools_all_installed():
    """Verify check_tools returns True for all tools when shutil.which finds binaries."""
    detector = EnvironmentDetector()

    with patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
        results = detector.check_tools()

        for tool in EnvironmentDetector.DEFAULT_EXTERNAL_TOOLS:
            assert tool in results
            assert results[tool] is True


def test_check_tools_none_installed():
    """Verify check_tools returns False for all tools when shutil.which returns None."""
    detector = EnvironmentDetector()

    with patch("shutil.which", return_value=None):
        results = detector.check_tools()

        for tool in EnvironmentDetector.DEFAULT_EXTERNAL_TOOLS:
            assert tool in results
            assert results[tool] is False


def test_check_tools_httpx_toolkit_fallback():
    """Verify check_tools identifies httpx when only httpx-toolkit binary is installed."""
    detector = EnvironmentDetector()

    def mock_which(cmd):
        if cmd == "httpx":
            return None
        if cmd == "httpx-toolkit":
            return "/usr/bin/httpx-toolkit"
        return None

    with patch("shutil.which", side_effect=mock_which):
        results = detector.check_tools(["httpx"])
        assert results["httpx"] is True


def test_check_tools_httpx_both_missing():
    """Verify check_tools returns False when neither httpx nor httpx-toolkit is installed."""
    detector = EnvironmentDetector()

    with patch("shutil.which", return_value=None):
        results = detector.check_tools(["httpx"])
        assert results["httpx"] is False


def test_check_tools_custom_subset():
    """Verify check_tools works with a custom list of tool names."""
    detector = EnvironmentDetector()

    def mock_which(cmd):
        if cmd == "node":
            return "/usr/bin/node"
        return None

    with patch("shutil.which", side_effect=mock_which):
        results = detector.check_tools(["node", "custom_scanner"])
        assert results == {"node": True, "custom_scanner": False}


def test_check_network_empty_target():
    """Verify check_network handles empty or whitespace target strings gracefully."""
    detector = EnvironmentDetector()

    res1 = detector.check_network("")
    assert res1["dns_resolvable"] is False
    assert res1["http_reachable"] is False
    assert res1["error"] == "No target specified"

    res2 = detector.check_network("   ")
    assert res2["dns_resolvable"] is False
    assert res2["http_reachable"] is False
    assert res2["error"] == "No target specified"


def test_check_network_dns_success_http_success():
    """Verify check_network succeeds when DNS resolves and HTTP returns 200."""
    detector = EnvironmentDetector()

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with patch.object(httpx.Client, "get", return_value=mock_resp):
            res = detector.check_network("example.com")

            assert res["target"] == "example.com"
            assert res["host"] == "example.com"
            assert res["dns_resolvable"] is True
            assert res["ip_addresses"] == ["93.184.216.34"]
            assert res["http_reachable"] is True
            assert res["status_code"] == 200
            assert res["error"] is None


def test_check_network_dns_failure():
    """Verify check_network handles DNS resolution failure."""
    detector = EnvironmentDetector()

    with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        res = detector.check_network("invalid-nonexistent-domain.xyz")

        assert res["dns_resolvable"] is False
        assert res["ip_addresses"] == []
        assert res["http_reachable"] is False
        assert res["status_code"] is None
        assert "Name or service not known" in str(res["error"])


def test_check_network_dns_success_http_connect_error():
    """Verify check_network handles DNS resolution success with HTTP connection error."""
    detector = EnvironmentDetector()

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with patch.object(httpx.Client, "get", side_effect=httpx.ConnectError("Connection refused")):
            res = detector.check_network("localhost")

            assert res["dns_resolvable"] is True
            assert res["http_reachable"] is False
            assert res["status_code"] is None
            assert "Connection refused" in str(res["error"])


def test_check_network_dns_success_http_timeout():
    """Verify check_network handles HTTP request timeout."""
    detector = EnvironmentDetector()

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with patch.object(httpx.Client, "get", side_effect=httpx.ConnectTimeout("Request timed out")):
            res = detector.check_network("192.0.2.1")

            assert res["dns_resolvable"] is True
            assert res["http_reachable"] is False
            assert "Request timed out" in str(res["error"])


def test_check_network_url_target_parsing():
    """Verify check_network extracts host correctly from full URLs."""
    detector = EnvironmentDetector()

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80))]
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with patch.object(httpx.Client, "get", return_value=mock_resp) as mock_get:
            res = detector.check_network("https://sub.example.com:8443/api/v1?query=1")

            assert res["host"] == "sub.example.com"
            assert res["dns_resolvable"] is True
            assert res["http_reachable"] is True
            mock_get.assert_called_once_with("https://sub.example.com:8443/api/v1?query=1")


def test_check_cloud_metadata_all_unreachable():
    """Verify check_cloud_metadata returns False for all providers when endpoints are unreachable."""
    detector = EnvironmentDetector()

    with patch.object(httpx.Client, "get", side_effect=httpx.ConnectTimeout("Timeout")):
        res = detector.check_cloud_metadata()

        assert res["aws"] is False
        assert res["gcp"] is False
        assert res["azure"] is False
        assert res["endpoints"]["aws"]["accessible"] is False
        assert res["endpoints"]["gcp"]["accessible"] is False
        assert res["endpoints"]["azure"]["accessible"] is False


def test_check_cloud_metadata_aws_detected():
    """Verify check_cloud_metadata detects AWS when IMDS returns 200."""
    detector = EnvironmentDetector()

    def mock_get(url, **kwargs):
        if "169.254.169.254/latest/meta-data" in url:
            resp = MagicMock()
            resp.status_code = 200
            return resp
        raise httpx.ConnectTimeout("Timeout")

    with patch.object(httpx.Client, "get", side_effect=mock_get):
        res = detector.check_cloud_metadata()

        assert res["aws"] is True
        assert res["gcp"] is False
        assert res["azure"] is False
        assert res["endpoints"]["aws"]["accessible"] is True
        assert res["endpoints"]["aws"]["status_code"] == 200


def test_check_cloud_metadata_gcp_detected():
    """Verify check_cloud_metadata detects GCP when metadata endpoint returns 200."""
    detector = EnvironmentDetector()

    def mock_get(url, **kwargs):
        headers = kwargs.get("headers", {})
        if "metadata.google.internal" in url and headers.get("Metadata-Flavor") == "Google":
            resp = MagicMock()
            resp.status_code = 200
            return resp
        raise httpx.ConnectTimeout("Timeout")

    with patch.object(httpx.Client, "get", side_effect=mock_get):
        res = detector.check_cloud_metadata()

        assert res["aws"] is False
        assert res["gcp"] is True
        assert res["azure"] is False
        assert res["endpoints"]["gcp"]["accessible"] is True


def test_check_cloud_metadata_azure_detected():
    """Verify check_cloud_metadata detects Azure when IMDS endpoint returns 200."""
    detector = EnvironmentDetector()

    def mock_get(url, **kwargs):
        headers = kwargs.get("headers", {})
        if "169.254.169.254/metadata/instance" in url and headers.get("Metadata") == "true":
            resp = MagicMock()
            resp.status_code = 200
            return resp
        raise httpx.ConnectTimeout("Timeout")

    with patch.object(httpx.Client, "get", side_effect=mock_get):
        res = detector.check_cloud_metadata()

        assert res["aws"] is False
        assert res["gcp"] is False
        assert res["azure"] is True
        assert res["endpoints"]["azure"]["accessible"] is True


def test_detect_composite_structure():
    """Verify detect() produces composite dictionary with tools, network, cloud, and summary."""
    detector = EnvironmentDetector()

    mock_tools = {"subfinder": True, "httpx": True, "nuclei": False, "katana": False, "dnsx": True, "node": True, "npm": True}
    mock_network = {
        "target": "example.com",
        "host": "example.com",
        "dns_resolvable": True,
        "ip_addresses": ["93.184.216.34"],
        "http_reachable": True,
        "status_code": 200,
        "error": None,
    }
    mock_cloud = {
        "aws": False,
        "gcp": True,
        "azure": False,
        "endpoints": {
            "aws": {"accessible": False, "status_code": None},
            "gcp": {"accessible": True, "status_code": 200},
            "azure": {"accessible": False, "status_code": None},
        },
    }

    with patch.object(detector, "check_tools", return_value=mock_tools):
        with patch.object(detector, "check_network", return_value=mock_network):
            with patch.object(detector, "check_cloud_metadata", return_value=mock_cloud):
                result = detector.detect("example.com")

                assert "tools" in result
                assert "network" in result
                assert "cloud_metadata" in result
                assert "summary" in result

                assert result["tools"] == mock_tools
                assert result["network"] == mock_network
                assert result["cloud_metadata"] == mock_cloud

                summary = result["summary"]
                assert summary["tools_available_count"] == 5
                assert summary["tools_missing_count"] == 2
                assert summary["network_reachable"] is True
                assert summary["in_cloud_environment"] is True


def test_mission_dataclass_environment_field():
    """Verify Mission dataclass initializes with default empty environment dict."""
    mission = Mission(target="https://target.local")
    assert hasattr(mission, "environment")
    assert isinstance(mission.environment, dict)
    assert mission.environment == {}

    mission.environment = {"tools": {"subfinder": True}}
    assert mission.environment["tools"]["subfinder"] is True


def test_mission_runtime_initialization_populates_environment():
    """Verify AutonomousMissionRuntime populates mission.environment on init if empty."""
    mission = Mission(target="https://target.local")
    assert mission.environment == {}

    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    fake_env = {
        "tools": {"subfinder": True},
        "network": {"http_reachable": True},
        "cloud_metadata": {"aws": False},
        "summary": {"tools_available_count": 1},
    }

    with patch("argus.utils.environment.EnvironmentDetector.detect", return_value=fake_env) as mock_detect:
        runtime = AutonomousMissionRuntime(
            mission=mission,
            state_machine=sm,
            checkpointer=checkpointer,
            mission_planner=MockEngine(),
            research_planner=MockEngine(),
            task_scheduler=MockEngine(),
            tool_orchestrator=MockEngine(),
            correlation_engine=MockEngine(),
            fusion_engine=MockEngine(),
            investigation_builder=MockEngine(),
            priority_engine=MockEngine(),
            hypothesis_engine=MockEngine(),
            learning_engine=MockEngine(),
        )

        mock_detect.assert_called_once_with("https://target.local")
        assert mission.environment == fake_env


def test_mission_runtime_planning_step_populates_environment_if_empty():
    """Verify AutonomousMissionRuntime.step() populates environment during PLANNING if empty."""
    mission = Mission(target="https://target.local")
    # Pre-populate dummy to bypass __init__ detection test, then clear it
    mission.environment = {"initial": True}

    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    runtime = AutonomousMissionRuntime(
        mission=mission,
        state_machine=sm,
        checkpointer=checkpointer,
        mission_planner=MockEngine(),
        research_planner=MockEngine(),
        task_scheduler=MockEngine(),
        tool_orchestrator=MockEngine(),
        correlation_engine=MockEngine(),
        fusion_engine=MockEngine(),
        investigation_builder=MockEngine(),
        priority_engine=MockEngine(),
        hypothesis_engine=MockEngine(),
        learning_engine=MockEngine(),
    )

    # Clear environment and set status to PLANNING
    mission.environment = {}
    sm.transition_to(MissionState.PLANNING)

    fake_env = {"tools": {"katana": True}, "summary": {"tools_available_count": 1}}
    with patch("argus.utils.environment.EnvironmentDetector.detect", return_value=fake_env) as mock_detect:
        runtime.step()

        mock_detect.assert_called_once_with("https://target.local")
        assert mission.environment == fake_env
        assert mission.status == MissionState.RESEARCHING


def test_mission_runtime_preserves_prepopulated_environment():
    """Verify AutonomousMissionRuntime does not overwrite existing mission.environment."""
    pre_existing_env = {"tools": {"nuclei": True}, "custom": "value"}
    mission = Mission(target="https://target.local", environment=pre_existing_env)

    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    with patch("argus.utils.environment.EnvironmentDetector.detect") as mock_detect:
        runtime = AutonomousMissionRuntime(
            mission=mission,
            state_machine=sm,
            checkpointer=checkpointer,
            mission_planner=MockEngine(),
            research_planner=MockEngine(),
            task_scheduler=MockEngine(),
            tool_orchestrator=MockEngine(),
            correlation_engine=MockEngine(),
            fusion_engine=MockEngine(),
            investigation_builder=MockEngine(),
            priority_engine=MockEngine(),
            hypothesis_engine=MockEngine(),
            learning_engine=MockEngine(),
        )

        mock_detect.assert_not_called()
        assert mission.environment == pre_existing_env


@pytest.mark.parametrize(
    "malformed_url",
    [
        "http://[invalid_ipv6",
        "http://]",
        "https://[",
        "[invalid_ipv6]:8080",
        "http://user:pass@[invalid_ipv6",
    ],
)
def test_check_network_malformed_bracket_urls(malformed_url):
    """Verify check_network gracefully handles malformed bracket URLs without raising exceptions."""
    detector = EnvironmentDetector()
    res = detector.check_network(malformed_url)

    assert res["target"] == malformed_url
    assert res["host"] == ""
    assert res["dns_resolvable"] is False
    assert res["ip_addresses"] == []
    assert res["http_reachable"] is False
    assert res["status_code"] is None
    assert res["error"] is not None
    assert "Invalid target URL:" in res["error"]


def test_check_network_ipv6_raw_and_bracketed_targets():
    """Verify check_network extracts host correctly and uses bracketed URLs for IPv6 targets."""
    detector = EnvironmentDetector()

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    # 1. Raw IPv6 localhost (::1)
    mock_addrinfo_v6_loopback = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo_v6_loopback):
        with patch.object(httpx.Client, "get", return_value=mock_resp) as mock_get:
            res = detector.check_network("::1")
            assert res["target"] == "::1"
            assert res["host"] == "::1"
            assert res["dns_resolvable"] is True
            assert res["ip_addresses"] == ["::1"]
            assert res["http_reachable"] is True
            mock_get.assert_called_once_with("http://[::1]")

    # 2. Raw IPv6 public address (2001:db8::1)
    mock_addrinfo_v6_pub = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 80, 0, 0))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo_v6_pub):
        with patch.object(httpx.Client, "get", return_value=mock_resp) as mock_get:
            res = detector.check_network("2001:db8::1")
            assert res["target"] == "2001:db8::1"
            assert res["host"] == "2001:db8::1"
            assert res["dns_resolvable"] is True
            assert res["ip_addresses"] == ["2001:db8::1"]
            assert res["http_reachable"] is True
            mock_get.assert_called_once_with("http://[2001:db8::1]")

    # 3. Bracketed IPv6 with port ([::1]:8080)
    with patch("socket.getaddrinfo", return_value=mock_addrinfo_v6_loopback):
        with patch.object(httpx.Client, "get", return_value=mock_resp) as mock_get:
            res = detector.check_network("[::1]:8080")
            assert res["target"] == "[::1]:8080"
            assert res["host"] == "::1"
            assert res["dns_resolvable"] is True
            assert res["http_reachable"] is True
            mock_get.assert_called_once_with("http://[::1]:8080")


def test_mission_runtime_malformed_url_target_resilience():
    """Verify AutonomousMissionRuntime handles malformed URL target gracefully during initialization."""
    mission = Mission(target="http://[invalid_ipv6")
    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    runtime = AutonomousMissionRuntime(
        mission=mission,
        state_machine=sm,
        checkpointer=checkpointer,
        mission_planner=MockEngine(),
        research_planner=MockEngine(),
        task_scheduler=MockEngine(),
        tool_orchestrator=MockEngine(),
        correlation_engine=MockEngine(),
        fusion_engine=MockEngine(),
        investigation_builder=MockEngine(),
        priority_engine=MockEngine(),
        hypothesis_engine=MockEngine(),
        learning_engine=MockEngine(),
    )

    assert mission.environment != {}
    network_info = mission.environment.get("network", {})
    assert network_info.get("dns_resolvable") is False
    assert network_info.get("http_reachable") is False
    assert "Invalid target URL:" in network_info.get("error", "")

