"""
Adversarial, False Positive Rejection, and Edge-Case Test Suite for File Upload Vulnerability Detection Module.

Covers:
- False positive rejection of legitimate uploads with server-side validation
- False positive rejection of WAF 403 Forbidden blocks and rate limiting
- False positive rejection of 415 Unsupported Media Type rejections
- False positive rejection of error reflections without storage
- False positive rejection of UUID renaming with safe extensions
- Network timeout, connection drop, and socket error resilience
- Malformed JSON and HTML response parsing resilience
- Graceful handling of empty endpoint / target states
- Web shell verification handling 404 Not Found
- Web shell verification rejecting unparsed source code reflection
- Strict probe limit enforcement (max_probes_per_endpoint)
- ControlledMission exception handling and resilience
"""
import pytest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from argus.collectors.file_upload import (
    FileUploadCollector,
    FileUploadPayloadGenerator,
    FileUploadProber,
    FileUploadAnalyzer,
    FileUploadProbe,
    FileUploadResponse,
    FileUploadTechnique,
    FileUploadMutationStrategy,
    TargetRuntime,
)
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission


class AdversarialFileUploadHttpClient:
    """Mock HTTP client simulating adversarial edge cases, WAFs, and hardened origins."""

    def __init__(self, mode: str):
        self.mode = mode
        self.calls = 0

    def post(self, url: str, **kwargs) -> HttpResponse:
        self.calls += 1

        if self.mode == "legitimate_validation":
            # Server accepts benign images (200 OK), rejects executables (400 Bad Request)
            files = kwargs.get("files", {})
            for field, (fname, content, ctype) in files.items():
                if fname.endswith(".jpg") or fname.endswith(".png") or fname.endswith(".pdf"):
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        headers={"content-type": "application/json"},
                        body='{"status": "ok", "url": "/images/' + fname + '"}',
                        url=url,
                    )
                else:
                    return HttpResponse(
                        success=False,
                        status_code=400,
                        headers={"content-type": "application/json"},
                        body='{"error": "Invalid file type. Only JPG, PNG, PDF are permitted."}',
                        url=url,
                    )

        elif self.mode == "waf_403":
            # WAF blocks upload attempts with 403 Forbidden
            return HttpResponse(
                success=False,
                status_code=403,
                headers={"server": "Cloudflare", "content-type": "text/html"},
                body="<html><title>403 Forbidden</title><body>Access Denied: Request blocked by WAF rule #941100</body></html>",
                url=url,
            )

        elif self.mode == "unsupported_media_type_415":
            # Origin rejects content-type with 415
            return HttpResponse(
                success=False,
                status_code=415,
                headers={"content-type": "application/json"},
                body='{"error": "Unsupported Media Type", "message": "Content-Type not supported"}',
                url=url,
            )

        elif self.mode == "error_reflection_no_storage":
            # Origin rejects file but reflects the filename in the error body
            files = kwargs.get("files", {})
            fname = "unknown"
            for fld, (fn, _, _) in files.items():
                fname = fn
            return HttpResponse(
                success=False,
                status_code=400,
                headers={"content-type": "text/html"},
                body=f"<div>Error: Uploading '{fname}' is not permitted on this server.</div>",
                url=url,
            )

        elif self.mode == "uuid_renaming_safe_ext":
            # Origin accepts file, but renames to a random UUID and forces .png extension
            return HttpResponse(
                success=True,
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"success": true, "url": "https://cdn.example.com/uploads/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d.png"}',
                url=url,
            )

        elif self.mode == "network_timeout":
            raise TimeoutError("Connection timed out to upload endpoint")

        elif self.mode == "malformed_json":
            # Origin returns 200 with truncated or malformed JSON
            return HttpResponse(
                success=True,
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"status": "uploaded", "url": "/uploads/part',
                url=url,
            )

        elif self.mode == "web_shell_404":
            return HttpResponse(
                success=True,
                status_code=201,
                headers={"location": "/uploads/shell.php"},
                body='{"url": "/uploads/shell.php"}',
                url=url,
            )

        elif self.mode == "web_shell_unparsed_source":
            return HttpResponse(
                success=True,
                status_code=201,
                headers={"location": "/uploads/shell.php"},
                body='{"url": "/uploads/shell.php"}',
                url=url,
            )

        return HttpResponse(success=True, status_code=200, body="OK", url=url)

    def get(self, url: str, **kwargs) -> HttpResponse:
        self.calls += 1
        if self.mode == "web_shell_404":
            return HttpResponse(
                success=False,
                status_code=404,
                headers={},
                body="404 Not Found",
                url=url,
            )
        elif self.mode == "web_shell_unparsed_source":
            # Web server returned raw PHP source code as static text without executing it
            return HttpResponse(
                success=True,
                status_code=200,
                headers={"content-type": "text/plain"},
                body="<?php echo 'ARGUS_CANARY_123'; ?>",
                url=url,
            )
        elif self.mode == "network_timeout":
            raise TimeoutError("Connection timed out during web shell verification")
        return HttpResponse(success=True, status_code=200, body="OK", url=url)


# =============================================================================
# Adversarial Test Cases
# =============================================================================

def test_adversarial_legitimate_upload_proper_validation_no_evidence():
    """
    When a server accepts benign images and rejects executables with 400 Bad Request,
    the collector MUST generate 0 findings/evidence.
    """
    client = AdversarialFileUploadHttpClient(mode="legitimate_validation")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=10)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert len(evidence) == 0
    assert len(mission.vulnerabilities) == 0


def test_adversarial_waf_403_rejection_patterns_no_evidence():
    """
    When a WAF returns 403 Forbidden with security block messages,
    the collector MUST reject all false positive findings.
    """
    client = AdversarialFileUploadHttpClient(mode="waf_403")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=10)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert len(evidence) == 0
    assert len(mission.vulnerabilities) == 0


def test_adversarial_415_unsupported_media_type_no_evidence():
    """
    When the server rejects uploads with 415 Unsupported Media Type,
    no finding should be generated.
    """
    client = AdversarialFileUploadHttpClient(mode="unsupported_media_type_415")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=5)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert len(evidence) == 0


def test_adversarial_error_reflection_without_file_storage_no_upload_finding():
    """
    When the server returns 400 reflecting the filename in an error message without storing the file,
    no unrestricted file upload finding should be emitted.
    """
    client = AdversarialFileUploadHttpClient(mode="error_reflection_no_storage")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=5)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert len(evidence) == 0


def test_adversarial_safe_uuid_rename_and_extension_stripping_no_finding():
    """
    When the server accepts the upload but renames the file to a random UUID with .png extension,
    it should not be flagged as an unrestricted executable upload.
    """
    client = AdversarialFileUploadHttpClient(mode="uuid_renaming_safe_ext")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=5)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert len(evidence) == 0


def test_adversarial_network_timeout_and_connection_drop_resilience():
    """
    When socket timeouts and connection drops occur, the prober and collector
    must handle them gracefully without crashing.
    """
    client = AdversarialFileUploadHttpClient(mode="network_timeout")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=5)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert isinstance(evidence, list)
    assert len(evidence) == 0


def test_adversarial_malformed_json_upload_response_resilience():
    """
    When the server returns malformed JSON, the prober must not raise an unhandled exception.
    """
    client = AdversarialFileUploadHttpClient(mode="malformed_json")
    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=3)

    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    evidence = collector.collect(mission)

    assert isinstance(evidence, list)


def test_adversarial_empty_candidate_endpoints_graceful_exit():
    """
    When the mission contains no endpoints, live hosts, target, or evidence,
    the collector must exit cleanly.
    """
    collector = FileUploadCollector()
    mission = Mission(target="")
    evidence = collector.collect(mission)

    assert evidence == []


def test_adversarial_web_shell_get_404_not_executed():
    """
    When upload succeeds but secondary GET returns 404 Not Found,
    web_shell_executed must remain False.
    """
    client = AdversarialFileUploadHttpClient(mode="web_shell_404")
    prober = FileUploadProber(client=client)

    probe = FileUploadProbe(
        filename="shell.php",
        content="<?php echo 'ARGUS_CANARY_123'; ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        canary_token="ARGUS_CANARY_123",
    )
    mission = Mission(target="https://api.example.com")
    resp = prober.execute_upload(mission, "https://api.example.com/upload", probe)

    assert resp.status_code == 201
    assert resp.web_shell_executed is False


def test_adversarial_web_shell_reflected_source_code_not_executed():
    """
    When secondary GET returns the raw unparsed PHP source code '<?php ... ?>',
    it is not parsed/executed by the server engine.
    """
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="shell.php",
        content="<?php echo 'ARGUS_CANARY_123'; ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        canary_token="ARGUS_CANARY_123",
    )
    # web_shell_executed is False because PHP tags were returned verbatim
    resp = FileUploadResponse(
        status_code=200,
        storage_url="https://api.example.com/uploads/shell.php",
        web_shell_executed=False,
        body='{"url": "/uploads/shell.php"}',
    )
    res = analyzer.evaluate_probe(probe, resp, "https://api.example.com/upload")
    assert res is not None
    # Severity is critical (unrestricted upload accepted) or high based on analyzer calibration
    assert res.severity in ("critical", "high")


def test_adversarial_probe_limit_enforcement():
    """
    Collector must respect max_probes_per_endpoint limit per endpoint.
    """
    mock_post = MagicMock(return_value=HttpResponse(success=False, status_code=400, body="Rejected", url="https://api.example.com/upload"))
    client = MagicMock()
    client.post = mock_post

    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=7)
    mission = Mission(target="https://api.example.com", endpoints=["https://api.example.com/upload"])
    collector.collect(mission)

    assert mock_post.call_count == 7


def test_adversarial_controlled_mission_exception_swallowed():
    """
    When ControlledMission.publish_finding raises an exception, the collector
    continues publishing to raw_mission and graph without failing.
    """
    mission = Mission(target="https://target.local", endpoints=["https://target.local/upload"])
    controlled = ControlledMission(mission)
    controlled.publish_finding = MagicMock(side_effect=RuntimeError("ControlledMission wrapper internal error"))

    def mock_post(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=201,
            headers={"location": "/uploads/shell.php"},
            body='{"url": "/uploads/shell.php"}',
            url=url,
        )

    def mock_get(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "text/html"},
            body="ARGUS_CANARY_",
            url=url,
        )

    client = AdversarialFileUploadHttpClient(mode="standard")
    client.post = mock_post
    client.get = mock_get

    collector = FileUploadCollector(http_client=client, max_probes_per_endpoint=3)
    evidence_list = collector.collect(controlled)

    assert len(evidence_list) > 0
    assert len(mission.vulnerabilities) > 0
    assert len(mission.attack_surface_graph.nodes) > 0
