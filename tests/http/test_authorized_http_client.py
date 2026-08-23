import pytest
import threading
import json
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager
from argus.authorization.scope import ScopeState
from argus.authorization.gate import AuthDecision, authorization_gate
from argus.http.client import AuthorizedHttpClient, HttpResponse, sanitize_url

# Find an available local port
def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

class MockHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/timeout":
            time.sleep(0.5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"timeout done")
            return
            
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=abcdef12345; Secure; HttpOnly")
        self.send_header("X-Custom-Header", "Hello")
        self.end_headers()
        
        response = {
            "message": "GET ok",
            "headers": {k: v for k, v in self.headers.items()}
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))
        
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        
        response = {
            "message": "POST ok",
            "body": body,
            "headers": {k: v for k, v in self.headers.items()}
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

@pytest.fixture(scope="module")
def mock_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), MockHttpHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()
    thread.join()

@pytest.fixture
def test_mission():
    mission = Mission(name="HTTP Test Mission", target="127.0.0.1")
    mission.scope = ["127.0.0.1"]
    mission_manager._active_missions[mission.id] = mission
    return mission

def test_in_scope_success(mock_server, test_mission):
    client = AuthorizedHttpClient()
    response = client.get(test_mission, f"{mock_server}/")
    
    assert response.success is True
    assert response.status_code == 200
    assert response.error is None
    assert response.scope_decision.decision == ScopeState.IN_SCOPE
    assert response.authorization_decision.allowed is True

def test_out_of_scope_blocked(mock_server, test_mission):
    # Change scope to exclude 127.0.0.1
    test_mission.scope = ["example.com"]
    client = AuthorizedHttpClient()
    response = client.get(test_mission, f"{mock_server}/")
    
    assert response.success is False
    assert response.status_code is None
    assert "Blocked by scope" in response.error
    assert response.scope_decision.decision == ScopeState.OUT_OF_SCOPE
    assert response.authorization_decision is None

def test_auth_denied_blocked(mock_server, test_mission):
    client = AuthorizedHttpClient()
    with patch.object(authorization_gate, "can_execute_action", return_value=AuthDecision(False, "Action policy block")):
        response = client.get(test_mission, f"{mock_server}/")
        
        assert response.success is False
        assert response.status_code is None
        assert "Blocked by authorization" in response.error
        assert response.authorization_decision.allowed is False

def test_get_works(mock_server, test_mission):
    client = AuthorizedHttpClient()
    response = client.get(test_mission, f"{mock_server}/")
    
    assert response.success is True
    body_data = json.loads(response.body)
    assert body_data["message"] == "GET ok"

def test_post_json_works(mock_server, test_mission):
    client = AuthorizedHttpClient()
    response = client.post(test_mission, f"{mock_server}/", json={"hello": "world"})
    
    assert response.success is True
    body_data = json.loads(response.body)
    assert body_data["message"] == "POST ok"
    sent_body = json.loads(body_data["body"])
    assert sent_body == {"hello": "world"}

def test_headers_and_cookies_sanitized(mock_server, test_mission):
    client = AuthorizedHttpClient()
    headers = {
        "Authorization": "Bearer super_secret_token",
        "Cookie": "session_id=12345",
        "X-Custom-Header": "not-secret"
    }
    response = client.get(test_mission, f"{mock_server}/", headers=headers)
    
    assert response.success is True
    
    # Check that HTTPResponse headers redact sensitive ones
    assert response.request_headers.get("Authorization") == "[REDACTED]"
    assert response.request_headers.get("Cookie") == "[REDACTED]"
    assert response.headers.get("set-cookie") == "[REDACTED]"
    assert response.headers.get("x-custom-header") == "Hello"
    
    # Check that evidence metadata has redacted headers
    assert len(test_mission.evidence) > 0
    evidence = test_mission.evidence.all()[-1]
    assert evidence.metadata["request_headers"].get("Authorization") == "[REDACTED]"
    assert evidence.metadata["request_headers"].get("Cookie") == "[REDACTED]"
    assert evidence.metadata["headers"].get("set-cookie") == "[REDACTED]"
    
    # Check that the server actually received the real headers (they were echoed back in GET ok JSON body)
    body_data = json.loads(response.body)
    assert body_data["headers"].get("Authorization") == "Bearer super_secret_token"
    assert body_data["headers"].get("Cookie") == "session_id=12345"

def test_timeout_handled(mock_server, test_mission):
    client = AuthorizedHttpClient()
    response = client.get(test_mission, f"{mock_server}/timeout", timeout=0.1)
    
    assert response.success is False
    assert "Timeout" in response.error

def test_connection_errors_handled(test_mission):
    client = AuthorizedHttpClient()
    # Port 65530 is likely unused and won't accept connection
    response = client.get(test_mission, "http://127.0.0.1:65530/")
    
    assert response.success is False
    assert "Connection error" in response.error

def test_evidence_created_correctly(mock_server, test_mission):
    test_mission.evidence.clear()
    client = AuthorizedHttpClient()
    client.post(test_mission, f"{mock_server}/", json={"test": "evidence"})
    
    assert len(test_mission.evidence) == 1
    evidence = test_mission.evidence.all()[0]
    
    assert evidence.mission_id == test_mission.id
    assert evidence.category == "HTTP Response"
    assert evidence.source == f"{mock_server}/"
    assert "HTTP POST to" in evidence.title
    assert "completed with status 200" in evidence.description
    assert evidence.status == "UNVERIFIED"
    assert evidence.confidence == 1.0
