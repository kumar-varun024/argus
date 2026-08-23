import pytest
import threading
import socket
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

from argus.runtime.mission import Mission, GraphQLState
from argus.runtime.manager import mission_manager
from argus.plugins.graphql.schema import GraphQLSchemaAnalyzer
from argus.plugins.graphql.models import GraphQLEndpoint

def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

class LocalGraphQLHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        
        try:
            req_data = json.loads(body)
            query = req_data.get("query", "")
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Bad Request")
            return
            
        if "__schema" not in query:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Only introspection supported")
            return
            
        response = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "getProfile",
                                    "type": {
                                        "kind": "OBJECT",
                                        "name": "Profile"
                                    },
                                    "args": []
                                }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Profile",
                            "fields": [
                                {
                                    "name": "name",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String"
                                        }
                                    }
                                },
                                {
                                    "name": "age",
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Int"
                                    }
                                }
                            ]
                        },
                        {
                            "kind": "ENUM",
                            "name": "UserRole",
                            "enumValues": [
                                {"name": "ADMIN"},
                                {"name": "USER"}
                            ]
                        }
                    ]
                }
            }
        }
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

@pytest.fixture(scope="module")
def local_graphql_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), LocalGraphQLHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}/graphql"
    server.shutdown()
    server.server_close()
    thread.join()

def test_graphql_http_integration(local_graphql_server):
    mission = Mission(name="GraphQL Integration Mission", target="127.0.0.1")
    mission.scope = ["127.0.0.1"]
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url=local_graphql_server))
    
    mission_manager._active_missions[mission.id] = mission
    
    analyzer = GraphQLSchemaAnalyzer()
    schema = analyzer.analyze(mission)
    
    assert schema is not None
    assert schema.source == "Introspection"
    
    assert "Profile" in schema.types
    profile_type = schema.types["Profile"]
    assert profile_type.kind == "OBJECT"
    
    assert "name" in profile_type.fields
    assert profile_type.fields["name"].type == "String!"
    assert profile_type.fields["name"].is_required is True
    
    assert "age" in profile_type.fields
    assert profile_type.fields["age"].type == "Int"
    assert profile_type.fields["age"].is_required is False
    
    assert "UserRole" in schema.enums
    assert "ADMIN" in schema.enums["UserRole"].values
    assert "USER" in schema.enums["UserRole"].values
    
    assert "getProfile" in schema.queries
    assert schema.queries["getProfile"].return_type == "Profile"
    
    assert len(mission.evidence) > 0
    ev = mission.evidence.all()[-1]
    assert ev.category == "HTTP Response"
    assert ev.source == local_graphql_server
    assert "__schema" in ev.value
    assert ev.mission_id == mission.id
