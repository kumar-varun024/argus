from fastapi.testclient import TestClient
from argus.workspace.web.app import app
import sys
import traceback

client = TestClient(app)

try:
    response = client.get("/")
    print(f"Status: {response.status_code}")
    print(response.text)
except Exception as e:
    print("Exception occurred:")
    traceback.print_exc()
