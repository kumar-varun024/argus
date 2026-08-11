import os
import uuid
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from argus.workspace.models import Project, WorkspaceTask, Conversation
from argus.workspace.api import router, project_repo, task_repo
from fastapi import FastAPI

@pytest.fixture
def test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app

@pytest.fixture
def client(test_app) -> Generator:
    # Clear caches for isolated tests
    project_repo._cache.clear()
    task_repo._cache.clear()
    
    with TestClient(test_app) as c:
        yield c

def test_project_crud(client):
    headers = {"x-user-id": "test_user_1"}
    
    # Create Project
    res = client.post("/api/projects/", json={"name": "Alpha Project"}, headers=headers)
    assert res.status_code == 200
    p = res.json()
    assert p["name"] == "Alpha Project"
    assert p["user_id"] == "test_user_1"
    pid = p["project_id"]
    
    # Get Project
    res = client.get(f"/api/projects/{pid}", headers=headers)
    assert res.status_code == 200
    assert res.json()["name"] == "Alpha Project"
    
    # Update Project
    res = client.patch(f"/api/projects/{pid}", json={"name": "Beta Project"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["name"] == "Beta Project"
    
    # List Projects
    res = client.get("/api/projects/", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 1
    
    # Delete Project
    res = client.delete(f"/api/projects/{pid}", headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "archived"

def test_task_crud(client):
    headers = {"x-user-id": "test_user_1"}
    
    # Create Project
    p_res = client.post("/api/projects/", json={"name": "Project X"}, headers=headers)
    pid = p_res.json()["project_id"]
    
    # Create Task
    res = client.post(f"/api/projects/{pid}/tasks", json={"name": "Task 1"}, headers=headers)
    assert res.status_code == 200
    t = res.json()
    assert t["name"] == "Task 1"
    assert t["project_id"] == pid
    tid = t["task_id"]
    
    # Get Task
    res = client.get(f"/api/tasks/{tid}", headers=headers)
    assert res.status_code == 200
    assert res.json()["name"] == "Task 1"
    
    # List Tasks for Project
    res = client.get(f"/api/projects/{pid}/tasks", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 1
    
    # Update Task
    res = client.patch(f"/api/tasks/{tid}", json={"status": "completed"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "completed"

def test_authorization_isolation(client):
    headers1 = {"x-user-id": "user_a"}
    headers2 = {"x-user-id": "user_b"}
    
    # User A creates project
    res = client.post("/api/projects/", json={"name": "User A Project"}, headers=headers1)
    pid = res.json()["project_id"]
    
    # User B tries to read User A's project
    res = client.get(f"/api/projects/{pid}", headers=headers2)
    assert res.status_code == 404
    
    # User B tries to update User A's project
    res = client.patch(f"/api/projects/{pid}", json={"name": "Hacked"}, headers=headers2)
    assert res.status_code == 404
    
    # User B lists projects, shouldn't see A's
    res = client.get("/api/projects/", headers=headers2)
    assert len(res.json()) == 0
    
    # User A creates task
    res = client.post(f"/api/projects/{pid}/tasks", json={"name": "User A Task"}, headers=headers1)
    tid = res.json()["task_id"]
    
    # User B tries to read User A's task
    res = client.get(f"/api/tasks/{tid}", headers=headers2)
    assert res.status_code == 404
