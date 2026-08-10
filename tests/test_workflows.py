import pytest
from argus.intelligence.models import APIEndpoint
from argus.intelligence.business_models import BusinessObject
from argus.workflows.builder import WorkflowBuilder
from argus.workflows.models import Workflow, WorkflowStep
from argus.core.mission import Mission
import json
import dataclasses

def test_auth_workflow_detection():
    endpoints = [
        APIEndpoint(method="POST", path="/api/v1/login", resource="login", operation="login"),
        APIEndpoint(method="POST", path="/api/v1/auth/token", resource="auth", operation="token")
    ]
    
    builder = WorkflowBuilder(endpoints=endpoints, business_objects=[])
    workflows = builder.build()
    
    assert len(workflows) == 1
    wf = workflows[0]
    assert wf.name == "Authentication"
    assert len(wf.steps) == 2
    assert wf.entry_points[0] == "/api/v1/login"
    assert wf.confidence == 0.8

def test_workflow_dependencies():
    endpoints = [
        APIEndpoint(method="POST", path="/api/v1/register", resource="register", operation="register"),
        APIEndpoint(method="POST", path="/api/v1/login", resource="login", operation="login"),
        APIEndpoint(method="POST", path="/api/v1/orgs", resource="orgs", operation="create", business_object="Organization"),
        APIEndpoint(method="GET", path="/api/v1/billing/invoices", resource="billing", operation="list", business_object="Invoice")
    ]
    
    bo = [
        BusinessObject(name="Organization"),
        BusinessObject(name="Invoice")
    ]
    
    builder = WorkflowBuilder(endpoints=endpoints, business_objects=bo)
    workflows = builder.build()
    
    assert len(workflows) == 4
    
    names_to_wfs = {w.name: w for w in workflows}
    
    assert "Registration" in names_to_wfs
    assert "Authentication" in names_to_wfs
    assert "Organization Management" in names_to_wfs
    assert "Billing" in names_to_wfs
    
    # Check dependencies
    auth_wf = names_to_wfs["Authentication"]
    org_wf = names_to_wfs["Organization Management"]
    billing_wf = names_to_wfs["Billing"]
    
    assert names_to_wfs["Registration"].id in auth_wf.dependencies
    assert auth_wf.id in org_wf.dependencies
    assert org_wf.id in billing_wf.dependencies

def test_business_object_extraction():
    endpoints = [
        APIEndpoint(method="POST", path="/api/v1/orgs", resource="orgs", operation="create", business_object="Organization"),
    ]
    
    builder = WorkflowBuilder(endpoints=endpoints, business_objects=[])
    workflows = builder.build()
    
    assert len(workflows) == 1
    wf = workflows[0]
    assert "Organization" in wf.business_objects

def test_step_ordering():
    endpoints = [
        APIEndpoint(method="DELETE", path="/api/v1/users/1", resource="users", operation="delete"),
        APIEndpoint(method="GET", path="/api/v1/users", resource="users", operation="list"),
        APIEndpoint(method="POST", path="/api/v1/users", resource="users", operation="create"),
        APIEndpoint(method="PUT", path="/api/v1/users/1", resource="users", operation="update"),
    ]
    
    builder = WorkflowBuilder(endpoints=endpoints, business_objects=[])
    wfs = builder.build()
    # It should detect a general CRUD flow grouped by endpoint structure or just general if BO is present
    # Oh wait, we only generate general CRUD if a business object is present.
    # Let's add business object
    
    endpoints_bo = [
        APIEndpoint(method="DELETE", path="/api/v1/users/1", resource="users", operation="delete", business_object="User"),
        APIEndpoint(method="GET", path="/api/v1/users", resource="users", operation="list", business_object="User"),
        APIEndpoint(method="POST", path="/api/v1/users", resource="users", operation="create", business_object="User"),
        APIEndpoint(method="PUT", path="/api/v1/users/1", resource="users", operation="update", business_object="User"),
    ]
    builder2 = WorkflowBuilder(endpoints=endpoints_bo, business_objects=[BusinessObject(name="User")])
    wfs = builder2.build()
    
    assert len(wfs) == 1
    wf = wfs[0]
    assert wf.name == "User Management"
    assert len(wf.steps) == 4
    
    # POST -> GET -> PUT -> DELETE
    assert wf.steps[0].http_method == "POST"
    assert wf.steps[1].http_method == "GET"
    assert wf.steps[2].http_method == "PUT"
    assert wf.steps[3].http_method == "DELETE"
    
    # Check ordering links
    assert wf.steps[1].previous_steps[0] == wf.steps[0].id
    assert wf.steps[1].next_steps[0] == wf.steps[2].id

def test_authorization_attachment():
    endpoints = [
        APIEndpoint(method="POST", path="/api/admin/users", resource="users", operation="create", business_object="User"),
        APIEndpoint(method="GET", path="/api/admin/users", resource="users", operation="list", business_object="User"),
    ]
    builder = WorkflowBuilder(endpoints=endpoints, business_objects=[BusinessObject(name="User")])
    wfs = builder.build()
    
    assert len(wfs) == 1
    wf = wfs[0]
    assert wf.steps[0].required_role == "Admin"
    assert "Admin" in wf.roles

def test_mission_integration():
    mission = Mission(target="test")
    mission.endpoints = [
        dataclasses.asdict(APIEndpoint(method="POST", path="/login", resource="login", operation="login"))
    ]
    builder = WorkflowBuilder(mission=mission)
    wfs = builder.build()
    
    assert len(wfs) == 1
    assert len(mission.workflows) == 1
    assert mission.workflows[0].name == "Authentication"
