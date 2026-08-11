import datetime
from fastapi import APIRouter, HTTPException, Query, Path, Header, Depends
from fastapi.responses import FileResponse
from typing import List, Optional
from pydantic import BaseModel

def get_current_user(x_user_id: str = Header("local_user")) -> str:
    return x_user_id

from argus.workspace.models import Conversation, Project, WorkspaceTask
from argus.workspace.repository import ConversationRepository, ProjectRepository, WorkspaceTaskRepository
from argus.workspace.storage import AttachmentStorage
from argus.workspace.vision import VisionPipeline

router = APIRouter(prefix="/api", tags=["workspace"])
repository = ConversationRepository()
project_repo = ProjectRepository()
task_repo = WorkspaceTaskRepository()
storage = AttachmentStorage()
vision = VisionPipeline()

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class TaskUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class ConversationUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None # e.g., 'archived'
    project_id: Optional[str] = None
    task_id: Optional[str] = None

# --- PROJECTS ---

@router.get("/projects/")
def list_projects(user_id: str = Depends(get_current_user)):
    return project_repo.search(user_id=user_id)

@router.post("/projects/")
def create_project(project: Project, user_id: str = Depends(get_current_user)):
    project.user_id = user_id
    project_repo.save(project)
    return project

@router.get("/projects/{project_id}")
def get_project(project_id: str, user_id: str = Depends(get_current_user)):
    p = project_repo.get(project_id)
    if not p or p.user_id != user_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return p

@router.patch("/projects/{project_id}")
def update_project(project_id: str, update: ProjectUpdate, user_id: str = Depends(get_current_user)):
    p = project_repo.get(project_id)
    if not p or p.user_id != user_id:
        raise HTTPException(status_code=404, detail="Project not found")
    if update.name is not None:
        p.name = update.name
    if update.description is not None:
        p.description = update.description
    if update.status is not None:
        p.status = update.status
    p.updated_at = datetime.datetime.utcnow().isoformat()
    project_repo.save(p)
    return p

@router.delete("/projects/{project_id}")
def delete_project(project_id: str, user_id: str = Depends(get_current_user)):
    p = project_repo.get(project_id)
    if not p or p.user_id != user_id:
        raise HTTPException(status_code=404, detail="Project not found")
    # Soft delete / archive to avoid cascade issues unless explicitly implemented
    p.status = "archived"
    project_repo.save(p)
    return {"status": "archived"}

# --- TASKS ---

@router.get("/projects/{project_id}/tasks")
def list_tasks_for_project(project_id: str, user_id: str = Depends(get_current_user)):
    # Verify project auth
    p = project_repo.get(project_id)
    if not p or p.user_id != user_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return task_repo.search(project_id=project_id, user_id=user_id)

@router.post("/projects/{project_id}/tasks")
def create_task(project_id: str, task: WorkspaceTask, user_id: str = Depends(get_current_user)):
    p = project_repo.get(project_id)
    if not p or p.user_id != user_id:
        raise HTTPException(status_code=404, detail="Project not found")
    task.project_id = project_id
    task.user_id = user_id
    task_repo.save(task)
    return task

@router.get("/tasks/{task_id}")
def get_task(task_id: str, user_id: str = Depends(get_current_user)):
    t = task_repo.get(task_id)
    if not t or t.user_id != user_id:
        raise HTTPException(status_code=404, detail="Task not found")
    return t

@router.patch("/tasks/{task_id}")
def update_task(task_id: str, update: TaskUpdate, user_id: str = Depends(get_current_user)):
    t = task_repo.get(task_id)
    if not t or t.user_id != user_id:
        raise HTTPException(status_code=404, detail="Task not found")
    if update.name is not None:
        t.name = update.name
    if update.description is not None:
        t.description = update.description
    if update.status is not None:
        t.status = update.status
    t.updated_at = datetime.datetime.utcnow().isoformat()
    task_repo.save(t)
    return t

@router.delete("/tasks/{task_id}")
def delete_task(task_id: str, user_id: str = Depends(get_current_user)):
    t = task_repo.get(task_id)
    if not t or t.user_id != user_id:
        raise HTTPException(status_code=404, detail="Task not found")
    t.status = "archived"
    task_repo.save(t)
    return {"status": "archived"}

@router.get("/conversations/")
def list_conversations(
    user_id: str = Depends(get_current_user),
    include_archived: bool = False
):
    """List all conversations, optionally filtered by user."""
    return repository.search(user_id=user_id, include_archived=include_archived)

@router.post("/conversations/")
def create_conversation(conv: Optional[Conversation] = None, user_id: str = Depends(get_current_user)):
    """Create a new persistent conversation."""
    if not conv:
        conv = Conversation(title="New Conversation")
    conv.user_id = user_id
    repository.save(conv)
    return conv

@router.get("/conversations/search")
def search_conversations(
    q: str = Query(None),
    project_id: str = Query(None),
    task_id: str = Query(None),
    user_id: str = Depends(get_current_user),
    include_archived: bool = False
):
    """Search conversations by title or message content."""
    return repository.search(query=q, user_id=user_id, project_id=project_id, task_id=task_id, include_archived=include_archived)

@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str = Path(...), user_id: str = Depends(get_current_user)):
    """Retrieve a specific conversation."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if conv.user_id != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to conversation")
    return conv

@router.patch("/conversations/{conversation_id}")
def update_conversation(conversation_id: str, update: ConversationUpdate, user_id: str = Depends(get_current_user)):
    """Update conversation metadata (rename, archive)."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if conv.user_id != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to conversation")
        
    if update.title is not None:
        conv.title = update.title
    if update.project_id is not None:
        conv.project_id = update.project_id
    if update.task_id is not None:
        conv.task_id = update.task_id
    if update.status is not None:
        conv.status = update.status
        if update.status == "archived":
            conv.archived_at = datetime.datetime.utcnow().isoformat()
        else:
            conv.archived_at = None
            
    conv.updated_at = datetime.datetime.utcnow().isoformat()
    repository.save(conv)
    return conv

@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, user_id: str = Depends(get_current_user)):
    """Permanently delete a conversation."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if conv.user_id != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to conversation")
    repository.delete(conversation_id)
    return {"status": "deleted"}

# --- ATTACHMENTS ---

@router.get("/attachments/{attachment_id}")
def get_attachment(attachment_id: str, cid: str = Query(None)):
    """Serves the binary image file. In a real app, this verifies `cid` auth."""
    # Find the attachment in the repo to get the storage_reference
    if not cid:
        raise HTTPException(status_code=400, detail="Missing conversation ID for auth")
    
    conv = repository.get(cid)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
        
    target_att = None
    for msg in conv.messages:
        for att in msg.attachments:
            if att.image_id == attachment_id:
                target_att = att
                break
        if target_att: break
        
    if not target_att:
        raise HTTPException(status_code=404, detail="Attachment not found in conversation")
        
    if not target_att.storage_reference:
        raise HTTPException(status_code=404, detail="Attachment has no storage reference")
        
    try:
        path = storage.get_path(target_att.storage_reference)
        return FileResponse(path, media_type=target_att.mime_type)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File on disk not found")

@router.post("/attachments/{attachment_id}/analyze")
def analyze_attachment(attachment_id: str, cid: str = Query(...)):
    """Triggers or retries the vision analysis pipeline for an attachment."""
    conv = repository.get(cid)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
        
    target_att = None
    for msg in conv.messages:
        for att in msg.attachments:
            if att.image_id == attachment_id:
                target_att = att
                break
        if target_att: break
        
    if not target_att:
        raise HTTPException(status_code=404, detail="Attachment not found")
        
    # Run vision pipeline
    target_att = vision.analyze(target_att)
    
    # Save conversation state
    repository.save(conv)
    return target_att

# --- EVIDENCE ---

from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.manager import EvidenceManager

evidence_manager = EvidenceManager()

class EvidenceCreate(BaseModel):
    title: str
    description: str
    category: str
    source_type: str = "SCREENSHOT"
    source_id: str
    conversation_id: str
    message_id: str
    observation_id: str
    original_ai_description: str
    investigation_id: str = ""

@router.post("/evidence")
def create_evidence(req: EvidenceCreate):
    """Promotes an observation into Evidence."""
    corrected = req.description != req.original_ai_description
    
    prov = ProvenanceData(
        conversation_id=req.conversation_id,
        message_id=req.message_id,
        image_id=req.source_id,
        observation_id=req.observation_id,
        original_ai_description=req.original_ai_description,
        corrected_by_user=corrected
    )
    
    ev = Evidence(
        title=req.title,
        description=req.description,
        category=req.category,
        source_type=req.source_type,
        source_id=req.source_id,
        investigation_id=req.investigation_id,
        created_by="USER_PROVIDED" if corrected else "AI_DERIVED",
        status="USER_REVIEWED",
        provenance=prov
    )
    
    saved_ev = evidence_manager.save(ev)
    
    try:
        conv = repository.get(req.conversation_id)
        if conv:
            _extract_and_ingest_graph(saved_ev, req, conv)
    except Exception as e:
        print(f"Graph ingestion failed: {e}")
        
    return saved_ev

@router.get("/investigations/{investigation_id}/evidence")
def get_investigation_evidence(investigation_id: str):
    """Returns all evidence for an investigation."""
    return evidence_manager.get_by_investigation(investigation_id)

@router.patch("/evidence/{evidence_id}/review")
def review_evidence(evidence_id: str, new_description: str = Query(...)):
    """Updates evidence description (user correction)."""
    ev = evidence_manager.get(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
        
    ev.description = new_description
    ev.provenance.corrected_by_user = True
    ev.created_by = "USER_PROVIDED"
    ev.status = "USER_REVIEWED"
    
    return evidence_manager.save(ev)

# --- MISSION / CONVERSATION INTEGRATION ---

class InvestigationSwitchRequest(BaseModel):
    investigation_id: str

@router.get("/missions/{mission_id}/conversations")
def get_mission_conversations(mission_id: str):
    """List conversations belonging to a mission."""
    all_convs = repository.search(user_id=None, include_archived=True)
    return [c for c in all_convs if getattr(c, 'mission_id', '') == mission_id]

@router.post("/missions/{mission_id}/conversations")
def create_mission_conversation(mission_id: str, conv: Conversation):
    """Create a new conversation for a mission."""
    conv.mission_id = mission_id
    repository.save(conv)
    return conv

@router.post("/conversations/{conversation_id}/switch-investigation")
def switch_investigation(conversation_id: str, req: InvestigationSwitchRequest):
    """Switches the active investigation for a conversation."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    conv.investigation_id = req.investigation_id
    conv.updated_at = datetime.datetime.utcnow().isoformat()
    repository.save(conv)
    return conv

# --- GRAPH INTEGRATION ---

import re
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.runtime.manager import mission_manager
from argus.graph.builder import KnowledgeGraphBuilder

def _extract_and_ingest_graph(ev: Evidence, req: EvidenceCreate, conversation: Conversation):
    if not conversation.mission_id:
        return
        
    mission = mission_manager.get_mission(conversation.mission_id)
    if not mission: return
    
    graph = getattr(mission, "graph", None)
    if not graph:
        KnowledgeGraphBuilder().build(mission)
        graph = mission.graph
        
    status = "USER_CONFIRMED" if ev.created_by == "USER_PROVIDED" else "AI_INFERRED"
    
    text = f"{ev.title} {ev.description}"
    
    # 1. Endpoint extraction
    endpoints = re.findall(r"(?:GET|POST|PUT|DELETE|PATCH)?\s*(/[a-zA-Z0-9_\-\./]+)", text)
    # 2. URLs
    urls = re.findall(r"https?://[a-zA-Z0-9_\-\.]+", text)
    
    ev_node_id = f"ev_{ev.id}"
    ev_node = graph.get(ev_node_id)
    if not ev_node:
        ev_node = Node(id=ev_node_id, type="Evidence", value=ev.title, metadata={"evidence_id": ev.id})
        graph.add(ev_node)
        
    for ep in set(endpoints):
        ep = ep.strip()
        if len(ep) < 2: continue
        ep_id = f"ep_{ep}"
        ep_node = graph.get(ep_id)
        if not ep_node:
            ep_node = Node(id=ep_id, type="Endpoint", value=ep)
            graph.add(ep_node)
            
        graph.connect(ep_id, ev_node_id, "OBSERVED_IN", metadata={"status": status, "provenance": f"conv_{req.conversation_id}"})
        
    for url in set(urls):
        url_id = f"url_{url}"
        url_node = graph.get(url_id)
        if not url_node:
            url_node = Node(id=url_id, type="URL", value=url)
            graph.add(url_node)
            
        graph.connect(url_id, ev_node_id, "OBSERVED_IN", metadata={"status": status, "provenance": f"conv_{req.conversation_id}"})

@router.get("/investigations/{investigation_id}/graph")
def get_investigation_graph(investigation_id: str, mission_id: str = Query(...)):
    """Returns the graph nodes and edges for visualization."""
    mission = mission_manager.get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
        
    graph = getattr(mission, "graph", None)
    if not graph:
        return {"nodes": [], "edges": []}
        
    nodes = [{"id": n.id, "label": n.value, "group": n.type} for n in graph.all()]
    edges = [{"from": e.source, "to": e.target, "label": e.type, "title": e.metadata.get("status", "")} for e in graph.edges]
    return {"nodes": nodes, "edges": edges}

@router.post("/graph/entities/{edge_id}/review")
def review_graph_relationship(edge_id: str, action: str = Query(...)): # action = accept/reject
    # In a real app we'd identify the exact edge. 
    # For now, this is a stub for the planner's capability.
    return {"status": f"Edge {edge_id} {action}ed"}

# --- AUTHORIZATION & SCOPE ---

@router.get("/missions/{mission_id}/scope")
def get_mission_scope(mission_id: str):
    """Returns the active scope rules for a mission."""
    mission = mission_manager.get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    return {"scope": mission.scope}

@router.post("/missions/{mission_id}/scope/check")
def check_mission_scope(mission_id: str, target: str = Query(...)):
    """Checks if a target is authorized under the mission scope."""
    from argus.authorization.scope import ScopeResolver
    decision = ScopeResolver().check_scope(target, mission_id)
    return {
        "target": decision.target,
        "decision": decision.decision.value,
        "matched_rule": decision.matched_rule,
        "explanation": ScopeResolver().explain_scope_decision(decision)
    }

@router.get("/missions/{mission_id}/permissions")
def get_mission_permissions(mission_id: str, user_id: str = "system_user"):
    """Returns permission state for the current user."""
    from argus.authorization.gate import authorization_gate
    perm = authorization_gate.can_access_mission(user_id, mission_id)
    return {"allowed": perm.allowed, "reason": perm.reason}

@router.post("/missions/{mission_id}/authorize-action")
def authorize_mission_action(mission_id: str, action: str = Query(...), target: str = Query(...), user_id: str = "system_user"):
    """Centralized authorization gate for taking actions on targets."""
    from argus.authorization.gate import authorization_gate
    auth = authorization_gate.can_execute_action(user_id, action, target, mission_id)
    scope_data = None
    if auth.scope_decision:
        scope_data = {
            "decision": auth.scope_decision.decision.value,
            "matched_rule": auth.scope_decision.matched_rule
        }
    return {
        "allowed": auth.allowed,
        "reason": auth.reason,
        "scope": scope_data
    }

# --- ORCHESTRATION WORKFLOW ---

from argus.orchestration.orchestrator import ResearchWorkflowOrchestrator
from argus.orchestration.models import ResearchStep
from argus.orchestration.planner import WorkflowPlanner

orchestrator = ResearchWorkflowOrchestrator()
workflow_planner = WorkflowPlanner()

@router.get("/investigations/{investigation_id}/workflow")
def get_workflow(investigation_id: str, mission_id: str = Query(...)):
    """Returns the active workflow for an investigation, or creates one if it doesn't exist."""
    # Find existing workflow
    for wf in orchestrator._workflows.values():
        if wf.investigation_id == investigation_id:
            return wf
            
    # Create new
    return orchestrator.create_workflow(investigation_id, mission_id)

@router.post("/investigations/{investigation_id}/workflow/plan")
def plan_workflow_steps(investigation_id: str, mission_id: str = Query(...)):
    """Plans the next logical steps for an investigation."""
    wf = get_workflow(investigation_id, mission_id)
    steps = workflow_planner.generate_candidate_steps(investigation_id)
    ranked = workflow_planner.rank_candidate_steps(steps)
    
    # Just take top 1 for now
    if ranked:
        orchestrator.plan_next_step(wf.id, ranked[0])
    
    return wf

@router.post("/workflow/steps/{step_id}/execute")
def execute_workflow_step(step_id: str, workflow_id: str = Query(...), user_id: str = "system_user"):
    return orchestrator.execute_step(workflow_id, step_id, user_id)

@router.post("/workflow/steps/{step_id}/pause")
def pause_workflow(step_id: str, workflow_id: str = Query(...)):
    wf = orchestrator.get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    wf.is_paused = True
    orchestrator._record_event(wf, "WORKFLOW_PAUSED", f"Workflow paused at step {step_id}")
    return wf

@router.post("/workflow/steps/{step_id}/resume")
def resume_workflow(step_id: str, workflow_id: str = Query(...)):
    wf = orchestrator.get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    wf.is_paused = False
    orchestrator._record_event(wf, "WORKFLOW_RESUMED", f"Workflow resumed at step {step_id}")
    return wf

@router.get("/workflow/{workflow_id}/timeline")
def get_workflow_timeline(workflow_id: str):
    wf = orchestrator.get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf.events

