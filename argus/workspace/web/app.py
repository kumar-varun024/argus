import os
import uuid
from typing import List
from fastapi import FastAPI, Request, Form, UploadFile, File, Query, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
import uvicorn

from argus.workspace.models import Conversation, ImageAttachment
from argus.workspace.engine import ConversationEngine
from argus.workspace.api import router as api_router, repository, storage, vision
from argus.workspace import huntOrchestrator
from argus.workspace.huntBridge import hunt_bridge

app = FastAPI(title="Argus Multimodal Workspace")
app.include_router(api_router)

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

engine = ConversationEngine(repository=repository)

from argus.runtime.manager import mission_manager

@app.get("/", response_class=HTMLResponse)
async def get_workspace(request: Request, cid: str = None):
    """Renders the main conversational workspace UI."""
    current_user = "local_user"
    if cid:
        conversation = repository.get(cid)
        if not conversation or conversation.user_id != current_user:
            return RedirectResponse(url="/")
    else:
        # Empty state dummy object to satisfy Jinja template without persisting
        conversation = Conversation(conversation_id="", title="New Conversation", user_id=current_user)
        
    if conversation.project_id:
        from argus.workspace.api import project_repo, task_repo
        p = project_repo.get(conversation.project_id)
        if p:
            conversation.current_context['project_name'] = p.name
        if conversation.task_id:
            t = task_repo.get(conversation.task_id)
            if t:
                conversation.current_context['task_name'] = t.name
                
    if conversation.mission_id:
        try:
            mission = mission_manager.get_mission(conversation.mission_id)
            conversation.current_context['mission_name'] = mission.name
            conversation.current_context['mission_target'] = mission.target
            conversation.current_context['mission_scope'] = ", ".join(mission.scope) if mission.scope else "Unconstrained Research"
            
            graph = getattr(mission, "graph", None)
            conversation.current_context['graph_available'] = True if graph and len(graph.all()) > 0 else False
            
            if conversation.investigation_id:
                inv = mission.investigations.get(conversation.investigation_id)
                if inv:
                    conversation.current_context['investigation_title'] = inv.title
                    
                # Fetch evidence and findings
                from argus.workspace.api import evidence_manager
                evidence_list = evidence_manager.get_by_investigation(conversation.investigation_id)
                conversation.current_context['evidence_count'] = len(evidence_list)
                
                # Assume status "USER_REVIEWED" or "CONFIRMED" is finding-worthy, or category = Finding
                # For now, let's just count all that are confirmed or user reviewed.
                findings_count = sum(1 for e in evidence_list if e.status in ["USER_REVIEWED", "CONFIRMED", "CORROBORATED"])
                conversation.current_context['findings_count'] = findings_count
        except Exception as e:
            pass
            
    return templates.TemplateResponse(
        request=request,
        name="workspace.html", 
        context={
            "request": request, 
            "conversation": conversation
        }
    )

@app.post("/chat", response_class=HTMLResponse)
async def post_chat(
    request: Request, 
    cid: str = Form(""),
    project_id: str = Form(""),
    task_id: str = Form(""),
    message: str = Form(...),
    images: List[UploadFile] = File(None)
):
    """Handles sending a message and optional image attachments."""
    current_user = "local_user"
    if cid:
        conversation = repository.get(cid)
        if not conversation or conversation.user_id != current_user:
            return RedirectResponse(url="/")
    else:
        conversation = Conversation(
            title="New Conversation", 
            user_id=current_user,
            project_id=project_id,
            task_id=task_id
        )
        repository.save(conversation)
        
    # Deduplicate: if the exact same message was just sent by the same user, ignore it.
    if conversation.messages:
        last_msg = conversation.messages[-1]
        # Check the last user message or the last AI message (if it's a double post, the last user message might be [-2])
        recent_user_msgs = [m for m in conversation.messages[-3:] if m.role == "user"]
        # Only deduplicate if there are no images
        has_images = images and any(img.filename for img in images)
        if recent_user_msgs and recent_user_msgs[-1].text == message and not has_images:
            import datetime
            last_time = datetime.datetime.fromisoformat(recent_user_msgs[-1].timestamp.replace("Z", ""))
            # If last_time is aware, strip tzinfo or use aware for both
            last_time = last_time.replace(tzinfo=None)
            if (datetime.datetime.utcnow() - last_time).total_seconds() < 5:
                return RedirectResponse(url=f"/?cid={conversation.conversation_id}", status_code=303)
                
    attachments = []
    
    if images:
        for img in images:
            if img and img.filename:
                # Save securely
                image_id = str(uuid.uuid4())
                meta = storage.save_upload(img, image_id)
                
                attachment = ImageAttachment(
                    image_id=image_id,
                    filename=meta["filename"],
                    mime_type=meta["mime_type"],
                    size=meta["size"],
                    storage_reference=meta["storage_reference"]
                )
                
                # Analyze via Vision Pipeline
                attachment = vision.analyze(attachment)
                
                attachments.append(attachment)
        
    # Process user message
    engine.add_user_message(conversation, message, attachments)
    
    # Process AI response
    engine.generate_response(conversation)
    
    # PERSISTENCE: Actually save the conversation!
    import datetime
    conversation.last_message_at = datetime.datetime.utcnow().isoformat()
    repository.save(conversation)
    
    # Redirect to the persistent URL
    return RedirectResponse(url=f"/?cid={conversation.conversation_id}", status_code=303)

@app.post("/chat/stream")
async def post_chat_stream(
    request: Request,
    cid: str = Form(""),
    project_id: str = Form(""),
    task_id: str = Form(""),
    message: str = Form(...),
    images: List[UploadFile] = File(None)
):
    """Handles sending a message and streaming the AI response."""
    current_user = "local_user"
    if cid:
        from argus.workspace.api import repository
        conversation = repository.get(cid)
        if not conversation or conversation.user_id != current_user:
            raise HTTPException(status_code=403, detail="Unauthorized")
    else:
        from argus.workspace.api import repository
        conversation = Conversation(
            title="New Conversation", 
            user_id=current_user,
            project_id=project_id,
            task_id=task_id
        )
        repository.save(conversation)
        
    attachments = []
    
    if images:
        for img in images:
            if img and img.filename:
                # Save securely
                image_id = str(uuid.uuid4())
                meta = storage.save_upload(img, image_id)
                
                attachment = ImageAttachment(
                    image_id=image_id,
                    filename=meta["filename"],
                    mime_type=meta["mime_type"],
                    size=meta["size"],
                    storage_reference=meta["storage_reference"]
                )
                
                # Analyze via Vision Pipeline
                attachment = vision.analyze(attachment)
                
                attachments.append(attachment)
                
    # Process user message
    engine.add_user_message(conversation, message, attachments)
    
    return StreamingResponse(
        engine.generate_response_stream(conversation), 
        media_type="text/event-stream",
        headers={"X-Conversation-Id": conversation.conversation_id}
    )

@app.get("/api/provider/status")
def get_provider_status():
    """Returns the safe status of the configured AI provider."""
    provider = engine.provider
    return {
        "provider": provider.__class__.__name__.replace("Provider", "").replace("Model", "").replace("Compatible", "").lower(),
        "model": provider.model_name(),
        "configured": True
    }

@app.post("/hunt/propose")
async def post_hunt_propose(cid: str = Form(""), message: str = Form(...)):
    """Classify a chat message: if it's a hunt command, return an approval-card
    proposal (scope decision + single-use nonce); otherwise {is_hunt: false}."""
    current_user = "local_user"
    mission_id = ""
    if cid:
        conversation = repository.get(cid)
        if conversation and conversation.user_id == current_user:
            mission_id = conversation.mission_id or ""
    proposal = huntOrchestrator.maybeProposeHunt(message, mission_id, current_user, bridge=hunt_bridge)
    if proposal is None:
        return JSONResponse({"is_hunt": False})
    return JSONResponse(huntOrchestrator.proposalToDict(proposal))


@app.post("/hunt/confirm")
async def post_hunt_confirm(nonce: str = Form(...)):
    """Consume a confirmation nonce and dispatch the hunt (authorization is
    re-verified inside the bridge). Returns the started mission id."""
    dispatch = hunt_bridge.confirmHunt(nonce, "local_user")
    return JSONResponse(huntOrchestrator.dispatchToDict(dispatch))


@app.get("/hunt/stream/{mission_id}")
async def get_hunt_stream(mission_id: str, request: Request):
    """Server-Sent Events stream of one mission's live lifecycle events."""
    return StreamingResponse(
        huntOrchestrator.streamMissionEvents(mission_id, request=request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Starts the Uvicorn web server for the workspace."""
    uvicorn.run(app, host=host, port=port)
