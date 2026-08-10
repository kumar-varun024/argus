import datetime
from fastapi import APIRouter, HTTPException, Query, Path
from fastapi.responses import FileResponse
from typing import List, Optional
from pydantic import BaseModel

from argus.workspace.models import Conversation
from argus.workspace.repository import ConversationRepository
from argus.workspace.storage import AttachmentStorage
from argus.workspace.vision import VisionPipeline

router = APIRouter(prefix="/api", tags=["workspace"])
repository = ConversationRepository()
storage = AttachmentStorage()
vision = VisionPipeline()

class ConversationUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None # e.g., 'archived'

@router.get("/conversations/")
def list_conversations(
    user_id: str = None,
    include_archived: bool = False
):
    """List all conversations, optionally filtered by user."""
    return repository.search(user_id=user_id, include_archived=include_archived)

@router.post("/conversations/")
def create_conversation(conv: Conversation):
    """Create a new persistent conversation."""
    repository.save(conv)
    return conv

@router.get("/conversations/search")
def search_conversations(
    q: str = Query(...),
    user_id: str = None,
    include_archived: bool = False
):
    """Search conversations by title or message content."""
    return repository.search(query=q, user_id=user_id, include_archived=include_archived)

@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str = Path(...)):
    """Retrieve a specific conversation."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv

@router.patch("/conversations/{conversation_id}")
def update_conversation(conversation_id: str, update: ConversationUpdate):
    """Update conversation metadata (rename, archive)."""
    conv = repository.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
        
    if update.title is not None:
        conv.title = update.title
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
def delete_conversation(conversation_id: str):
    """Permanently delete a conversation."""
    if not repository.get(conversation_id):
        raise HTTPException(status_code=404, detail="Conversation not found")
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
    
    return evidence_manager.save(ev)

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

