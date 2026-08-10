import os
import uuid
from fastapi import FastAPI, Request, Form, UploadFile, File, Query, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

from argus.workspace.models import Conversation, ImageAttachment
from argus.workspace.engine import ConversationEngine
from argus.workspace.api import router as api_router
from argus.workspace.repository import ConversationRepository
from argus.workspace.storage import AttachmentStorage
from argus.workspace.vision import VisionPipeline

app = FastAPI(title="Argus Multimodal Workspace")
app.include_router(api_router)

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

engine = ConversationEngine()
repository = ConversationRepository()
storage = AttachmentStorage()
vision = VisionPipeline()

@app.get("/", response_class=HTMLResponse)
async def get_workspace(request: Request, cid: str = None):
    """Renders the main conversational workspace UI."""
    if cid:
        conversation = repository.get(cid)
        if not conversation:
            return RedirectResponse(url="/")
    else:
        # For simplicity, if no ID provided, just create a new one but don't save until message sent
        conversation = Conversation(title="New Conversation")
        
    return templates.TemplateResponse("workspace.html", {
        "request": request, 
        "conversation": conversation
    })

@app.post("/chat", response_class=HTMLResponse)
async def post_chat(
    request: Request, 
    cid: str = Form(""),
    message: str = Form(...),
    image: UploadFile = File(None)
):
    """Handles sending a message and optional image attachment."""
    if cid:
        conversation = repository.get(cid)
        if not conversation:
            conversation = Conversation(conversation_id=cid, title="New Conversation")
    else:
        conversation = Conversation(title="New Conversation")
        
    attachments = []
    
    if image and image.filename:
        # Save securely
        image_id = str(uuid.uuid4())
        meta = storage.save_upload(image, image_id)
        
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
    
    # Redirect to the persistent URL
    return RedirectResponse(url=f"/?cid={conversation.conversation_id}", status_code=303)

def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Starts the Uvicorn web server for the workspace."""
    uvicorn.run(app, host=host, port=port)
