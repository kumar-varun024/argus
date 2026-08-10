import json
import os
import dataclasses
from pathlib import Path
from typing import List, Optional, Dict, Any
from argus.workspace.models import Conversation

class ConversationRepository:
    """Handles JSON-based persistence of workspace conversations with fast in-memory indexing."""
    
    def __init__(self, data_dir: str = "~/.argus/workspace/conversations"):
        self.data_dir = Path(os.path.expanduser(data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory indexes for fast queries without scanning all files
        self._cache: Dict[str, Conversation] = {}
        self._user_index: Dict[str, set] = {}
        self._mission_index: Dict[str, set] = {}
        self._project_index: Dict[str, set] = {}
        
        self._load_all()
        
    def _load_all(self):
        """Loads all conversations from the filesystem into memory indexes."""
        self._cache.clear()
        self._user_index.clear()
        self._mission_index.clear()
        self._project_index.clear()
        
        for file_path in self.data_dir.glob("*.json"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                    # Convert dicts back to Message/Attachment objects could be complex, 
                    # but pydantic or manual decoding works. 
                    # For standard dataclasses:
                    # The prompt didn't specify strict dict-to-dataclass hydration logic,
                    # but we will assume naive initialization works or we can just keep them as dicts if needed.
                    # Since we use dataclasses, let's inject them directly for now, or just use the model kwargs.
                    
                    # Simplistic hydration (ignores nested lists mapping for brevity, but let's assume it's acceptable for JSON)
                    from argus.workspace.models import Message, ImageAttachment, ContextReference
                    
                    messages_data = data.pop("messages", [])
                    messages = []
                    for msg_d in messages_data:
                        atts = [ImageAttachment(**a) for a in msg_d.pop("attachments", [])]
                        refs = [ContextReference(**r) for r in msg_d.pop("references", [])]
                        messages.append(Message(**msg_d, attachments=atts, references=refs))
                        
                    conv = Conversation(**data, messages=messages)
                    self._add_to_index(conv)
            except Exception as e:
                pass # Skip malformed
                
    def _add_to_index(self, conv: Conversation):
        self._cache[conv.conversation_id] = conv
        
        if conv.user_id:
            self._user_index.setdefault(conv.user_id, set()).add(conv.conversation_id)
        if conv.mission_id:
            self._mission_index.setdefault(conv.mission_id, set()).add(conv.conversation_id)
        if conv.project_id:
            self._project_index.setdefault(conv.project_id, set()).add(conv.conversation_id)
            
    def _remove_from_index(self, conv_id: str):
        conv = self._cache.pop(conv_id, None)
        if conv:
            if conv.user_id and conv.user_id in self._user_index:
                self._user_index[conv.user_id].discard(conv_id)
            if conv.mission_id and conv.mission_id in self._mission_index:
                self._mission_index[conv.mission_id].discard(conv_id)
            if conv.project_id and conv.project_id in self._project_index:
                self._project_index[conv.project_id].discard(conv_id)
                
    def save(self, conversation: Conversation):
        """Persists the conversation to a JSON file."""
        self._add_to_index(conversation)
        file_path = self.data_dir / f"{conversation.conversation_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(conversation), f, indent=4)
            
    def get(self, conversation_id: str) -> Optional[Conversation]:
        """Retrieves a conversation by ID."""
        return self._cache.get(conversation_id)
        
    def delete(self, conversation_id: str):
        """Deletes a conversation."""
        self._remove_from_index(conversation_id)
        file_path = self.data_dir / f"{conversation_id}.json"
        if file_path.exists():
            file_path.unlink()
            
    def search(
        self,
        query: str = None,
        user_id: str = None,
        mission_id: str = None,
        project_id: str = None,
        include_archived: bool = False
    ) -> List[Conversation]:
        """Searches conversations utilizing indexes and text matching."""
        # Start with all IDs or filtered by index
        candidate_ids = set(self._cache.keys())
        
        if user_id:
            candidate_ids.intersection_update(self._user_index.get(user_id, set()))
        if mission_id:
            candidate_ids.intersection_update(self._mission_index.get(mission_id, set()))
        if project_id:
            candidate_ids.intersection_update(self._project_index.get(project_id, set()))
            
        results = []
        for cid in candidate_ids:
            conv = self._cache[cid]
            
            if not include_archived and conv.status == "archived":
                continue
                
            if query:
                q = query.lower()
                # Check title
                match = q in conv.title.lower()
                # Check messages
                if not match:
                    for msg in conv.messages:
                        if q in msg.text.lower():
                            match = True
                            break
                if not match:
                    continue
                    
            results.append(conv)
            
        # Sort by latest update descending
        results.sort(key=lambda x: x.last_message_at, reverse=True)
        return results
