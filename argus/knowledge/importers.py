import json
import yaml
from pathlib import Path
from typing import Iterator

from argus.knowledge.models import KnowledgeEntry


def import_json(file_path: Path) -> Iterator[KnowledgeEntry]:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    if isinstance(data, list):
        for item in data:
            yield KnowledgeEntry(**item)
    elif isinstance(data, dict):
        yield KnowledgeEntry(**data)


def import_yaml(file_path: Path) -> Iterator[KnowledgeEntry]:
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    if isinstance(data, list):
        for item in data:
            yield KnowledgeEntry(**item)
    elif isinstance(data, dict):
        yield KnowledgeEntry(**data)


def import_markdown(file_path: Path) -> Iterator[KnowledgeEntry]:
    # Basic markdown parsing assuming YAML frontmatter bounded by ---
    # And the rest of the file is the description
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]
            body = parts[2].strip()
            
            data = yaml.safe_load(frontmatter)
            if isinstance(data, dict):
                if "description" not in data:
                    data["description"] = body
                yield KnowledgeEntry(**data)
            return

    # If it's just markdown without frontmatter, it's malformed for our purposes, yield nothing
    return
