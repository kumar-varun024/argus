import pytest
import os
import json
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory

from argus.knowledge.models import KnowledgeEntry, KnowledgeCategory
from argus.knowledge.manager import KnowledgeManager


@pytest.fixture
def temp_dir():
    with TemporaryDirectory() as d:
        yield d

@pytest.fixture
def manager(temp_dir):
    return KnowledgeManager(data_dir=temp_dir)

def test_add_and_get(manager):
    entry = KnowledgeEntry(
        title="Test Entry",
        category=KnowledgeCategory.HEURISTIC,
        description="A test heuristic"
    )
    manager.add(entry)
    
    retrieved = manager.get(entry.id)
    assert retrieved is not None
    assert retrieved.title == "Test Entry"
    assert retrieved.category == KnowledgeCategory.HEURISTIC

def test_persistence(temp_dir):
    manager1 = KnowledgeManager(data_dir=temp_dir)
    entry = KnowledgeEntry(
        title="Persistent Entry",
        category=KnowledgeCategory.METHODOLOGY,
        description="Will be saved to disk"
    )
    manager1.add(entry)
    
    # Reload from disk
    manager2 = KnowledgeManager(data_dir=temp_dir)
    retrieved = manager2.get(entry.id)
    assert retrieved is not None
    assert retrieved.title == "Persistent Entry"

def test_update_and_delete(manager):
    entry = KnowledgeEntry(
        title="To Update",
        category=KnowledgeCategory.TECHNOLOGY,
        description="Old"
    )
    manager.add(entry)
    
    entry.description = "New"
    manager.update(entry)
    
    assert manager.get(entry.id).description == "New"
    
    manager.delete(entry.id)
    assert manager.get(entry.id) is None

def test_search_and_filter(manager):
    entry1 = KnowledgeEntry(
        title="OAuth Token Leak",
        category=KnowledgeCategory.FINDING_PATTERN,
        description="Token leaked in URL",
        related_technologies=["OAuth", "HTTP"],
        tags=["auth", "leak"]
    )
    
    entry2 = KnowledgeEntry(
        title="SQL Injection",
        category=KnowledgeCategory.FINDING_PATTERN,
        description="SQLi in login",
        related_technologies=["SQL", "Database"],
        tags=["injection", "sqli"]
    )
    
    manager.add(entry1)
    manager.add(entry2)
    
    assert len(manager.filter_by_category(KnowledgeCategory.FINDING_PATTERN)) == 2
    assert len(manager.filter_by_tag("auth")) == 1
    
    # Search keyword
    res = manager.search(keyword="Token")
    assert len(res) == 1
    assert res[0].id == entry1.id
    
    # Search tech
    res = manager.search(technology="OAuth")
    assert len(res) == 1
    assert res[0].id == entry1.id

def test_related_entries(manager):
    entry1 = KnowledgeEntry(
        title="OAuth Authorization Code",
        category=KnowledgeCategory.AUTHENTICATION_PATTERN,
        description="...",
        related_technologies=["OAuth"]
    )
    
    entry2 = KnowledgeEntry(
        title="PKCE",
        category=KnowledgeCategory.AUTHENTICATION_PATTERN,
        description="...",
        related_technologies=["OAuth"],
        related_entries=[entry1.id]
    )
    
    manager.add(entry1)
    manager.add(entry2)
    
    related = manager.related(entry2.id)
    assert len(related) > 0
    assert entry1.id in [r.id for r in related]

def test_imports(temp_dir, manager):
    # JSON
    json_path = Path(temp_dir) / "test.json"
    with open(json_path, "w") as f:
        json.dump({
            "title": "JSON Entry",
            "category": KnowledgeCategory.METHODOLOGY.value,
            "description": "desc"
        }, f)
        
    manager.import_file(str(json_path))
    res = manager.search(keyword="JSON Entry")
    assert len(res) == 1
    
    # YAML
    yaml_path = Path(temp_dir) / "test.yaml"
    with open(yaml_path, "w") as f:
        yaml.dump({
            "title": "YAML Entry",
            "category": KnowledgeCategory.HEURISTIC.value,
            "description": "desc yaml"
        }, f)
        
    manager.import_file(str(yaml_path))
    res = manager.search(keyword="YAML Entry")
    assert len(res) == 1
    
    # Markdown
    md_path = Path(temp_dir) / "test.md"
    with open(md_path, "w") as f:
        f.write("---\n")
        f.write("title: MD Entry\n")
        f.write(f"category: {KnowledgeCategory.FINDING_PATTERN.value}\n")
        f.write("---\n")
        f.write("Desc markdown\n")
        
    manager.import_file(str(md_path))
    res = manager.search(keyword="MD Entry")
    assert len(res) == 1
