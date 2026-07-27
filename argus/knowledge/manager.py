import json
import os
import shutil
from pathlib import Path
from typing import List, Optional

from argus.knowledge.models import KnowledgeEntry, KnowledgeCategory
from argus.knowledge.importers import import_json, import_yaml, import_markdown


class KnowledgeManager:
    def __init__(self, data_dir: str = "~/.argus/knowledge"):
        self.data_dir = Path(os.path.expanduser(data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, KnowledgeEntry] = {}
        self.load_all()

    def load_all(self):
        """Loads all knowledge entries from the storage directory."""
        self._entries.clear()
        for file_path in self.data_dir.glob("*.json"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    entry = KnowledgeEntry(**data)
                    self._entries[entry.id] = entry
            except Exception as e:
                pass  # Skip malformed files for now

    def _save(self, entry: KnowledgeEntry):
        """Persists a single knowledge entry to the storage directory."""
        file_path = self.data_dir / f"{entry.id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            import dataclasses
            json.dump(dataclasses.asdict(entry), f, indent=4)

    def add(self, entry: KnowledgeEntry):
        self._entries[entry.id] = entry
        self._save(entry)

    def update(self, entry: KnowledgeEntry):
        if entry.id not in self._entries:
            raise KeyError(f"KnowledgeEntry {entry.id} not found.")
        self._entries[entry.id] = entry
        self._save(entry)

    def delete(self, entry_id: str):
        if entry_id in self._entries:
            del self._entries[entry_id]
            file_path = self.data_dir / f"{entry_id}.json"
            if file_path.exists():
                file_path.unlink()

    def get(self, entry_id: str) -> Optional[KnowledgeEntry]:
        return self._entries.get(entry_id)

    def filter_by_category(self, category: KnowledgeCategory | str) -> List[KnowledgeEntry]:
        cat_value = category.value if isinstance(category, KnowledgeCategory) else category
        return [e for e in self._entries.values() if e.category.value == cat_value or e.category == cat_value]

    def filter_by_tag(self, tag: str) -> List[KnowledgeEntry]:
        tag_lower = tag.lower()
        return [e for e in self._entries.values() if tag_lower in [t.lower() for t in e.tags]]

    def search(
        self,
        keyword: Optional[str] = None,
        technology: Optional[str] = None,
        business_object: Optional[str] = None,
        authentication: Optional[str] = None,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
        capec: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[KnowledgeEntry]:
        results = list(self._entries.values())

        if keyword:
            kw = keyword.lower()
            results = [
                e for e in results
                if kw in e.title.lower() or kw in e.description.lower()
            ]

        if technology:
            tech = technology.lower()
            results = [e for e in results if tech in [t.lower() for t in e.related_technologies]]

        if business_object:
            bo = business_object.lower()
            results = [e for e in results if bo in [b.lower() for b in e.related_business_objects]]

        if authentication:
            auth = authentication.lower()
            results = [e for e in results if auth in [a.lower() for a in e.related_authentication]]

        if cwe:
            cwe_lower = cwe.lower()
            results = [e for e in results if cwe_lower in [c.lower() for c in e.related_cwes]]

        if owasp:
            owasp_lower = owasp.lower()
            results = [e for e in results if owasp_lower in [o.lower() for o in e.related_owasp]]

        if capec:
            capec_lower = capec.lower()
            results = [e for e in results if capec_lower in [c.lower() for c in e.related_capecs]]

        if tags:
            tag_set = {t.lower() for t in tags}
            results = [
                e for e in results
                if tag_set.issubset({t.lower() for t in e.tags})
            ]

        return results

    def related(self, entry_id: str) -> List[KnowledgeEntry]:
        entry = self.get(entry_id)
        if not entry:
            return []
            
        related_ids = set(entry.related_entries)
        related = [self._entries[rid] for rid in related_ids if rid in self._entries]
        
        # Also find implicit relationships (e.g., shared tags could be a weak relation)
        # But for now keep it to explicit related_entries or overlapping technologies/business objects
        for other in self._entries.values():
            if other.id == entry_id or other.id in related_ids:
                continue
            
            # Simple heuristic for implicit relatedness
            shared_techs = set(t.lower() for t in entry.related_technologies).intersection(t.lower() for t in other.related_technologies)
            shared_cwes = set(c.lower() for c in entry.related_cwes).intersection(c.lower() for c in other.related_cwes)
            
            if len(shared_techs) > 0 or len(shared_cwes) > 0:
                related.append(other)
                related_ids.add(other.id)

        return related

    def export(self, export_dir: str, format: str = "json"):
        export_path = Path(export_dir)
        export_path.mkdir(parents=True, exist_ok=True)
        import dataclasses
        
        if format == "json":
            for entry in self._entries.values():
                file_path = export_path / f"{entry.id}.json"
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(dataclasses.asdict(entry), f, indent=4)
        else:
            raise ValueError(f"Export format {format} not supported yet.")

    def import_file(self, file_path: str):
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File {file_path} not found.")

        ext = path.suffix.lower()
        if ext == ".json":
            entries = import_json(path)
        elif ext in (".yaml", ".yml"):
            entries = import_yaml(path)
        elif ext == ".md":
            entries = import_markdown(path)
        else:
            raise ValueError(f"Unsupported import format: {ext}")

        for entry in entries:
            self.add(entry)
