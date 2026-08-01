from dataclasses import dataclass

@dataclass
class FileObject:
    name: str
    category: str # Document, Avatar, Media, Archive, CSV
    
class ObjectAnalyzer:
    def classify(self, path: str) -> FileObject:
        lower = path.lower()
        if "avatar" in lower or "profile" in lower or "image" in lower:
            return FileObject(name=path, category="Avatar/Media")
        elif "csv" in lower or "import" in lower or "export" in lower:
            return FileObject(name=path, category="CSV/Data")
        elif "doc" in lower or "pdf" in lower:
            return FileObject(name=path, category="Document")
        elif "zip" in lower or "tar" in lower or "archive" in lower:
            return FileObject(name=path, category="Archive")
        else:
            return FileObject(name=path, category="Generic")
