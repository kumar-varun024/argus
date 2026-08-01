from dataclasses import dataclass
from typing import List

@dataclass
class UploadEndpoint:
    path: str
    method: str
    is_bulk: bool = False

@dataclass
class DownloadEndpoint:
    path: str
    method: str

class UploadAnalyzer:
    def extract_endpoints(self, endpoints: List[dict]) -> (List[UploadEndpoint], List[DownloadEndpoint]):
        uploads = []
        downloads = []
        for ep in endpoints:
            path = ep.get("path", "").lower()
            method = ep.get("method", "GET").upper()
            
            if "upload" in path or "import" in path or "attach" in path:
                uploads.append(UploadEndpoint(
                    path=ep.get("path", ""),
                    method=method,
                    is_bulk="bulk" in path or "import" in path
                ))
            elif "download" in path or "export" in path or "file/" in path or "media/" in path:
                downloads.append(DownloadEndpoint(
                    path=ep.get("path", ""),
                    method=method
                ))
                
        return uploads, downloads
