from dataclasses import dataclass
from typing import List, Optional
from argus.plugins.file_upload.uploads import UploadEndpoint, DownloadEndpoint
from argus.plugins.file_upload.storage import StorageLocation
from argus.plugins.file_upload.objects import FileObject

@dataclass
class FileUploadWorkflow:
    upload: Optional[UploadEndpoint] = None
    download: Optional[DownloadEndpoint] = None
    storage: Optional[StorageLocation] = None
    file_object: Optional[FileObject] = None
