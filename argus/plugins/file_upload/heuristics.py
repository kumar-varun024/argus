from typing import List, Dict, Any
from argus.intelligence.models import Investigation

class BaseFileUploadHeuristic:
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        pass

class AttachmentWorkflowHeuristic(BaseFileUploadHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        workflows = context.get('workflows', [])
        for wf in workflows:
            if wf.file_object and wf.file_object.category in ["Document", "Generic"]:
                if wf.upload and "attach" in wf.upload.path.lower():
                    inv = Investigation(
                        title=f"Review Attachment Ownership: {wf.upload.path}",
                        category="File Upload",
                        affected_objects=[wf.upload.path],
                        reasoning="Attachments often bypass authorization checks during retrieval (IDOR) or allow file type bypasses.",
                        supporting_evidence=[f"Upload Endpoint: {wf.upload.path}"],
                        manual_validation_steps=["1. Upload an attachment.", "2. Attempt to download it from a different account.", "3. Bypass extension checks."]
                    )
                    invs.append(inv)
        return invs

class DataImportExportHeuristic(BaseFileUploadHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        workflows = context.get('workflows', [])
        for wf in workflows:
            if wf.file_object and wf.file_object.category == "CSV/Data":
                if wf.upload:
                    inv = Investigation(
                        title=f"Review Data Import Workflow: {wf.upload.path}",
                        category="Data Import",
                        affected_objects=[wf.upload.path],
                        reasoning="CSV and bulk imports are prone to CSV Injection, SSRF (if fetching URLs), and missing rate limits.",
                        supporting_evidence=[f"Import Endpoint: {wf.upload.path}"],
                        manual_validation_steps=["1. Test for CSV Injection.", "2. Attempt to upload oversized payloads.", "3. Test for SSRF if URLs are processed."]
                    )
                    invs.append(inv)
        return invs

class TemporaryStorageHeuristic(BaseFileUploadHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        workflows = context.get('workflows', [])
        for wf in workflows:
            if wf.storage and wf.storage.type == "Temporary":
                inv = Investigation(
                    title=f"Review Temporary Storage Lifecycle: {wf.storage.path_pattern}",
                    category="File Storage",
                    affected_objects=[wf.storage.path_pattern],
                    reasoning="Temporary files might be accessible via race conditions before deletion, or might be leaked if an error occurs during processing.",
                    supporting_evidence=[f"Storage path pattern: {wf.storage.path_pattern}"],
                    manual_validation_steps=["1. Attempt to access the file immediately after upload.", "2. Cause a processing error and check if file persists."]
                )
                invs.append(inv)
        return invs

class FileProcessingHeuristic(BaseFileUploadHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        workflows = context.get('workflows', [])
        for wf in workflows:
            if wf.file_object and wf.file_object.category in ["Avatar/Media", "Archive", "Document"]:
                if wf.upload:
                    inv = Investigation(
                        title=f"Review File Processing Workflow: {wf.upload.path}",
                        category="File Processing",
                        affected_objects=[wf.upload.path],
                        reasoning=f"Processing {wf.file_object.category} files can lead to ImageTragick, XXE (in DOCX/PDF), or Zip Slip (in Archives).",
                        supporting_evidence=[f"Upload Endpoint: {wf.upload.path}", f"Category: {wf.file_object.category}"],
                        manual_validation_steps=["1. Test for image processing vulnerabilities (e.g. ImageMagick).", "2. Test XXE in documents.", "3. Test path traversal in archives."]
                    )
                    invs.append(inv)
        return invs

FILE_UPLOAD_HEURISTIC_REGISTRY = [
    AttachmentWorkflowHeuristic(),
    DataImportExportHeuristic(),
    TemporaryStorageHeuristic(),
    FileProcessingHeuristic()
]
