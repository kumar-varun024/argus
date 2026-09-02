import sys
import os
import json
import urllib.parse
from unittest.mock import MagicMock

# Import the target module
from argus.collectors.file_upload import (
    FileUploadCollector,
    FileUploadPayloadGenerator,
    FileUploadProber,
    FileUploadAnalyzer,
    FileUploadProbe,
    FileUploadResponse,
    FileUploadResult,
    FileUploadSeverity,
    FileUploadTechnique,
    FileUploadMutationStrategy,
    TargetRuntime,
)
from argus.reporting.cvss import CVSSCalculator
from argus.runtime.models import Mission
from argus.runtime.registry import ToolRegistry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.planning.task_generator import TaskGenerator, GapInfo
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import AttackSurfaceGraph
from argus.graph.node import Node
from argus.evidence.model import Evidence, EvidenceStore

print("=== STARTING EMPIRICAL ADVERSARIAL STRESS TEST ===")

errors = []

def record_error(msg):
    print(f"[FAIL] {msg}")
    errors.append(msg)

def record_pass(msg):
    print(f"[PASS] {msg}")

# -----------------------------------------------------------------------------
# 1. Unrestricted Executable Payloads across Runtime Families
# -----------------------------------------------------------------------------
gen = FileUploadPayloadGenerator()
unrestricted = gen.generate_unrestricted_probes()
runtimes_tested = {p.target_runtime for p in unrestricted}

expected_runtimes = {
    TargetRuntime.PHP,
    TargetRuntime.JSP,
    TargetRuntime.ASP_ASPX,
    TargetRuntime.PYTHON,
    TargetRuntime.RUBY,
    TargetRuntime.BASH,
    TargetRuntime.GENERIC,
}

if expected_runtimes.issubset(runtimes_tested):
    record_pass(f"Unrestricted probes cover all {len(runtimes_tested)} expected runtimes: {[r.value for r in runtimes_tested]}")
else:
    record_error(f"Missing runtimes in unrestricted probes: {expected_runtimes - runtimes_tested}")

# Verify payload syntax & canary token inclusion per runtime
for p in unrestricted:
    if not p.canary_token:
        record_error(f"Probe {p.filename} missing canary token")
    content_str = p.content if isinstance(p.content, str) else p.content.decode('utf-8', errors='ignore')
    if p.canary_token not in content_str:
        record_error(f"Probe {p.filename} content does not contain canary token {p.canary_token}")
    if p.technique != FileUploadTechnique.UNRESTRICTED_UPLOAD:
        record_error(f"Probe {p.filename} has wrong technique: {p.technique}")

# -----------------------------------------------------------------------------
# 2. MIME Type Bypass Mutations
# -----------------------------------------------------------------------------
mime_probes = gen.generate_mime_bypass_probes()
valid_exec_exts = (".php", ".phtml", ".jsp", ".asp", ".aspx", ".py", ".rb", ".sh")
benign_mimes = {"image/jpeg", "image/png", "image/gif", "application/pdf"}

if len(mime_probes) >= 10:
    record_pass(f"MIME bypass probes generated: {len(mime_probes)}")
else:
    record_error(f"Too few MIME bypass probes: {len(mime_probes)}")

for p in mime_probes:
    if not any(p.filename.endswith(ext) for ext in valid_exec_exts):
        record_error(f"MIME probe {p.filename} does not have executable extension")
    if p.content_type not in benign_mimes:
        record_error(f"MIME probe {p.filename} content_type {p.content_type} is not a benign MIME type")
    if p.strategy != FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH:
        record_error(f"MIME probe {p.filename} has wrong strategy: {p.strategy}")
    if p.technique != FileUploadTechnique.MIME_TYPE_BYPASS:
        record_error(f"MIME probe {p.filename} has wrong technique: {p.technique}")

# -----------------------------------------------------------------------------
# 3. Double Extension Combinations (>= 3 combinations including .aspx.gif)
# -----------------------------------------------------------------------------
double_ext_probes = gen.generate_double_extension_probes()
double_ext_filenames = [p.filename for p in double_ext_probes]

if len(double_ext_probes) >= 3:
    record_pass(f"Double extension probes count: {len(double_ext_probes)}")
else:
    record_error(f"Double extension probes count < 3: {len(double_ext_probes)}")

if "payload.aspx.gif" in double_ext_filenames:
    record_pass("Explicitly confirmed 'payload.aspx.gif' present in double extension probes")
else:
    record_error("Missing 'payload.aspx.gif' in double extension probes")

required_combos = ["shell.php.jpg", "payload.asp.png", "exploit.jsp.gif", "payload.aspx.gif"]
found_combos = [c for c in required_combos if c in double_ext_filenames]
if len(found_combos) >= 3:
    record_pass(f"Found required double extension combinations: {found_combos}")
else:
    record_error(f"Not enough required double extension combinations: {found_combos}")

# -----------------------------------------------------------------------------
# 4. Polyglot Magic Bytes (9 Configurations: GIF89a, PNG, JPEG, PDF)
# -----------------------------------------------------------------------------
polyglot_probes = gen.generate_polyglot_probes()
if len(polyglot_probes) == 9:
    record_pass(f"Polyglot probes count exactly 9: {[p.filename for p in polyglot_probes]}")
else:
    record_error(f"Polyglot probes count expected 9, got {len(polyglot_probes)}")

magic_signatures = {
    "gif": b"GIF89a",
    "png": b"PNG",
    "jpg": b"ÿØÿ",
    "pdf": b"%PDF-1.",
}

for p in polyglot_probes:
    if not isinstance(p.content, bytes):
        record_error(f"Polyglot {p.filename} content is not bytes")
        continue
    matched_sig = False
    for ext_key, sig in magic_signatures.items():
        if p.filename.endswith(f".{ext_key}"):
            if p.content.startswith(sig):
                matched_sig = True
            else:
                record_error(f"Polyglot {p.filename} does not start with magic bytes for {ext_key}")
    if not matched_sig:
        record_error(f"Polyglot {p.filename} did not match any known signature pattern")
    if p.technique != FileUploadTechnique.POLYGLOT_MAGIC_BYTES:
        record_error(f"Polyglot {p.filename} has wrong technique: {p.technique}")
    if p.strategy != FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING:
        record_error(f"Polyglot {p.filename} has wrong strategy: {p.strategy}")

# -----------------------------------------------------------------------------
# 5. Path Traversal in Filenames
# -----------------------------------------------------------------------------
traversal_probes = gen.generate_path_traversal_probes()
if len(traversal_probes) >= 8:
    record_pass(f"Path traversal probes count: {len(traversal_probes)}")
else:
    record_error(f"Path traversal probes count < 8: {len(traversal_probes)}")

has_dotdot_slash = any("../" in p.filename for p in traversal_probes)
has_dotdot_backslash = any("..\" in p.filename for p in traversal_probes)
has_url_encoded = any("%2f" in p.filename or "%252f" in p.filename or "%c0%af" in p.filename for p in traversal_probes)

if has_dotdot_slash and has_dotdot_backslash and has_url_encoded:
    record_pass("Path traversal probes include ../, ..\, and URL-encoded sequences")
else:
    record_error(f"Path traversal probes missing traversal variations: slash={has_dotdot_slash}, backslash={has_dotdot_backslash}, url={has_url_encoded}")

# -----------------------------------------------------------------------------
# 6. Evasion Mutations (7 Strategies)
# -----------------------------------------------------------------------------
evasions = gen.generate_evasion_mutations()
strategies_in_evasions = {p.strategy for p in evasions}
expected_strategies = {
    FileUploadMutationStrategy.EXTENSION_CASING,
    FileUploadMutationStrategy.NULL_BYTE,
    FileUploadMutationStrategy.FILENAME_ENCODING,
    FileUploadMutationStrategy.TRAILING_DOTS_SPACES,
    FileUploadMutationStrategy.NTFS_STREAM,
}
if expected_strategies.issubset(strategies_in_evasions):
    record_pass(f"Evasion mutations cover strategies: {[s.value for s in strategies_in_evasions]}")
else:
    record_error(f"Missing evasion strategies: {expected_strategies - strategies_in_evasions}")

# Test apply_mutation dynamically
base_probe = FileUploadProbe(
    filename="test.php",
    content="<?php echo 1; ?>",
    content_type="application/x-php",
    technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
    strategy=FileUploadMutationStrategy.STANDARD,
    target_runtime=TargetRuntime.PHP,
)

cased = gen.apply_mutation(base_probe, FileUploadMutationStrategy.EXTENSION_CASING)
if cased.filename.lower() == "test.php" and cased.filename != "test.php":
    record_pass(f"apply_mutation EXTENSION_CASING produced: {cased.filename}")
else:
    record_error(f"apply_mutation EXTENSION_CASING failed: {cased.filename}")

nulled = gen.apply_mutation(base_probe, FileUploadMutationStrategy.NULL_BYTE)
if "%00" in nulled.filename and nulled.content_type == "image/jpeg":
    record_pass(f"apply_mutation NULL_BYTE produced: {nulled.filename}")
else:
    record_error(f"apply_mutation NULL_BYTE failed: {nulled.filename}")

mismatched = gen.apply_mutation(base_probe, FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH)
if mismatched.content_type == "image/jpeg":
    record_pass("apply_mutation CONTENT_TYPE_MISMATCH modified content_type to image/jpeg")
else:
    record_error(f"apply_mutation CONTENT_TYPE_MISMATCH failed: {mismatched.content_type}")

magic_mut = gen.apply_mutation(base_probe, FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING)
if isinstance(magic_mut.content, bytes) and magic_mut.content.startswith(b"GIF89a"):
    record_pass("apply_mutation MAGIC_BYTES_PREPENDING prepended GIF89a header")
else:
    record_error("apply_mutation MAGIC_BYTES_PREPENDING failed")

encoded = gen.apply_mutation(base_probe, FileUploadMutationStrategy.FILENAME_ENCODING)
if "%2e" in encoded.filename:
    record_pass(f"apply_mutation FILENAME_ENCODING produced: {encoded.filename}")
else:
    record_error(f"apply_mutation FILENAME_ENCODING failed: {encoded.filename}")

trailing = gen.apply_mutation(base_probe, FileUploadMutationStrategy.TRAILING_DOTS_SPACES)
if trailing.filename.endswith("."):
    record_pass(f"apply_mutation TRAILING_DOTS_SPACES produced: {trailing.filename}")
else:
    record_error(f"apply_mutation TRAILING_DOTS_SPACES failed: {trailing.filename}")

ntfs = gen.apply_mutation(base_probe, FileUploadMutationStrategy.NTFS_STREAM)
if "::" in ntfs.filename:
    record_pass(f"apply_mutation NTFS_STREAM produced: {ntfs.filename}")
else:
    record_error(f"apply_mutation NTFS_STREAM failed: {ntfs.filename}")

# -----------------------------------------------------------------------------
# 7. Storage Path Extraction & Web Shell Execution
# -----------------------------------------------------------------------------
prober = FileUploadProber()
analyzer = FileUploadAnalyzer()

# 7.1 Location Header Extraction
resp1 = FileUploadResponse(
    status_code=201,
    headers={"Location": "/uploads/shell_loc.php"},
    body="File created successfully",
)
prober._extract_storage_information(resp1, "https://target.local/api/upload", "shell_loc.php")
if resp1.storage_url == "https://target.local/uploads/shell_loc.php":
    record_pass(f"Location header extraction correct: {resp1.storage_url}")
else:
    record_error(f"Location header extraction incorrect: {resp1.storage_url}")

# 7.2 JSON Body Extraction (Prioritizing URL over path, preserving path disclosure)
resp2 = FileUploadResponse(
    status_code=200,
    headers={"Content-Type": "application/json"},
    body=json.dumps({"file_url": "https://cdn.target.local/files/exploit.jsp", "path": "/var/www/html/uploads/exploit.jsp"}),
)
prober._extract_storage_information(resp2, "https://target.local/upload", "exploit.jsp")
if resp2.storage_url == "https://cdn.target.local/files/exploit.jsp" and resp2.storage_path_disclosed == "/var/www/html/uploads/exploit.jsp":
    record_pass(f"JSON extraction correct: URL={resp2.storage_url}, DisclosedPath={resp2.storage_path_disclosed}")
else:
    record_error(f"JSON extraction failed: URL={resp2.storage_url}, DisclosedPath={resp2.storage_path_disclosed}")

# 7.3 HTML Regex Extraction
resp3 = FileUploadResponse(
    status_code=200,
    headers={"Content-Type": "text/html"},
    body='<html><body>Upload success! Download at <a href="/static/files/avatar.php.jpg">here</a></body></html>',
)
prober._extract_storage_information(resp3, "https://target.local/upload", "avatar.php.jpg")
if resp3.storage_url == "https://target.local/static/files/avatar.php.jpg":
    record_pass(f"HTML regex extraction correct: {resp3.storage_url}")
else:
    record_error(f"HTML regex extraction failed: {resp3.storage_url}")

# 7.4 Web Shell Execution Canary Check
mock_client = MagicMock()
mock_get_resp = MagicMock()
mock_get_resp.status_code = 200
mock_get_resp.body = "ARGUS_CANARY_TEST123"
mock_client.get.return_value = mock_get_resp

prober_with_client = FileUploadProber(client=mock_client)
resp_shell = FileUploadResponse(
    status_code=200,
    storage_url="https://target.local/uploads/shell.php",
)
prober_with_client._check_web_shell_reachability(None, resp_shell, "ARGUS_CANARY_TEST123")

if resp_shell.web_shell_executed and resp_shell.is_reflected:
    record_pass("Web shell executed verified: canary found without source tags")
else:
    record_error(f"Web shell execution check failed: executed={resp_shell.web_shell_executed}, reflected={resp_shell.is_reflected}")

# 7.5 Unexecuted Reflected Source Code Canary Check
mock_get_src = MagicMock()
mock_get_src.status_code = 200
mock_get_src.body = "<?php echo 'ARGUS_CANARY_TEST123'; ?>"
mock_client.get.return_value = mock_get_src

resp_src = FileUploadResponse(
    status_code=200,
    storage_url="https://target.local/uploads/shell.php",
)
prober_with_client._check_web_shell_reachability(None, resp_src, "ARGUS_CANARY_TEST123")

if not resp_src.web_shell_executed and resp_src.is_reflected:
    record_pass("Web shell source code reflection correctly marked as NOT executed")
else:
    record_error(f"Source code reflection marked incorrectly: executed={resp_src.web_shell_executed}, reflected={resp_src.is_reflected}")

# -----------------------------------------------------------------------------
# 8. False Positive Rejection & Severity Calibration
# -----------------------------------------------------------------------------
# 8.1 Benign probe
benign_p = gen.generate_benign_probes()[0]
res_benign = analyzer.evaluate_probe(benign_p, FileUploadResponse(status_code=200, body="OK"), "https://target.local")
if res_benign is None:
    record_pass("Benign probe rejected as false positive")
else:
    record_error("Benign probe was NOT rejected")

# 8.2 Proper validation 403 rejection
mal_p = unrestricted[0]
res_403 = analyzer.evaluate_probe(mal_p, FileUploadResponse(status_code=403, body="File type is not allowed"), "https://target.local")
if res_403 is None:
    record_pass("403 validation rejection correctly ignored")
else:
    record_error("403 validation rejection was NOT ignored")

# 8.3 Safe UUID Renaming
res_uuid = analyzer.evaluate_probe(
    mal_p,
    FileUploadResponse(
        status_code=200,
        body=json.dumps({"file_url": "https://target.local/files/12345678-1234-1234-1234-123456789abc.png"}),
        storage_url="https://target.local/files/12345678-1234-1234-1234-123456789abc.png",
    ),
    "https://target.local"
)
if res_uuid is None:
    record_pass("Safe UUID renaming rejected as false positive")
else:
    record_error("Safe UUID renaming was NOT rejected")

# 8.4 HTTP 500 Stack Trace Info Disclosure (CWE-200 / MEDIUM)
res_500 = analyzer.evaluate_probe(
    mal_p,
    FileUploadResponse(
        status_code=500,
        body="Fatal error: Uncaught Exception in /var/www/html/upload.php on line 42
Stack trace:...",
    ),
    "https://target.local"
)
if res_500 is not None and res_500.cwe_id == "CWE-200" and res_500.severity == "medium":
    record_pass(f"HTTP 500 error disclosure calibrated as CWE-200 / MEDIUM: {res_500.description[:60]}...")
else:
    record_error(f"HTTP 500 error disclosure miscalibrated: {res_500}")

# 8.5 Unrestricted Upload (CWE-434 / CRITICAL)
res_unres = analyzer.evaluate_probe(
    mal_p,
    FileUploadResponse(status_code=200, body="Upload success"),
    "https://target.local"
)
if res_unres is not None and res_unres.cwe_id == "CWE-434" and res_unres.severity == "critical":
    record_pass("Unrestricted upload calibrated as CWE-434 / CRITICAL")
else:
    record_error(f"Unrestricted upload miscalibrated: {res_unres}")

# 8.6 MIME Bypass / Double Extension / Polyglot (CWE-436 / HIGH)
res_mime = analyzer.evaluate_probe(
    mime_probes[0],
    FileUploadResponse(status_code=200, body="Upload success"),
    "https://target.local"
)
if res_mime is not None and res_mime.cwe_id == "CWE-436" and res_mime.severity == "high":
    record_pass("MIME bypass calibrated as CWE-436 / HIGH")
else:
    record_error(f"MIME bypass miscalibrated: {res_mime}")

# 8.7 Path Traversal (CWE-22 / HIGH)
res_trav = analyzer.evaluate_probe(
    traversal_probes[0],
    FileUploadResponse(status_code=200, body="Upload success"),
    "https://target.local"
)
if res_trav is not None and res_trav.cwe_id == "CWE-22" and res_trav.severity == "high":
    record_pass("Path traversal calibrated as CWE-22 / HIGH")
else:
    record_error(f"Path traversal miscalibrated: {res_trav}")

# -----------------------------------------------------------------------------
# 9. Pipeline & Graph Integration
# -----------------------------------------------------------------------------
collector = FileUploadCollector()
mission = Mission(target="https://api.target.local")
mission.attack_surface_graph = AttackSurfaceGraph()
mission.vulnerabilities = []

mock_prober = MagicMock()
mock_prober.execute_upload.return_value = FileUploadResponse(
    status_code=200,
    body="Upload success",
    storage_url="https://api.target.local/uploads/shell.php",
    web_shell_executed=True,
)
collector.prober = mock_prober

findings = collector.collect(mission)
if len(findings) > 0:
    record_pass(f"Collector emitted {len(findings)} findings")
    # Check quadruple state publishing
    if len(mission.evidence.all()) > 0:
        record_pass("1. raw_mission.evidence populated")
    else:
        record_error("1. raw_mission.evidence NOT populated")

    if len(mission.vulnerabilities) > 0:
        record_pass("2. raw_mission.vulnerabilities populated")
    else:
        record_error("2. raw_mission.vulnerabilities NOT populated")

    edges = mission.attack_surface_graph.get_edges()
    has_vuln_edges = [e for e in edges if e.get("type") == "HAS_VULNERABILITY" or e.get("edge_type") == "HAS_VULNERABILITY"]
    if len(has_vuln_edges) >= 2:
        record_pass(f"3. attack_surface_graph has {len(has_vuln_edges)} HAS_VULNERABILITY edges")
    else:
        record_error(f"3. attack_surface_graph missing HAS_VULNERABILITY edges: {has_vuln_edges}")
else:
    record_error("Collector did not emit findings")

# -----------------------------------------------------------------------------
# 10. CVSS & Task Generator DAG resolution
# -----------------------------------------------------------------------------
calc = CVSSCalculator()
cwe_upload = calc.get_cwe("unrestricted_upload")
cwe_mime = calc.get_cwe("mime_type_bypass")
if cwe_upload and cwe_upload.id == "CWE-434":
    record_pass("CVSSCalculator correctly maps unrestricted_upload to CWE-434")
else:
    record_error(f"CVSSCalculator failed for unrestricted_upload: {cwe_upload}")

if cwe_mime and cwe_mime.id == "CWE-436":
    record_pass("CVSSCalculator correctly maps mime_type_bypass to CWE-436")
else:
    record_error(f"CVSSCalculator failed for mime_type_bypass: {cwe_mime}")

tg = TaskGenerator()
gap = GapInfo(entity_type="endpoint", entity_id="https://api.target.local/upload", gap_type="untested_endpoint")
recon_tasks = tg.generate_recon_tasks()
task_ids = [t.id for t in recon_tasks]
if "file_upload" in task_ids:
    record_pass("TaskGenerator includes 'file_upload' task in recon DAG")
else:
    record_error(f"'file_upload' missing from TaskGenerator recon tasks: {task_ids}")

print("
=== STRESS TEST SUMMARY ===")
if errors:
    print(f"TOTAL FAILURES: {len(errors)}")
    for err in errors:
        print(f" - {err}")
    sys.exit(1)
else:
    print("ALL 31 EMPIRICAL STRESS CHECKS PASSED PERFECTLY!")
    sys.exit(0)
