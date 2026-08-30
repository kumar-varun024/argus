## 2026-08-27T00:05:05Z

You are the Recon Core Implementation Worker for ARGUS Sprint 1.
Your working directory is /home/varun/argus/.agents/recon_core_worker.

Authoritative requirements are in /home/varun/argus/.agents/ORIGINAL_REQUEST.md.
Survey findings are in /home/varun/argus/.agents/survey_explorer_1/handoff.md and /home/varun/argus/.agents/survey_explorer_2/handoff.md.
Project plan and architecture are in /home/varun/argus/PROJECT.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File Write Ownership:
You have exclusive write ownership of:
- `argus/runtime/parser.py`
- `argus/runtime/executor.py`
- `argus/runtime/mission.py`
- `argus/collectors/subfinder.py`
- `argus/collectors/katana.py`

Implementation Tasks:
1. R1 Subfinder:
   - In `argus/runtime/parser.py`, update `ReconParser.parse_subfinder(output)` to return `list[dict]` where each item is `{"hostname": str, "source": "subfinder"}`. Support both plain text lines and JSON lines gracefully.
   - In `argus/runtime/executor.py`, ensure `context.mission.subdomains` is stored as a list of strings (`[s["hostname"] if isinstance(s, dict) else s for s in subdomains]`) for backward compatibility.
   - Create `Evidence` with `category="subdomain"`, `value=hostname`, `source="subfinder"`, `metadata={"source": "subfinder", "hostname": hostname}`.
   - In `argus/collectors/subfinder.py`, ensure string hostnames are stored in `mission.subdomains`.

2. R2 HTTPX:
   - In `argus/runtime/parser.py`, update `ReconParser.parse_httpx(output)` to parse JSONL into dicts containing keys: `url`, `scheme`, `host`, `port`, `status`, `title`, `server`, `technologies`. If `scheme`, `host`, `port` are missing in JSON, derive them from `urllib.parse.urlparse(url)`. Normalize `tech` / `technologies` to `list[str]`. Handle alias fields (`status_code`, `webserver`). Skip malformed lines with warning.
   - In `argus/runtime/executor.py`, update `context.mission.live_hosts` to store the structured host dicts (`hosts`).
   - For each host, create `Evidence(category="live_host", value=h.get("url") or h.get("host"), source="httpx", metadata=h)`.
   - For each `tech` in `h.get("technologies", [])`: append to `context.mission.technologies` (deduplicated), and create `Evidence(category="technology", value=tech, source="httpx", metadata={"name": tech, "host": h.get("host"), "url": h.get("url"), "source": "httpx"})`.

3. R3 Katana:
   - In `argus/runtime/parser.py`, update `ReconParser.parse_katana(output)` to parse plain URLs and JSON lines into `list[dict]` with at minimum `url` and `path` (plus `host`, `method`, `params`).
   - In `argus/runtime/executor.py`, match tool with `tool.id == "katana_crawler" or "katana" in tool.id:`, update `context.mission.endpoints.extend(endpoints)` (list of dicts).
   - For each endpoint, create `Evidence(category="endpoint", value=ep["url"], source="katana", metadata=ep)` (with `metadata["url"]` set to full URL).
   - In `argus/collectors/katana.py`, ensure set deduplication uses string URLs (e.g. `seen.add(ep["url"] if isinstance(ep, dict) else ep)`).

4. R4 Nuclei:
   - In `argus/runtime/parser.py`, update `ReconParser.parse_nuclei(output)` to parse JSONL into dicts with keys: `template_id`, `name`, `severity`, `host`, `matched_at`, `description`, `tags`, `extracted_results`. Handle `info` safely (when `item.get("info")` is None or dict).
   - In `argus/runtime/mission.py`, add `vulnerabilities: list[dict] = field(default_factory=list)` to the `Mission` dataclass and clean up duplicate `evidence` declaration.
   - In `argus/runtime/executor.py`, update `context.mission.vulnerabilities.extend(vulnerabilities)` (list of dicts).
   - For each vulnerability, create `Evidence(category="vulnerability", value=vuln.get("name") or vuln.get("template_id"), source="nuclei", severity=str(vuln.get("severity") or "info").lower(), description=vuln.get("description", ""), metadata=vuln)` (with `metadata["template_id"]` set).

5. Verification:
   - Execute the verification script from `ORIGINAL_REQUEST.md` lines 99-133 to ensure all 4 checks print PASS.
   - Run the full test suite: `python -m pytest tests/ --ignore=tests/workspace -x -q` to ensure all 427+ tests pass.
   - Run `python -m pytest tests/planning/test_recon_task_generation.py -v`.
