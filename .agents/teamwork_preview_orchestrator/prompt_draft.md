# Subagent Prompt Draft — Recon Core Implementation Worker (M1-M4)

## Role
Recon Intelligence Implementation Specialist (`teamwork_preview_worker`)

## Working Directory
`/home/varun/argus/.agents/recon_core_worker`

## Task Assignment
Implement R1, R2, R3, R4 normalization across `argus/runtime/parser.py`, `argus/runtime/executor.py`, `argus/runtime/mission.py`, `argus/collectors/subfinder.py`, and `argus/collectors/katana.py`.

### Specific Requirements:
1. **R1 Subfinder**:
   - `ReconParser.parse_subfinder(output)` returns `list[dict]` where each dict has at minimum `"hostname": str` and `"source": "subfinder"`.
   - `ExternalToolExecutor.execute()` sets `context.mission.subdomains = [s["hostname"] if isinstance(s, dict) else s for s in subdomains]` (backward-compatible list of strings).
   - In `executor.py`, create and store `Evidence` with `category="subdomain"`, `value=hostname`, `source="subfinder"`, `description=f"Discovered subdomain {hostname} for target {target}"`, `metadata={"source": "subfinder", "hostname": hostname}`.
   - `argus/collectors/subfinder.py` safely stores string hostnames in `mission.subdomains`.

2. **R2 HTTPX**:
   - `ReconParser.parse_httpx(output)` parses JSONL into dicts with keys: `url`, `scheme`, `host`, `port`, `status`, `title`, `server`, `technologies`.
   - If `scheme`, `host`, or `port` are missing in raw JSON, derive them from `urlparse(url)`. Normalize `technologies` to `list[str]`. Skip malformed JSON lines with a warning.
   - `ExternalToolExecutor.execute()` sets `context.mission.live_hosts = hosts` (list of dicts).
   - For each host, create `Evidence` with `category="live_host"`, `value=h.get("url") or h.get("host")`, `source="httpx"`, `metadata=h`.
   - For each `tech` in `h.get("technologies", [])`: append `tech` to `context.mission.technologies` (deduplicated), and create `Evidence` with `category="technology"`, `value=tech`, `source="httpx"`, `metadata={"name": tech, "host": h.get("host"), "url": h.get("url"), "source": "httpx"}`.

3. **R3 Katana**:
   - `ReconParser.parse_katana(output)` parses plain URLs and JSON lines into `list[dict]` with at minimum `url`, `path`, `host`, `method`, `params`.
   - `ExternalToolExecutor.execute()` checks `tool.id == "katana_crawler" or "katana" in tool.id:`, sets `context.mission.endpoints.extend(endpoints)` (list of dicts).
   - For each endpoint, create `Evidence` with `category="endpoint"`, `value=ep["url"]`, `source="katana"`, `metadata=ep` (with `metadata["url"]` set to full URL).
   - `argus/collectors/katana.py` handles dict endpoints (e.g. `seen.add(ep["url"] if isinstance(ep, dict) else ep)`).

4. **R4 Nuclei**:
   - `ReconParser.parse_nuclei(output)` returns `list[dict]` with keys `template_id`, `name`, `severity`, `host`, `matched_at`, `description`, `tags`, `extracted_results`. Defensively handle `info` being None or dict.
   - In `argus/runtime/mission.py`, add `vulnerabilities: list[dict] = field(default_factory=list)` to `Mission` dataclass and remove any duplicate fields.
   - `ExternalToolExecutor.execute()` sets `context.mission.vulnerabilities.extend(vulnerabilities)` (list of dicts).
   - For each vulnerability, create `Evidence` with `category="vulnerability"`, `value=vuln.get("name") or vuln.get("template_id")`, `source="nuclei"`, `severity=str(vuln.get("severity") or "info").lower()`, `description=vuln.get("description", "")`, `metadata=vuln` (with `metadata["template_id"]` set).

5. **Verification & Audit**:
   - Run the verification script logic from `ORIGINAL_REQUEST.md`.
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q` to verify zero regression.
   - Record results in `/home/varun/argus/.agents/recon_core_worker/handoff.md`.
