## 2026-08-30T11:10:39Z
You are a Spec Miner subagent for the ARGUS platform.
Your working directory is /home/varun/argus/.agents/spec_miner_cmdi/
Your role is to extract and document precise OS Command Injection (CMDi) requirements, payload sets, detection signatures, separator strategies, and edge cases for Sprint 11.

MANDATORY FIRST STEP: Read the requirements in /home/varun/argus/.agents/ORIGINAL_REQUEST.md (especially section ## 2026-08-30T11:08:07Z for Sprint 11 Command Injection).

Tasks to investigate & specify:
1. Result-based detection:
   - Exact command payload sets (whoami, id, hostname, uname -a, etc.)
   - Regex patterns and signatures to match OS outputs (e.g. `uid=\d+\(.*?\)\s+gid=\d+`, Windows `nt authority\\`, etc.) while avoiding false positives on normal application responses.
2. Time-based differential detection:
   - Delay commands (sleep 5, ping -c 5 127.0.0.1, timeout /t 5, etc.)
   - Baseline timing measurement, threshold calculation (differential >= 4.0 seconds above baseline).
3. Error-based detection:
   - Malformed commands triggering OS error messages (e.g., `/bin/sh: line 1: ...: command not found`, `syntax error near unexpected token`, `'...' is not recognized as an internal or external command`, etc.).
4. Separator & Bypass Mutation strategies (at least 5 distinct strategies):
   - Semicolons (`;`)
   - Pipes (`|`, `||`)
   - Ampersands (`&`, `&&`)
   - Backticks (`` `cmd` ``)
   - Dollar-parens (`$(cmd)`)
   - Newlines (`\n`, `%0a`, `%0d%0a`)
   - URL-encoded variants (`%3B`, `%7C`, `%26`, etc.)
   - Whitespace substitutions (`$IFS`, `${IFS}`, tabs, `%20`, `+`)
   - Inline comments / quotes bypasses
5. Parameter injection points:
   - Query parameters (GET/POST query string)
   - POST body fields (form-urlencoded, JSON, raw)
   - Path segments
   - Relevant HTTP headers (User-Agent, Referer, Cookie, Custom headers, etc.)
6. Acceptance criteria mapping & test cases specification (Tiers 1-4).

Deliverable:
Write a comprehensive specification to /home/varun/argus/.agents/spec_miner_cmdi/handoff.md.

When complete, write progress.md and handoff.md in your working directory, and send a final completion message to the orchestrator.
