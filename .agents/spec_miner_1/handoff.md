# WebSocket Security Detection Specification — Sprint 18

**Agent**: `spec_miner_1` (WebSocket Security Specification Specialist)  
**Target Module**: `argus/collectors/websocket.py` & `argus/analyzers/websocket.py` (Argus Platform Sprint 18)  
**Date**: 2026-08-31  
**Status**: Specification Complete / Ready for Implementation  

---

## Executive Summary & Architecture Blueprint

This specification defines the architectural requirements, protocol semantics, detection algorithms, mutation matrices, evidence models, and false-positive suppression rules for the **WebSocket Security Detection Collector** in ARGUS.

The collector actively audits discovered WebSocket endpoints (`ws://`, `wss://`, and HTTP Upgrade endpoints) across four core vulnerability domains:
1. **Cross-Site WebSocket Hijacking (CSWSH)** (CWE-346, CWE-1385)
2. **Unauthenticated Handshakes & Query Token Leakage** (CWE-287, CWE-598, CWE-200)
3. **Bi-Directional Frame Injection & Fuzzing** (CWE-89, CWE-78, CWE-79, CWE-1321)
4. **WebSocket DoS & RFC 6455 Frame Protocol Abuse** (CWE-400, CWE-799, RFC 6455 §5.1)

---

## 1. Observation

Direct examination of the ARGUS platform codebase revealed the following structural interfaces, baseline dependencies, and architectural conventions:

1. **Collector Architecture Pattern** (`argus/collectors/graphql.py`, `argus/collectors/oauth.py`, `argus/collectors/base.py`):
   - Collectors inherit from `BaseCollector` and implement `collect(self, mission)` and `execute(self, mission) -> List[Evidence]`.
   - Modularity is split into three core classes:
     - `WebSocketPayloadGenerator`: Generates handshake variants, subprotocol lists, frame mutations, and injection vectors.
     - `WebSocketSecurityAnalyzer`: Analyzes handshake HTTP responses (status codes, headers, `Sec-WebSocket-Accept`) and incoming WebSocket frames (JSON error strings, command reflections, close status codes).
     - `WebSocketSecurityCollector`: Manages candidate endpoint discovery, HTTP upgrade dispatches, raw frame communications, evidence creation, and KnowledgeGraph edge updates.
   - Result dataclass `WebSocketSecurityResult` encapsulates technique, mutation strategy, severity, confidence, matched signature, evidence snippet, and status codes.

2. **Evidence Model** (`argus/evidence/model.py`):
   - `Evidence` dataclass with `slots=True`, requiring `category="websocket_security"`, `severity`, `confidence`, `title`, `description`, `metadata` (dict containing `url`, `endpoint_url`, `technique`, `mutation_strategy`, `cwe_id`, `cvss_score`), and `provenance=ProvenanceData()`.

3. **Attack Surface Graph & Pipeline Connectivity** (`argus/graph/attack_surface.py`, `argus/planning/task_generator.py`, `argus/runtime/plugins.py`):
   - Discovered endpoints map to `Node(id="endpoint:<url>", type="endpoint", value="<url>")`.
   - Confirmed vulnerabilities map to `Node(id="vulnerability:<template_id>:<url>:<technique>", type="vulnerability")`.
   - Edges: `live_host -> endpoint` via `HAS_ENDPOINT`, `endpoint -> vulnerability` via `HAS_VULNERABILITY`, and `live_host -> vulnerability` via `HAS_VULNERABILITY`.
   - Plugin registration in `argus/runtime/plugins.py` under `PluginExecutorAdapter._instantiate_specialist_fallback` matching `websocket` or `ws`.
   - DAG Task generation in `argus/planning/task_generator.py` under `_RECON_TEMPLATES["websocket_security"]`.

---

## 2. Logic Chain

From the observed system architecture, the specification is structured into four authoritative requirement sections:

```
[Endpoint Discovery & RFC 6455 Handshake] 
        │
        ├──> [R1: Handshake Anatomy & Prober Engine]
        │
        ├──> [R2: Multi-Vulnerability Detection Logic]
        │       ├── 2.1 CSWSH (Origin Header Mutation & Validation)
        │       ├── 2.2 Unauthenticated Handshake & Token Query Leakage
        │       ├── 2.3 Bi-directional Frame Fuzzing (SQLi, CMDi, XSS, Proto-Pollution)
        │       └── 2.4 DoS & RFC Abuse (Unmasked Frames, Frame Length, Ping Flood)
        │
        ├──> [R3: 5 Distinct Bypass & Mutation Strategies]
        │       ├── S1: Origin Header Manipulation
        │       ├── S2: Subprotocol Spoofing & Tampering
        │       ├── S3: Hop-by-Hop & Upgrade Smuggling / Casing
        │       ├── S4: Extension & Compression Fuzzing (permessage-deflate)
        │       └── S5: Auth Token & Parameter Precedence Manipulation
        │
        └──> [R4: Evidence Generation, Graph Wiring & FP Suppression]
```

---

## 3. Detailed Specification

### R1. WebSocket Endpoints & Handshake Anatomy

#### 1.1 Endpoint Discovery & Candidate Paths
The collector scans target base URLs across common WebSocket route conventions:

| Route Path | Technology / Framework | Common Protocol / Usage |
|---|---|---|
| `/ws`, `/wss` | Generic WebSocket | Plain WS / WSS generic channel |
| `/websocket`, `/api/ws`, `/api/v1/ws`, `/v1/ws`, `/v2/ws` | REST API Gateways | API event streaming and notifications |
| `/socket.io/`, `/socket.io/?EIO=4&transport=websocket` | Socket.IO / Engine.IO | Real-time bi-directional event bus |
| `/cable` | ActionCable (Ruby on Rails) | PubSub channel subscriptions |
| `/sockjs/websocket`, `/sockjs/` | SockJS | Emulated / fallback WebSocket transport |
| `/graphql-ws`, `/subscriptions`, `/graphql/subscriptions` | GraphQL Subscriptions | `graphql-ws` and `graphql-transport-ws` |
| `/primus/`, `/engine.io/` | Primus / Node.js Engine | Real-time framework abstractions |
| `/chat`, `/chat/ws`, `/notifications`, `/stream`, `/live` | Interactive Webapps | User messaging, feeds, live status |
| `/signalr`, `/signalr/connect`, `/hub` | ASP.NET SignalR | RPC / hub messaging |

#### 1.2 RFC 6455 Handshake Anatomy & Verification
The WebSocket handshake is initiated via an HTTP/1.1 `GET` request upgrading the protocol:

```http
GET /ws HTTP/1.1
Host: target.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.example.com
Sec-WebSocket-Protocol: chat, superchat
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
```

**Handshake Validation Algorithm (RFC 6455 §4.2.2)**:
1. Expected Status Code: `101 Switching Protocols`.
2. Expected `Upgrade` Header: Must contain `websocket` (case-insensitive).
3. Expected `Connection` Header: Must contain `Upgrade` (case-insensitive).
4. `Sec-WebSocket-Accept` Verification:
   $$\text{Sec-WebSocket-Accept} = \text{Base64}(\text{SHA-1}(\text{Sec-WebSocket-Key} + \text{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"}))$$
   - Example: If `Sec-WebSocket-Key` is `dGhlIHNhbXBsZSBub25jZQ==`, `Sec-WebSocket-Accept` MUST be `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.

---

### R2. Multi-Vulnerability Detection Logic

#### 2.1 Cross-Site WebSocket Hijacking (CSWSH) (CWE-346 / CWE-1385)
- **Mechanism**: Browsers automatically send ambient authentication cookies with cross-origin WebSocket handshakes. If the server does not strictly validate the `Origin` header against an allowlist, an attacker page can open a WebSocket to the target, hijack the authenticated session, and exfiltrate private streaming data or trigger unauthorized actions.
- **Probe Variations**:
  1. `Origin: null` (Sandboxed iframe / privacy mode simulation)
  2. `Origin: https://evil.com` (Arbitrary attacker origin)
  3. `Origin: https://target.example.com.attacker.com` (Subdomain suffix matching bypass)
  4. `Origin: https://attackertarget.example.com` (Prefix matching bypass)
  5. `Origin: http://target.example.com` (Insecure scheme downgrade)
- **Vulnerability Signature**: Server returns `101 Switching Protocols` with valid `Sec-WebSocket-Accept` when supplied with untrusted/spoofed `Origin` headers while session credentials/cookies are active.

#### 2.2 Unauthenticated Handshake & Token Leakage (CWE-287 / CWE-598 / CWE-200)
- **Mechanism**:
  1. **Anonymous Handshake Access**: Protected WebSocket routes accepting connections without `Authorization` headers, cookies, or credentials, permitting unauthorized access to private data streams.
  2. **Broken Token Acceptance**: Server accepts malformed, stripped, or expired tokens (`Bearer null`, `Bearer expired_token`, `alg: none` JWTs).
  3. **Query Parameter Token Leakage**: Passing sensitive credentials in URL query parameters (`?token=...`, `?access_token=...`, `?apiKey=...`), which leak to access logs, proxy caches, Referer headers, and browser history.
- **Vulnerability Signature**:
  - `101 Switching Protocols` on anonymous handshake to protected endpoint.
  - Presence of credentials in URL query parameters during successful handshake.

#### 2.3 Bi-Directional Frame Fuzzing & Injection (CWE-89, CWE-78, CWE-79, CWE-1321)
- **Mechanism**: Data transmitted in WebSocket text/JSON frames often bypasses HTTP perimeter WAF filters. The prober sends structured text/JSON messages containing injection payloads:
  1. **SQL Injection (SQLi)**:
     - Payloads: `' OR '1'='1' --`, `1' UNION SELECT @@version, user() --`, `{"query": "admin' --", "id": 1}`
     - Signatures: `SQL syntax.*MySQL`, `PostgreSQL.*ERROR`, `ORA-[0-9]{5}`, `sqlite3.OperationalError`.
  2. **OS Command Injection (CMDi)**:
     - Payloads: `; id`, `| whoami`, `& cat /etc/passwd`, `{"action": "ping", "host": "127.0.0.1; id"}`
     - Signatures: `uid=[0-9]+.*gid=[0-9]+`, `root:x:0:0:`, `Windows IP Configuration`.
  3. **Cross-Site Scripting (XSS)**:
     - Payloads: `<script>alert('ARGUS_WS_XSS')</script>`, `<img src=x onerror=alert(1)>`
     - Signatures: Verbatim unescaped reflection in broadcast frames.
  4. **Prototype Pollution**:
     - Payloads: `{"__proto__": {"admin": true, "polluted": true}}`, `{"constructor": {"prototype": {"isAdmin": true}}}`
     - Signatures: Modification of subsequent response state or server crash/reflection indicating prototype mutation.

#### 2.4 WebSocket DoS & RFC 6455 Frame Protocol Abuse (CWE-400, CWE-799, RFC 6455 §5.1)
- **Mechanism**:
  1. **Unmasked Client Frame Acceptance (RFC 6455 §5.1 Violation)**: Client-to-server frames MUST be masked. If a server accepts unmasked frames without immediately closing the connection with status `1002 (Protocol Error)`, it is vulnerable to cache poisoning and proxy frame injection.
  2. **Oversized Frame Length / Buffer Exhaustion**: Sending frame length headers declaring huge payloads (`0x7FFFFFFFFFFFFFFF` or 64MB+) to test if the server pre-allocates memory or crashes.
  3. **Ping/Pong & Message Flooding**: Dispatching 100+ rapid ping frames (`0x9`) or message bursts without backpressure or rate limiting.
- **Vulnerability Signature**:
  - Server accepts unmasked frames (`mask=0`) without dropping connection with close code `1002`.
  - Server hangs or crashes without returning close code `1009 (Message Too Big)` on oversized frames.
  - Server processes unlimited frame bursts without throttling (HTTP `429` or close code `1008`).

---

### R3. Bypass & Mutation Strategies (5 Distinct Strategies)

| Strategy ID | Strategy Name | Technique / Mutation Mechanism | Target Defense / Parser Flaw |
|---|---|---|---|
| **STRAT-1** | **Origin Header Manipulation** | • `Origin: null`<br>• `Origin: https://evil.com`<br>• `Origin: https://target.com.evil.com`<br>• `Origin: https://eviltarget.com`<br>• `Origin: http://target.com`<br>• `Origin: https://TARGET.COM` | Bypasses weak regexes, suffix matching, missing scheme checks, and null-origin trust flaws. |
| **STRAT-2** | **Subprotocol Tampering** | • `Sec-WebSocket-Protocol: graphql-ws, soap, chat, binary`<br>• `Sec-WebSocket-Protocol: admin, debug, internal, raw`<br>• `Sec-WebSocket-Protocol: unauthorized-proto, *`<br>• `Sec-WebSocket-Protocol: graphql-ws\t` | Bypasses subprotocol-based routing rules and accesses hidden administrative subprotocols. |
| **STRAT-3** | **Hop-by-Hop & Upgrade Header Smuggling** | • `Connection: keep-alive, Upgrade`<br>• `Connection: close, Upgrade`<br>• `Upgrade: WebSocket` (casing)<br>• `Upgrade: websocket; `<br>• Duplicate `Upgrade` headers | Bypasses intermediate reverse proxies, CDNs, and WAFs using strict header parsing. |
| **STRAT-4** | **Extension & Compression Fuzzing** | • `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits`<br>• `Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover`<br>• Malformed: `client_max_window_bits=99999`<br>• Unknown extensions | Bypasses compression filters and triggers memory allocation bugs or compression bombs in zlib handlers. |
| **STRAT-5** | **Auth Token & Query Precedence Manipulation** | • Query token variations: `?token=`, `?access_token=`, `?apiKey=`, `?ticket=`<br>• Stripped/empty token values (`?token=null`, `?token=0`)<br>• Conflicting header vs query token precedence (`Authorization: Bearer <valid>` + `?token=<invalid>`)<br>• Algorithm confusion JWTs (`alg: none`) | Bypasses token validation middleware by exploiting token extraction precedence and parser leniency. |

---

### R4. Evidence Generation & False Positive Suppression Criteria

#### 4.1 Evidence Generation Matrix

| Vulnerability Type | Severity | CVSS v3.1 | CWE ID | Evidence Category | Title Format |
|---|---|---|---|---|---|
| **CSWSH** | High | 8.8 | CWE-346 / CWE-1385 | `websocket_security` | `Cross-Site WebSocket Hijacking (CSWSH) Exposed: {url}` |
| **Unauthenticated Handshake** | High / Medium | 7.5 | CWE-287 | `websocket_security` | `Unauthenticated WebSocket Handshake Allowed: {url}` |
| **Query Token Leakage** | Medium | 5.3 | CWE-598 / CWE-200 | `websocket_security` | `WebSocket Authentication Token Leaked in Query Parameter: {url}` |
| **Frame SQL Injection** | Critical / High | 9.0 | CWE-89 | `websocket_security` | `WebSocket Frame SQL Injection Vulnerability: {url}` |
| **Frame Command Injection** | Critical | 9.8 | CWE-78 | `websocket_security` | `WebSocket Frame Command Injection Vulnerability: {url}` |
| **Frame XSS Reflection** | High | 7.2 | CWE-79 | `websocket_security` | `WebSocket Frame Stored/Reflected XSS: {url}` |
| **Frame Prototype Pollution** | High | 7.5 | CWE-1321 | `websocket_security` | `WebSocket Frame Prototype Pollution: {url}` |
| **Unmasked Frame Acceptance** | Medium | 5.3 | RFC 6455 §5.1 / CWE-400 | `websocket_security` | `WebSocket Server Accepts Unmasked Client Frames (RFC 6455 Violation): {url}` |
| **Missing Frame Rate Limiting** | Medium / Low | 4.3 | CWE-799 | `websocket_security` | `WebSocket Message Flooding & Missing Rate Limiting: {url}` |

#### 4.2 False Positive Suppression Rules

1. **Handshake Rejection Status Codes**:
   - HTTP responses `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `405 Method Not Allowed`, or `426 Upgrade Required` indicate **properly hardened security controls** and MUST NOT generate vulnerability evidence.
2. **Strict Handshake Verification**:
   - Status `101 Switching Protocols` is only treated as a valid handshake if the `Sec-WebSocket-Accept` header matches the cryptographic SHA-1/Base64 hash of the client's `Sec-WebSocket-Key`. Mock or generic 101 responses missing valid `Sec-WebSocket-Accept` MUST NOT be confirmed.
3. **In-Band Authentication Rejection**:
   - If an endpoint returns `101 Switching Protocols` but immediately closes the connection or requires an in-band authentication frame before processing application commands, and drops unauthenticated sessions with close code `1008 (Policy Violation)`, it MUST NOT be flagged as unauthenticated handshake.
4. **RFC 6455 Close Status Codes Verification**:
   - A server properly responding with standard RFC 6455 close codes is demonstrating **hardened compliance**:
     - `1000 Normal Closure`: Clean disconnect.
     - `1002 Protocol Error`: Server correctly rejecting malformed or unmasked client frames.
     - `1003 Unsupported Data`: Server rejecting unexpected binary/text formats.
     - `1008 Policy Violation`: Server rejecting unauthorized origins, missing auth tokens, or rate limit breaches.
     - `1009 Message Too Big`: Server correctly enforcing frame size limits.
5. **Injection Signature Specificity**:
   - SQLi/CMDi evidence MUST match unambiguous engine-specific error signatures (e.g. `SQL syntax`, `pg_query`, `root:x:0:0:`). Generic HTTP 400 or JSON parse errors (`SyntaxError: Unexpected token`) MUST NOT trigger injection findings.

---

## Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|---|---|---|---|---|---|---|
| 1 | Handshake | Endpoint Route Discovery | Probes standard and framework-specific WebSocket paths (`/ws`, `/socket.io`, `/cable`, `/graphql-ws`) | Base URL, path dictionary | Candidate endpoint list | Non-200/101 HTTP status codes ignored | Spec & Codebase Analysis |
| 2 | Handshake | RFC 6455 Key-Accept Verification | Verifies `Sec-WebSocket-Accept` matches `SHA1(Key + GUID)` Base64 string | `Sec-WebSocket-Key` string | `True` / `False` verification | Rejection on invalid hash | RFC 6455 §4.2.2 |
| 3 | CSWSH | Origin Header Validation Prober | Tests whether server accepts unauthorized cross-origin connections | `Origin: null`, `evil.com`, spoofed domain | `101 Switching Protocols` vs `403 Forbidden` | 403/401 on hardened servers | RFC 6454 / OWASP CSWSH |
| 4 | Authentication | Anonymous Handshake Auditor | Tests if protected endpoints allow connections with no auth headers or cookies | Empty headers/cookies | `101` (vulnerable) vs `401/403` (secure) | 401 Unauthorized | CWE-287 Spec |
| 5 | Authentication | Token Query Leakage Detector | Detects authentication tokens transmitted in URL query strings | URL with `?token=...`, `?access_token=...` | `Evidence` of token leakage | Redacts token in metadata logs | CWE-598 / CWE-200 |
| 6 | Frame Injection | JSON / Text Frame SQLi Prober | Injects SQL payloads into WebSocket message frames and parses error responses | SQLi vectors (`' OR '1'='1'`) | Matched database error signatures | 1007 / JSON error / 1008 | OWASP Testing Guide |
| 7 | Frame Injection | JSON / Text Frame CMDi Prober | Injects OS command payloads into WebSocket message frames | CMDi vectors (`; id`, `| whoami`) | Matched OS command output signatures | Syntax error / 1008 | CWE-78 Spec |
| 8 | Frame Injection | Frame XSS & DOM Reflection Auditor | Detects unescaped script tag reflection in broadcast WebSocket frames | XSS payloads (`<script>alert(1)</script>`) | Reflected unescaped snippet | Sanitized echo / 1003 | CWE-79 Spec |
| 9 | Frame Injection | Server Prototype Pollution Prober | Injects `__proto__` and `constructor` payloads into JSON frames | Prototype pollution JSON payloads | Modified object state / error signature | Parse error / Sanitized | CWE-1321 Spec |
| 10 | Protocol Abuse | Unmasked Client Frame Auditor | Sends unmasked frames (`mask=0`) to test RFC 6455 §5.1 compliance | Raw unmasked WS frame | Acceptance vs Close `1002` | Server closes connection with 1002 | RFC 6455 §5.1 |
| 11 | Protocol Abuse | Oversized Frame Length Prober | Sends frame headers with large payload length declarations | 64-bit frame length header (`16MB+`) | Close `1009 (Message Too Big)` vs Hang | Server returns 1009 or closes | RFC 6455 §5.2 / CWE-400 |
| 12 | Protocol Abuse | Ping Flood & Message Rate Limiting | Dispatches rapid bursts of ping/data frames to check throttling | 50-100 frames in <100ms | Close `1008 (Policy Violation)` / HTTP 429 | Throttling or drop | CWE-799 Spec |
| 13 | Mutation | Origin Manipulation Strategy | Applies 6 origin variations (null, evil, subdomain suffix, prefix, casing) | Handshake headers | Mutated HTTP upgrade request | 403 Forbidden on valid defense | R3 Strategy 1 |
| 14 | Mutation | Subprotocol Tampering Strategy | Manipulates `Sec-WebSocket-Protocol` with admin, debug, and comma-separated lists | Subprotocol header string | Mutated handshake request | Negotiated subprotocol / 400 | R3 Strategy 2 |
| 15 | Mutation | Hop-by-Hop Smuggling Strategy | Mutates `Connection: keep-alive, Upgrade` and `Upgrade` header casing | Header dictionaries | Mutated HTTP upgrade request | Proxy bypass / Normal upgrade | R3 Strategy 3 |
| 16 | Mutation | Extension Compression Strategy | Tests `permessage-deflate` parameter boundaries and malformed syntax | Extension header string | Mutated extension handshake | `Sec-WebSocket-Extensions` response | R3 Strategy 4 |
| 17 | Mutation | Auth Token Precedence Strategy | Tests token variations across query params and `Authorization` headers | Token param mutations | Mutated URL & headers | 401 / 403 on invalid tokens | R3 Strategy 5 |
| 18 | Graph | Attack Surface Graph Integration | Links live hosts to WebSocket endpoints and confirmed vulnerabilities | `Evidence` items | `Node` & `HAS_VULNERABILITY` edges | Graph node deduplication | `argus/graph/attack_surface.py` |
| 19 | Pipeline | TaskGenerator DAG Scheduling | Schedules `websocket_security` task upon discovering WS endpoints/tech | Mission technology state | Scheduled DAG step | Policy bypass if disabled | `argus/planning/task_generator.py` |
| 20 | Registry | Tool & Specialist Plugin Adapter | Registers `WebSocketSecurityCollector` in plugin manager and registry | Plugin ID `websocket_security` | Executable collector instance | ValueError if missing | `argus/runtime/plugins.py` |

---

## Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---|---|---|
| 1 | Handshake Protocol | HTTP/2 Extended CONNECT Handshake (RFC 8441) | Server rejects standard HTTP/1.1 Upgrade headers or requires `:protocol = websocket` pseudo-header. Prober falls back to HTTP/1.1. |
| 2 | CSWSH Detection | Cross-Origin Allowed via Public WS Gateway | Public notifications/tickers intentionally accept any Origin. Collector checks if endpoint requires authentication before flagging high severity CSWSH. |
| 3 | Frame Masking | Client sends 0-byte unmasked frame | Server must still enforce masking even for 0-byte payloads under RFC 6455 §5.1. Secure servers send Close `1002`. |
| 4 | Subprotocol Selection | Server accepts unrecognized subprotocol | Server echoes back an unsupported subprotocol in `Sec-WebSocket-Protocol` without validating it. Flagged as subprotocol reflection misconfiguration. |
| 5 | Token Leakage | Token in query parameter on public unauthenticated stream | Collector verifies whether token query param grants elevated privileges vs ephemeral session ID before setting severity. |
| 6 | Frame Injection | Server wraps messages in proprietary binary encoding (Protobuf/MessagePack) | Raw text injection fails deserialization on server. Collector detects binary frame opcode `0x2` and reports structured format requirement. |
| 7 | Fragmentation DoS | Unfinished fragmented frames (`FIN=0` without closing frame) | Server holds open buffer waiting for continuation frame (`opcode 0x0`). Hardened servers implement frame reassembly timeouts. |
| 8 | Ping-Pong Handling | Client sends unsolicited `Pong` (`opcode 0xA`) frames | Server ignores unsolicited Pong frames per RFC 6455 §5.5.3 without closing connection or crashing. |

---

## 4. Caveats

1. **Raw TCP / Socket Probing vs HTTP Client Abstraction**: In environments where Python's `httpx` or `requests` cannot directly negotiate raw bi-directional WebSocket frames after HTTP 101 Upgrade, the prober should utilize standard library `socket` / `ssl` or `websockets` client libraries wrapped within the `AuthenticatedHttpClient` abstraction.
2. **Network Timeout Sensitivity**: WebSocket rate limiting and DoS tests should avoid aggressive connection flooding that could degrade real assessment targets; prober bursts must be bounded (max 50 frames) with short timeouts.
3. **No Code Modifications**: Per strict read-only assignment, no implementation files or test files were modified during this specification sprint.

---

## 5. Conclusion

The WebSocket Security Detection Module for ARGUS has been fully specified across all required functional dimensions (R1-R4):
- **Handshake & Endpoints**: 9+ standard route conventions, complete RFC 6455 §4.2.2 verification algorithms.
- **Vulnerability Coverage**: CSWSH, Unauthenticated Handshake, Query Token Leakage, SQLi/CMDi/XSS/Prototype Pollution frame injection, Unmasked Frame abuse, Oversized frames, and Ping flooding.
- **Mutation Strategies**: 5 distinct bypass strategies (Origin manipulation, Subprotocol tampering, Hop-by-hop smuggling, Extension fuzzing, Auth precedence).
- **Evidence & False Positive Suppression**: Strict status code checks, `Sec-WebSocket-Accept` validation, RFC 6455 close status code checks (`1000`, `1002`, `1008`, `1009`), and KnowledgeGraph `HAS_VULNERABILITY` edge generation.

---

## 6. Verification Method

To verify the specification against the ARGUS test suite and runtime architecture:
1. Verify the handoff document exists and is complete:
   ```bash
   test -f /home/varun/argus/.agents/spec_miner_1/handoff.md && echo "Handoff verified"
   ```
2. Verify baseline test suite zero regression:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
3. Inspect data models and plugin registries for contract alignment:
   - `argus/collectors/__init__.py`
   - `argus/runtime/plugins.py`
   - `argus/graph/attack_surface.py`
   - `argus/planning/task_generator.py`

