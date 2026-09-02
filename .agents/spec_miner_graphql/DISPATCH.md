## 2026-08-31T12:03:33Z
You are Survey Spec Miner: GraphQL Security Spec Miner for Sprint 17 (GraphQL Security).

Your Working Directory is: /home/varun/argus/.agents/spec_miner_graphql/
Read ORIGINAL_REQUEST at: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Task:
1. Analyze the exact technical specifications and detection logic required for GraphQL security:
   - **R1: Endpoint & Injection Point Discovery:** Common GraphQL path signatures (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/v2/graphql`, etc.), GET parameter patterns (`?query=...`), POST JSON payloads (`{"query": "...", "variables": {}}`), POST raw content-type (`application/graphql`).
   - **R2.1: Introspection & Schema Leakage:** Full schema queries (`__schema { types { name fields { name } } }`), `__type(name: "Query")`, field suggestion signatures (`Did you mean ...`, `Cannot query field ...`, Levenshtein suggestions).
   - **R2.2: Query Depth & Complexity DoS:** Deep nested queries (e.g., circular/self-referencing types like `user { friends { friends { friends ... } } }`), recursive fragment expansion (`fragment F on User { ...F }` or nested fragment chains). Safe payloads vs unbounded recursion.
   - **R2.3: Batching / Query Multiplexing:** Array of queries (`[{"query": "..."}, {"query": "..."}]`) vs Alias multiplexing (`query { a: field, b: field, c: field ... }`) to bypass rate limits or query limits.
   - **R2.4: Field-Level Access Control & Injection:** Probing protected fields (e.g., `admin`, `system`, `debug`, `private`, `internal`, `token`, `secret`, `users`, `passwordHash`) and SQLi/Command injection patterns in GraphQL field arguments (e.g. `user(id: "1' OR '1'='1")`, `search(q: "'; sleep...")`).
   - **R3: Bypass & Mutation Strategies (at least 5 distinct strategies):**
     1. HTTP Method Swapping (GET vs POST vs PUT vs POST with form urlencoded)
     2. Content-Type manipulation (`application/graphql`, `application/json`, `application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data`)
     3. Whitespace / Comment obfuscation (`# comment\n`, query line breaks, unicode whitespace, commas as whitespace)
     4. Alias pollution / Duplicated fields
     5. Operation Name manipulation / Query variable extraction
     6. Directive fuzzing / @skip / @include bypass
   - Evidence generation requirements, severities (High, Medium, Low), false positive controls.
2. Write a detailed specification and detection blueprint report to `/home/varun/argus/.agents/spec_miner_graphql/handoff.md`.
3. When finished, send a brief completion message back. Do NOT send intermediate progress messages.
