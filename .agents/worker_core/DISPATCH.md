## 2026-08-30T19:55:08Z
You are the Senior Security Implementation Specialist for Sprint 16: Insecure Deserialization Detection Module.

Working directory: /home/varun/argus
Your agent directory: /home/varun/argus/.agents/worker_core/
Please read:
- /home/varun/argus/ORIGINAL_REQUEST.md
- /home/varun/argus/PROJECT.md
- /home/varun/argus/.agents/orchestrator/implementation_plan.md
- /home/varun/argus/.agents/explorer_2/handoff.md

### Core Mandate
Implement the complete Insecure Deserialization detection module and all pipeline/graph integrations across the following files:
1. `argus/collectors/deserialization.py` (New file)
   - Follow `BaseCollector` pattern (`argus/collectors/base.py` / `argus/collectors/xml_parser.py` / `ssrf.py`).
   - Enums: `DeserializationFormat` (JAVA, PYTHON_PICKLE, PHP_SERIALIZE, RUBY_MARSHAL, DOTNET_VIEWSTATE, DOTNET_BINARY_FORMATTER), `DeserializationTechnique`, `DeserializationMutationStrategy` (BASE64, DOUBLE_BASE64, GZIP_BASE64, HEX, URL_ENCODE, CONTENT_TYPE_MANIPULATION), `DeserializationResult`.
   - Error Signatures & Markers:
     * Java: Markers `\xac\xed\x00\x05` / `rO0AB`, regex for `ClassNotFoundException`, `InvalidClassException`, `StreamCorruptedException`, `OptionalDataException`, `ObjectStreamException`.
     * Python Pickle: Markers `gASV`, `\x80\x03`, `cos\nsystem`, regex for `UnpicklingError`, `_pickle.UnpicklingError`, `invalid load key`, `pickle data was truncated`, `TypeError: a bytes-like object is required`.
     * PHP Serialize: Markers `O:4:"User":`, `a:2:{`, regex for `unserialize(): Error at offset`, `unserialize(): Node no longer exists`, `PHP Notice: unserialize()`, `PHP Warning: unserialize()`.
     * Ruby Marshal: Markers `\x04\x08`, `BAh`, regex for `TypeError: incompatible marshal file format`, `ArgumentError: marshal data too short`, `dump format error`.
     * .NET: Markers `/wEPDw`, `AAEAAAD/////`, regex for `SerializationException`, `The input stream is not a valid binary format`, `ViewStateException`, `Invalid viewstate`, `JsonSerializationException`.
   - `DeserializationPayloadGenerator`: Generates payloads with >= 5 distinct bypass mutation strategies (Base64, Double Base64, Gzip compression, Hex, URL encoding, Content-Type manipulation).
   - `DeserializationAnalyzer`: Marker detection, error signature extraction, false positive suppression (reflection echo suppression, benign Base64 rejection, generic 404/500 suppression, baseline subtraction).
   - `DeserializationCollector`: Inherits from `BaseCollector`. Tests injection points (POST body, POST JSON, GET query, Cookies, Headers) using `AuthenticatedHttpClient`. Emits `Evidence` (category="deserialization", severity="critical"/"high", status="CONFIRMED", confidence >= 0.90, CWE-502). Creates in-mission `AttackSurfaceGraph` nodes (`live_host`, `endpoint`, `vulnerability`) and connects `HAS_ENDPOINT` & `HAS_VULNERABILITY` edges. Exposes `InsecureDeserializationCollector` and `DeserializationValidationCollector` aliases.
2. `argus/collectors/__init__.py`: Export `DeserializationCollector`, `InsecureDeserializationCollector`, `DeserializationValidationCollector`, `DeserializationFormat`, `DeserializationMutationStrategy`, etc.
3. `argus/runtime/registry.py`: Register `Tool(id="deserialization", ...)` with priority 95, capability `"deserialization_detector"`, and aliases (`insecure_deserialization`, `pickle`, `unserialize`, `java_deserialization`, etc.).
4. `argus/runtime/plugins.py`: Add fallback in `PluginExecutorAdapter._instantiate_specialist_fallback`.
5. `argus/planning/task_generator.py`: Add `deserialization` template in `_RECON_TEMPLATES` (dependencies: `["Discover API Endpoints"]`, required_inputs: `["endpoints"]`, category: `TaskCategory.EVIDENCE_CORRELATION`), gap resolution in `_resolve_template_for_gap`, and input handling in `from_gaps`.
6. `argus/graph/attack_surface.py`: Add Section 17 in `AttackSurfaceGraphBuilder.build_from_evidence` and `build` to construct `vulnerability` nodes and `HAS_VULNERABILITY` edges.
7. `argus/reporting/cvss.py`: Add CWE-502 ("Deserialization of Untrusted Data") and CVSS v3.1 9.8 Critical mapping.
