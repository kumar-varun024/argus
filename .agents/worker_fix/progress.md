# Progress Log — worker_fix

Last visited: 2026-09-02T18:42:50Z

## Current Status
- Fixed Defect 1: Updated `_derive_default_scope` in `argus/runtime/mission.py` to extract IPv6 address within brackets `[::1]:9000` -> `::1`.
- Fixed Defect 2: Updated `_derive_host_dict` in `argus/collectors/httpx.py` and `_derive_endpoint_dict` in `argus/collectors/katana.py` to correctly handle bracketed IPv6 with ports, normalize scheme-less hosts, and prevent path duplication.
- Fixed Defect 3: Guarded all 8 status code comparisons in `argus/collectors/oauth.py` with `if status is not None and ...` to handle `NoneType` status codes gracefully.
- Fixed Defect 4: Registered `mission` into `mission_manager._active_missions[mission.id] = mission` in `ScanEngine.run` in `argus/scanning/engine.py`.
- Running verification tests: `tests/authorization/test_adversarial_scope_recon.py`.
