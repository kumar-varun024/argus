
import sys
import os
import pytest

class ModulesTracker:
    def __init__(self):
        self.loaded_argus = set()

    def pytest_sessionfinish(self, session, exitstatus):
        for mod_name, mod in list(sys.modules.items()):
            if mod and hasattr(mod, '__file__') and mod.__file__:
                f = mod.__file__
                if '/argus/' in f and not '/site-packages/' in f:
                    rel = os.path.relpath(f, '.')
                    if rel.startswith('argus/'):
                        self.loaded_argus.add(rel)
        with open('.agents/audit_test_runner/loaded_argus_modules.txt', 'w') as f:
            for m in sorted(self.loaded_argus):
                f.write(m + '
')

tracker = ModulesTracker()
pytest.main(['tests/', '-q', '--collect-only'], plugins=[tracker])
