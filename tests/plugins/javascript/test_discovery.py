import pytest
import json
from argus.runtime.mission import Mission
from argus.evidence.model import Evidence
from argus.plugins.javascript.discovery import JavaScriptDiscovery

def test_javascript_discovery():
    mission = Mission("test_target")
    from argus.runtime.mission import JavaScriptState
    mission.javascript = JavaScriptState()
    
    # Mock evidence
    mission.evidence.add(Evidence(
        category="HTML", 
        value='''<html><body>
        <script src="https://example.com/app.bundle.js"></script>
        <script>import('./chunk1.js')</script>
        </body></html>''', 
        source="https://example.com"
    ))
    mission.evidence.add(Evidence(
        category="Network Traffic",
        value="//# sourceMappingURL=app.js.map",
        source="https://example.com/app.js"
    ))
    mission.evidence.add(Evidence(
        category="URL",
        value="",
        source="https://example.com/manifest.json"
    ))

    discovery = JavaScriptDiscovery()
    discovery.discover(mission)

    assert hasattr(mission, "javascript")
    assert len(mission.javascript.files) == 3
    assert "https://example.com/app.bundle.js" in mission.javascript.files
    assert "https://example.com/app.js" in mission.javascript.files
    assert "./chunk1.js" in mission.javascript.files
    
    assert len(mission.javascript.sourcemaps) == 1
    assert "app.js.map" in mission.javascript.sourcemaps
    
    assert len(mission.javascript.manifests) == 1
    assert "https://example.com/manifest.json" in mission.javascript.manifests
    
    # Check observations generated
    assert hasattr(mission, "findings")
    assert len(mission.findings) > 0

def test_javascript_discovery_extensions_and_imports():
    mission = Mission("test_target")
    from argus.runtime.mission import JavaScriptState
    mission.javascript = JavaScriptState()

    # JS/MJS extensions, chunk, bundle, module, sourcemaps (using comment styles), and imports
    js_code = '''
    import defaultExport from './some-module.module.js';
    import { someHelper } from './helper.mjs';
    import * as chunk from './lazy-chunk.chunk.js';
    export { other } from './exporter.js';
    import './side-effect';
    import "./another-side-effect.js";
    
    // Dynamic import
    const load = () => import('./dynamic-import.js');

    /*# sourceMappingURL=inline-multiline.js.map */
    '''
    
    mission.evidence.add(Evidence(
        category="javascript",
        value=js_code,
        source="https://example.com/app.js"
    ))

    discovery = JavaScriptDiscovery()
    discovery.discover(mission)

    # Verify discovered files
    files = mission.javascript.files
    assert "./some-module.module.js" in files
    assert "./helper.mjs" in files
    assert "./lazy-chunk.chunk.js" in files
    assert "./exporter.js" in files
    assert "./another-side-effect.js" in files
    assert "./side-effect" in files
    assert "./dynamic-import.js" in files
    
    # Verify discovered sourcemaps
    assert "inline-multiline.js.map" in mission.javascript.sourcemaps

def test_javascript_discovery_html_manifests_and_sourcemaps():
    mission = Mission("test_target")
    from argus.runtime.mission import JavaScriptState
    mission.javascript = JavaScriptState()

    html_content = '''
    <html>
      <head>
        <link rel="manifest" href="/manifest.json">
        <link href="/app-manifest.json" rel="manifest">
      </head>
      <body>
        <script src="https://example.com/dist/app.module.js"></script>
        <script>
          /*# sourceMappingURL=another.map */
        </script>
      </body>
    </html>
    '''
    
    mission.evidence.add(Evidence(
        category="HTML",
        value=html_content,
        source="https://example.com/index.html"
    ))

    discovery = JavaScriptDiscovery()
    discovery.discover(mission)

    assert "/manifest.json" in mission.javascript.manifests
    assert "/app-manifest.json" in mission.javascript.manifests
    assert "https://example.com/dist/app.module.js" in mission.javascript.files
    assert "another.map" in mission.javascript.sourcemaps

def test_javascript_discovery_webpack_vite_nextjs_manifests():
    mission = Mission("test_target")
    from argus.runtime.mission import JavaScriptState
    mission.javascript = JavaScriptState()

    # Webpack manifest
    webpack_manifest = {
        "files": {
            "main.js": "/static/js/main.chunk.js",
            "index.html": "/index.html",
            "main.js.map": "/static/js/main.chunk.js.map"
        },
        "entrypoints": [
            "static/js/runtime-main.js",
            "static/js/main.chunk.js"
        ]
    }
    
    mission.evidence.add(Evidence(
        category="webpack manifest",
        value=json.dumps(webpack_manifest),
        source="https://example.com/asset-manifest.json"
    ))

    # Vite manifest
    vite_manifest = {
        "src/main.js": {
            "file": "assets/main.1234.js",
            "src": "src/main.js",
            "isEntry": True,
            "imports": ["_vendor.1234.js"]
        },
        "_vendor.1234.js": {
            "file": "assets/vendor.1234.js",
            "src": "vendor.js"
        }
    }
    
    mission.evidence.add(Evidence(
        category="vite manifest",
        value=json.dumps(vite_manifest),
        source="https://example.com/.vite/manifest.json"
    ))

    # Next.js manifest
    nextjs_manifest = {
        "polyfillFiles": [
            "static/chunks/polyfills.js"
        ],
        "pages": {
            "/": [
                "static/chunks/main.js",
                "static/chunks/pages/index.js"
            ]
        }
    }
    
    mission.evidence.add(Evidence(
        category="next.js manifest",
        value=json.dumps(nextjs_manifest),
        source="https://example.com/_next/build-manifest.json"
    ))

    discovery = JavaScriptDiscovery()
    discovery.discover(mission)

    # Check files discovered from manifests
    files = mission.javascript.files
    # Webpack files
    assert "/static/js/main.chunk.js" in files
    assert "static/js/runtime-main.js" in files
    # Vite files
    assert "assets/main.1234.js" in files
    assert "src/main.js" in files
    assert "_vendor.1234.js" in files
    assert "assets/vendor.1234.js" in files
    assert "vendor.js" in files
    # Next.js files
    assert "static/chunks/polyfills.js" in files
    assert "static/chunks/main.js" in files
    assert "static/chunks/pages/index.js" in files

    # Check sourcemaps discovered from manifests
    sourcemaps = mission.javascript.sourcemaps
    assert "/static/js/main.chunk.js.map" in sourcemaps

    # Check manifest itself is registered
    manifests = mission.javascript.manifests
    assert "https://example.com/asset-manifest.json" in manifests
    assert "https://example.com/.vite/manifest.json" in manifests
    assert "https://example.com/_next/build-manifest.json" in manifests

