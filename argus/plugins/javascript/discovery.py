import logging
import re
from typing import List, Dict, Any

from argus.plugins.javascript.models import JavaScriptObservation
from argus.evidence.model import Evidence

logger = logging.getLogger(__name__)

class JavaScriptDiscovery:
    """Discovers JavaScript resources from multiple evidence sources."""

    def __init__(self):
        self.js_extensions = ['.js', '.mjs', '.chunk.js', '.bundle.js', '.module.js']
        self.manifest_indicators = ['manifest.json', '.vite/manifest.json', '_next/build-manifest.json', 'asset-manifest.json']
        
        # Regex for dynamic imports like import('./chunk.js') or import("module")
        self.dynamic_import_pattern = re.compile(r'''import\s*\(\s*['"]([^'"]+)['"]\s*\)''')
        # Regex for static imports (JavaScript imports)
        self.static_import_pattern = re.compile(r'''\b(?:import|export)\b\s+(?:[a-zA-Z0-9_$*,\s{}]+from\s+)?['"]([^'"]+)['"]''')
        # Regex for sourceMappingURL (both //# and /*#)
        self.sourcemap_pattern = re.compile(r'''(?://#|/\*#)\s*sourceMappingURL=([^\s*]+)''')
        # Regex for script tags with src
        self.script_src_pattern = re.compile(r'''<script[^>]+src=['"]([^'"]+)['"]''', re.IGNORECASE)
        # Regex for link tags with rel="manifest"
        self.manifest_link_pattern = re.compile(r'''<link\s+[^>]*?rel=['"]manifest['"][^>]*?href=['"]([^'"]+)['"]''', re.IGNORECASE)
        self.manifest_link_pattern_alt = re.compile(r'''<link\s+[^>]*?href=['"]([^'"]+)['"][^>]*?rel=['"]manifest['"]''', re.IGNORECASE)

    def discover(self, mission) -> None:
        logger.info("JavaScriptDiscovery: Starting discovery...")
        
        # We will use sets to avoid duplicates, but store as lists in the state
        files_found = set(mission.javascript.files) if hasattr(mission.javascript, 'files') else set()
        manifests_found = set(mission.javascript.manifests) if hasattr(mission.javascript, 'manifests') else set()
        sourcemaps_found = set(mission.javascript.sourcemaps) if hasattr(mission.javascript, 'sourcemaps') else set()
        
        new_observations = []
        
        if hasattr(mission, "evidence"):
            evidence_store = mission.evidence
            evidence_list = []
            if hasattr(evidence_store, "get_all"):
                evidence_list = evidence_store.get_all()
            elif hasattr(evidence_store, "all"):
                evidence_list = evidence_store.all()
            elif hasattr(evidence_store, "_evidence"):
                evidence_list = evidence_store._evidence
            elif isinstance(evidence_store, list):
                evidence_list = evidence_store
            elif hasattr(evidence_store, "__iter__"):
                evidence_list = list(evidence_store)

            for ev in evidence_list:
                val = str(ev.value)
                source = str(ev.source)
                category = str(ev.category).lower()
                
                # Check source URL/path for JS files and Manifests
                self._check_url_for_resources(source, ev, files_found, manifests_found, sourcemaps_found, new_observations)
                
                # Check if it's a manifest (by category or source URL)
                is_manifest = (
                    category in ['webpack manifest', 'vite manifest', 'next.js manifest', 'manifest', 'json'] or 
                    any(indicator in source.lower() for indicator in self.manifest_indicators)
                )
                if is_manifest:
                    import json
                    try:
                        data = json.loads(val)
                        temp_files = set()
                        temp_maps = set()
                        temp_manifests = set()
                        self._extract_from_json(data, temp_files, temp_maps, temp_manifests)
                        
                        # Add newly found resources
                        for f in temp_files:
                            if f not in files_found:
                                files_found.add(f)
                                new_observations.append(JavaScriptObservation(
                                    description=f"Discovered JavaScript file from manifest: {f}",
                                    confidence=0.9,
                                    evidence=[ev]
                                ))
                        for m in temp_maps:
                            if m not in sourcemaps_found:
                                sourcemaps_found.add(m)
                                new_observations.append(JavaScriptObservation(
                                    description=f"Discovered Source Map from manifest: {m}",
                                    confidence=0.9,
                                    evidence=[ev]
                                ))
                        for mn in temp_manifests:
                            if mn not in manifests_found:
                                manifests_found.add(mn)
                                new_observations.append(JavaScriptObservation(
                                    description=f"Discovered Manifest from manifest: {mn}",
                                    confidence=0.9,
                                    evidence=[ev]
                                ))
                    except json.JSONDecodeError:
                        # Fallback to content checking
                        self._check_content_for_resources(val, ev, files_found, manifests_found, sourcemaps_found, new_observations)
                
                # If network traffic, HTML, or JavaScript, check value for script tags, sourcemaps, imports
                elif category in ['html', 'network traffic', 'network', 'http response', 'javascript']:
                    self._check_content_for_resources(val, ev, files_found, manifests_found, sourcemaps_found, new_observations)
                    
        # Update mission state
        mission.javascript.files = list(files_found)
        mission.javascript.manifests = list(manifests_found)
        mission.javascript.sourcemaps = list(sourcemaps_found)
        
        if not hasattr(mission, "findings"):
            mission.findings = []
        mission.findings.extend(new_observations)
        
        logger.info(f"JavaScriptDiscovery: Discovered {len(files_found)} files, {len(manifests_found)} manifests, {len(sourcemaps_found)} sourcemaps.")

    def _extract_from_json(self, data: Any, files_found: set, sourcemaps_found: set, manifests_found: set):
        if isinstance(data, str):
            data_lower = data.lower()
            if any(data_lower.endswith(ext) for ext in self.js_extensions) or '.js?' in data_lower:
                files_found.add(data)
            elif data_lower.endswith('.map') or data_lower.endswith('.js.map'):
                sourcemaps_found.add(data)
            elif any(indicator in data_lower for indicator in self.manifest_indicators):
                manifests_found.add(data)
        elif isinstance(data, dict):
            for k, v in data.items():
                self._extract_from_json(k, files_found, sourcemaps_found, manifests_found)
                self._extract_from_json(v, files_found, sourcemaps_found, manifests_found)
        elif isinstance(data, list):
            for item in data:
                self._extract_from_json(item, files_found, sourcemaps_found, manifests_found)

    def _check_url_for_resources(self, url: str, ev: Evidence, files_found: set, manifests_found: set, sourcemaps_found: set, obs: List[JavaScriptObservation]):
        url_lower = url.lower()
        
        # Check for JS files
        if any(url_lower.endswith(ext) for ext in self.js_extensions) or '.js?' in url_lower:
            if url not in files_found:
                files_found.add(url)
                obs.append(JavaScriptObservation(
                    description=f"Discovered JavaScript file: {url}",
                    confidence=1.0,
                    evidence=[ev]
                ))
                
        # Check for Sourcemaps
        if url_lower.endswith('.js.map') or url_lower.endswith('.map'):
            if url not in sourcemaps_found:
                sourcemaps_found.add(url)
                obs.append(JavaScriptObservation(
                    description=f"Discovered Source Map: {url}",
                    confidence=1.0,
                    evidence=[ev]
                ))
                
        # Check for Manifests
        if any(indicator in url_lower for indicator in self.manifest_indicators):
            if url not in manifests_found:
                manifests_found.add(url)
                obs.append(JavaScriptObservation(
                    description=f"Discovered JavaScript Manifest: {url}",
                    confidence=1.0,
                    evidence=[ev]
                ))

    def _check_content_for_resources(self, content: str, ev: Evidence, files_found: set, manifests_found: set, sourcemaps_found: set, obs: List[JavaScriptObservation]):
        # Extract script tags from HTML
        for match in self.script_src_pattern.finditer(content):
            src = match.group(1)
            if src and src not in files_found and (any(src.lower().endswith(ext) for ext in self.js_extensions) or '.js?' in src.lower()):
                files_found.add(src)
                obs.append(JavaScriptObservation(
                    description=f"Discovered JavaScript file via HTML script tag: {src}",
                    confidence=0.9,
                    evidence=[ev]
                ))
                
        # Extract manifest links from HTML
        for pattern in [self.manifest_link_pattern, self.manifest_link_pattern_alt]:
            for match in pattern.finditer(content):
                manifest_url = match.group(1)
                if manifest_url and manifest_url not in manifests_found:
                    manifests_found.add(manifest_url)
                    obs.append(JavaScriptObservation(
                        description=f"Discovered JavaScript Manifest via HTML link tag: {manifest_url}",
                        confidence=0.9,
                        evidence=[ev]
                    ))

        # Extract dynamic imports
        for match in self.dynamic_import_pattern.finditer(content):
            imported = match.group(1)
            if imported and imported not in files_found:
                files_found.add(imported)
                obs.append(JavaScriptObservation(
                    description=f"Discovered dynamic JavaScript import: {imported}",
                    confidence=0.8,
                    evidence=[ev]
                ))
                
        # Extract static imports (JavaScript imports)
        for match in self.static_import_pattern.finditer(content):
            imported = match.group(1)
            is_valid = False
            imported_lower = imported.lower()
            if any(imported_lower.endswith(ext) for ext in self.js_extensions):
                is_valid = True
            elif imported.startswith('.') or imported.startswith('/'):
                # Avoid non-JS file extensions (like CSS, images, etc.)
                if not any(imported_lower.endswith(ext) for ext in ['.css', '.scss', '.sass', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.otf', '.json']):
                    is_valid = True
            
            if is_valid and imported not in files_found:
                files_found.add(imported)
                obs.append(JavaScriptObservation(
                    description=f"Discovered JavaScript import: {imported}",
                    confidence=0.8,
                    evidence=[ev]
                ))
                
        # Extract inline source maps
        for match in self.sourcemap_pattern.finditer(content):
            map_url = match.group(1)
            if map_url and map_url not in sourcemaps_found:
                sourcemaps_found.add(map_url)
                obs.append(JavaScriptObservation(
                    description=f"Discovered Source Map reference: {map_url}",
                    confidence=0.95,
                    evidence=[ev]
                ))
