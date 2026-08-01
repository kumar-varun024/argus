import pytest
from argus.plugins.manifest import PluginManifest
from argus.plugins.interfaces import BasePlugin
from argus.plugins.registry import PluginRegistry
from argus.plugins.events import EventBus
from argus.plugins.manager import PluginManager
import tempfile
import os

class DummyPlugin(BasePlugin):
    def initialize(self): pass
    def register(self): pass
    def execute(self, mission): pass
    def shutdown(self): pass

def test_registry_prevents_duplicates():
    registry = PluginRegistry()
    manifest = PluginManifest(
        name="TestPlugin",
        version="1.0",
        author="Admin",
        description="Test",
        entrypoint="test.py"
    )
    plugin = DummyPlugin(manifest)
    
    registry.register(plugin)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(plugin)

def test_registry_permission_validation():
    registry = PluginRegistry()
    manifest = PluginManifest(
        name="EvilPlugin",
        version="1.0",
        author="Admin",
        description="Test",
        entrypoint="test.py",
        permissions=["rm_rf_everything"]
    )
    plugin = DummyPlugin(manifest)
    
    with pytest.raises(ValueError, match="invalid permission"):
        registry.register(plugin)

def test_dependency_resolution():
    registry = PluginRegistry()
    
    manifest_a = PluginManifest(name="PluginA", version="1.0", author="A", description="A", entrypoint="A.py")
    manifest_b = PluginManifest(name="PluginB", version="1.0", author="B", description="B", entrypoint="B.py", dependencies=["PluginA"])
    manifest_c = PluginManifest(name="PluginC", version="1.0", author="C", description="C", entrypoint="C.py", dependencies=["PluginB"])
    
    registry.register(DummyPlugin(manifest_c))
    registry.register(DummyPlugin(manifest_a))
    registry.register(DummyPlugin(manifest_b))
    
    order = registry.resolve_load_order()
    names = [p.manifest.name for p in order]
    
    assert names == ["PluginA", "PluginB", "PluginC"]

def test_circular_dependency():
    registry = PluginRegistry()
    manifest_a = PluginManifest(name="PluginA", version="1.0", author="A", description="A", entrypoint="A.py", dependencies=["PluginB"])
    manifest_b = PluginManifest(name="PluginB", version="1.0", author="B", description="B", entrypoint="B.py", dependencies=["PluginA"])
    
    registry.register(DummyPlugin(manifest_a))
    registry.register(DummyPlugin(manifest_b))
    
    with pytest.raises(ValueError, match="Circular dependency"):
        registry.resolve_load_order()

def test_event_bus_isolation():
    bus = EventBus()
    
    call_count = 0
    def safe_callback(data):
        nonlocal call_count
        call_count += 1
        
    def crashing_callback(data):
        raise Exception("Plugin panicked")
        
    bus.subscribe("TestEvent", crashing_callback)
    bus.subscribe("TestEvent", safe_callback)
    
    # The publish should not crash due to the first callback failing
    bus.publish("TestEvent", {"data": "ok"})
    
    assert call_count == 1
