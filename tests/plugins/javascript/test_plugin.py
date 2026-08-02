import pytest
from argus.plugins.javascript.plugin import JavaScriptPlugin
from argus.plugins.manifest import PluginManifest
from argus.runtime.mission import Mission

def test_javascript_plugin_initialization():
    plugin = JavaScriptPlugin()
    assert plugin.manifest.name == "javascript_specialist"
    assert plugin.specialist is not None

def test_javascript_plugin_execute():
    plugin = JavaScriptPlugin()
    mission = Mission("test_target")
    plugin.execute(mission)
    assert hasattr(mission, "javascript")
