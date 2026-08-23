import os
import pytest

# Prevent real API calls during tests by enforcing mock mode globally BEFORE any imports
os.environ["ARGUS_LLM_PROVIDER"] = "mock"
for key in ["OPENAI_API_KEY", "DEEPSEEK_API_KEY", "NVIDIA_API_KEY", "GEMINI_API_KEY", "ARGUS_PRIMARY_PROVIDER", "ARGUS_PRIMARY_MODEL"]:
    if key in os.environ:
        del os.environ[key]

@pytest.fixture(autouse=True)
def isolate_workspace_data(tmp_path):
    """Ensure that all tests use a temporary directory for workspace data and no real API keys leak."""
    os.environ["ARGUS_WORKSPACE_DIR"] = str(tmp_path)
    
    # Reinitialize global repositories in api to point to the new temp dir
    try:
        from argus.workspace.api import repository, project_repo, task_repo
        repository.__init__()
        project_repo.__init__()
        task_repo.__init__()
    except ImportError:
        pass
        
    yield
