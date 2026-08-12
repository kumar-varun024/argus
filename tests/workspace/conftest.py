import os
import pytest

@pytest.fixture(autouse=True)
def isolate_workspace_data(tmp_path):
    """Ensure that all tests use a temporary directory for workspace data."""
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
