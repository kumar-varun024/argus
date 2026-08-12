import os
from argus.workspace.repository import ConversationRepository, ProjectRepository, WorkspaceTaskRepository

def test_database_isolation():
    """Verify that tests do not write to ~/.argus/workspace by default."""
    # Ensure ARGUS_WORKSPACE_DIR was set by conftest.py
    assert "ARGUS_WORKSPACE_DIR" in os.environ
    assert os.environ["ARGUS_WORKSPACE_DIR"] != os.path.expanduser("~/.argus/workspace")
    
    # Initialize repositories
    conv_repo = ConversationRepository()
    proj_repo = ProjectRepository()
    task_repo = WorkspaceTaskRepository()
    
    # Verify paths are bound to the test environment, not the user's home directory
    assert str(conv_repo.data_dir).startswith(os.environ["ARGUS_WORKSPACE_DIR"])
    assert str(proj_repo.data_dir).startswith(os.environ["ARGUS_WORKSPACE_DIR"])
    assert str(task_repo.data_dir).startswith(os.environ["ARGUS_WORKSPACE_DIR"])
