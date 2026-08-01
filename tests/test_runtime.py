import pytest
import os
import shutil
from argus.runtime.mission import Mission, MissionState
from argus.runtime.lifecycle import MissionLifecycle
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.scheduler import MissionScheduler
from argus.runtime.manager import MissionManager
from argus.runtime.context import MissionContext

def test_mission_lifecycle_transitions():
    mission = MissionLifecycle.create("target.local")
    assert mission.status == MissionState.CREATED
    
    MissionLifecycle.start(mission)
    assert mission.status == MissionState.RUNNING
    
    MissionLifecycle.pause(mission)
    assert mission.status == MissionState.PAUSED
    
    with pytest.raises(ValueError):
        MissionLifecycle.start(mission)
        
    MissionLifecycle.resume(mission)
    assert mission.status == MissionState.RUNNING
    
    MissionLifecycle.complete(mission)
    assert mission.status == MissionState.COMPLETED
    assert mission.phase == "finished"
    
    with pytest.raises(ValueError):
        MissionLifecycle.cancel(mission)

def test_mission_checkpointing():
    test_dir = ".argus/test_checkpoints"
    checkpointer = MissionCheckpointer(storage_dir=test_dir)
    
    mission = Mission(target="example.com", status=MissionState.RUNNING, phase="recon")
    mission.scope.append("test_scope")
    
    checkpointer.checkpoint(mission)
    
    recovered = checkpointer.recover(mission.id)
    assert recovered.id == mission.id
    assert recovered.target == "example.com"
    assert recovered.status == MissionState.RUNNING
    assert recovered.phase == "recon"
    assert "test_scope" in recovered.scope
    
    # Cleanup
    shutil.rmtree(test_dir, ignore_errors=True)

def test_mission_scheduler_phases():
    scheduler = MissionScheduler()
    mission = Mission(target="test.local", status=MissionState.RUNNING, phase="planning")
    
    execution_record = []
    
    def recon_handler(m: Mission):
        execution_record.append("recon_ran")
        
    scheduler.register_phase_handler("recon", recon_handler)
    
    # Step 1: planning -> recon
    scheduler.step(mission)
    assert mission.phase == "recon"
    
    # Step 2: recon runs, goes to intelligence
    scheduler.step(mission)
    assert "recon_ran" in execution_record
    assert mission.phase == "intelligence"

def test_mission_context():
    mission = Mission("test.local")
    MissionContext.set_active_mission(mission)
    assert MissionContext.get_active_mission().id == mission.id
    
    MissionContext.clear()
    assert MissionContext.get_active_mission() is None
