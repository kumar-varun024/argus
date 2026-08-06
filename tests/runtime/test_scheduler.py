"""Tests for the Task Scheduler (PR3 Sprint 11)."""
import pytest
from argus.runtime.mission import Mission
from argus.planning.models import ResearchTask, TaskCategory
from argus.runtime.executor import TaskScheduler
from argus.runtime.models import TaskState, EventType


@pytest.fixture
def base_mission():
    return Mission(target="test.example.com")


@pytest.fixture
def scheduler(base_mission):
    return TaskScheduler(base_mission, max_workers=2)


@pytest.fixture
def sample_tasks():
    t1 = ResearchTask(title="Task A", description="Desc", goal="G", category=TaskCategory.API_DISCOVERY, priority=0.9)
    t2 = ResearchTask(title="Task B", description="Desc", goal="G", category=TaskCategory.GRAPHQL_ANALYSIS, priority=0.8, dependencies=["Task A"])
    t3 = ResearchTask(title="Task C", description="Desc", goal="G", category=TaskCategory.TECHNOLOGY_DISCOVERY, priority=0.7)
    return [t1, t2, t3]


class TestSchedulerDependencies:
    def test_dependency_resolution_blocks_tasks(self, scheduler, sample_tasks):
        scheduler.schedule_tasks(sample_tasks)
        
        q = scheduler.queue_manager.queue
        
        task_a = next(t for t in q.tasks if t.task_title == "Task A")
        task_b = next(t for t in q.tasks if t.task_title == "Task B")
        task_c = next(t for t in q.tasks if t.task_title == "Task C")
        
        # A and C should be READY (no deps)
        assert task_a.state == TaskState.READY
        assert task_c.state == TaskState.READY
        # B should be BLOCKED (depends on A)
        assert task_b.state == TaskState.BLOCKED

    def test_completing_dependency_unblocks_task(self, scheduler, sample_tasks):
        scheduler.schedule_tasks(sample_tasks)
        
        # Batch 1 should be A and C (max_workers=2)
        batch1 = scheduler.get_executable_batch()
        assert len(batch1) == 2
        titles = [t.task_title for t in batch1]
        assert "Task A" in titles
        assert "Task C" in titles
        
        task_a = next(t for t in batch1 if t.task_title == "Task A")
        
        # B is still BLOCKED
        task_b = scheduler.queue_manager.get_task(sample_tasks[1].id)
        assert task_b.state == TaskState.BLOCKED
        
        # Complete A
        scheduler.report_success(task_a.task_id)
        
        # Now B should be READY when we ask for next batch
        batch2 = scheduler.get_executable_batch()
        assert len(batch2) == 1
        assert batch2[0].task_title == "Task B"


class TestSchedulerConcurrency:
    def test_parallel_scheduling_respects_max_workers(self, base_mission):
        sched = TaskScheduler(base_mission, max_workers=1)
        tasks = [
            ResearchTask(title="T1", description="Desc", goal="G", category=TaskCategory.API_DISCOVERY, priority=0.9),
            ResearchTask(title="T2", description="Desc", goal="G", category=TaskCategory.TECHNOLOGY_DISCOVERY, priority=0.8),
        ]
        sched.schedule_tasks(tasks)
        
        batch = sched.get_executable_batch()
        # Even though T1 and T2 are both READY, max_workers is 1, so only 1 is returned
        assert len(batch) == 1
        assert batch[0].task_title == "T1"  # Priority 0.9 > 0.8
        
        # Second batch is empty because max_workers limit is reached
        assert len(sched.get_executable_batch()) == 0


class TestRetryPolicy:
    def test_task_retries_on_failure(self, scheduler):
        t1 = ResearchTask(title="Fail Task", description="Desc", goal="G", category=TaskCategory.API_DISCOVERY)
        scheduler.schedule_tasks([t1])
        
        batch = scheduler.get_executable_batch()
        task = batch[0]
        assert task.retry_count == 0
        
        # Fail the task
        scheduler.report_failure(task.task_id, error="test error")
        
        # It should go back to READY
        t_check = scheduler.queue_manager.get_task(task.task_id)
        assert t_check.state == TaskState.READY
        assert t_check.retry_count == 1
        assert len(t_check.retry_history) == 1

    def test_task_fails_terminally_after_max_retries(self, scheduler):
        t1 = ResearchTask(title="Fail Task", description="Desc", goal="G", category=TaskCategory.API_DISCOVERY)
        scheduler.schedule_tasks([t1])
        
        task = scheduler.queue_manager.get_task(t1.id)
        # set max retries to 1
        task.retry_policy.max_retries = 1
        
        # Attempt 1 (gets to retry_count 0 -> 1)
        batch = scheduler.get_executable_batch()
        scheduler.report_failure(batch[0].task_id, error="e1")
        assert task.state == TaskState.READY
        
        # Attempt 2 (gets to retry_count 1 -> max)
        batch2 = scheduler.get_executable_batch()
        scheduler.report_failure(batch2[0].task_id, error="e2")
        
        # Should now be FAILED
        assert task.state == TaskState.FAILED
        assert task.retry_count == 1


class TestEventEmission:
    def test_events_emitted_on_lifecycle_changes(self, scheduler, sample_tasks):
        # schedule emits TASK_SCHEDULED (x3)
        scheduler.schedule_tasks(sample_tasks)
        
        # get batch emits TASK_STARTED (x2)
        batch = scheduler.get_executable_batch()
        
        # success emits TASK_COMPLETED (x1)
        scheduler.report_success(batch[0].task_id)
        
        history = scheduler.event_bus.get_history()
        
        assert len(history) == 6
        event_types = [e.event_type for e in history]
        
        assert event_types.count(EventType.TASK_SCHEDULED) == 3
        assert event_types.count(EventType.TASK_STARTED) == 2
        assert event_types.count(EventType.TASK_COMPLETED) == 1
