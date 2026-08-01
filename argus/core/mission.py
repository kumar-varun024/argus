"""
Legacy module for Mission.
Re-exports Mission from argus.runtime to maintain backward compatibility.
"""

from argus.runtime.mission import Mission, MissionState

__all__ = ["Mission", "MissionState"]
