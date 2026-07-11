from abc import ABC, abstractmethod


class BaseCollector(ABC):

    @abstractmethod
    def collect(self, mission):
        """Collect information and update the mission."""
        pass
