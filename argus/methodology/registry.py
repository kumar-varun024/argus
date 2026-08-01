from typing import Dict, List
from argus.methodology.models import Playbook
from argus.methodology.playbook import get_default_playbooks

class PlaybookRegistry:
    def __init__(self):
        self._playbooks: Dict[str, Playbook] = {}
        self.load_defaults()

    def load_defaults(self):
        for playbook in get_default_playbooks():
            self.register(playbook)

    def register(self, playbook: Playbook):
        if playbook.id in self._playbooks:
            raise ValueError(f"Playbook '{playbook.id}' is already registered.")
        self._playbooks[playbook.id] = playbook

    def unregister(self, playbook_id: str):
        if playbook_id in self._playbooks:
            del self._playbooks[playbook_id]

    def get_all(self) -> List[Playbook]:
        return list(self._playbooks.values())

    def get(self, playbook_id: str) -> Playbook:
        return self._playbooks.get(playbook_id)
