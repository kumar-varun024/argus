from argus.agents.base import BaseAgent


class ReconAgent(BaseAgent):

    def __init__(self):
        super().__init__("Recon Agent")

    def think(self, mission):
        print(f"Target: {mission.target}")
        print("Planning reconnaissance...")

    def execute(self, mission):
        print("No reconnaissance tools connected yet.")

    def evaluate(self, mission):
        print("Recon phase complete.")
