from .node import Node


class EvidenceGraph:

    def __init__(self):

        self.nodes = {}

    def add(self, node: Node):

        self.nodes[node.id] = node

    def get(self, node_id: str):

        return self.nodes.get(node_id)

    def connect(self, source: str, target: str):

        if source not in self.nodes:
            return

        if target not in self.nodes:
            return

        self.nodes[source].relationships.add(target)

    def all(self):

        return list(self.nodes.values())
