"""The credential graph: nodes, edges and the gaps the collector could not fill."""
from __future__ import annotations

import json


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[tuple[str, str, str]] = []
        # Anything the collector could not read. A gap is never treated as "nothing there".
        self.gaps: list[dict] = []
        # Where the data came from: provider, environment (observed or simulated) and details.
        self.sources: list[dict] = []

    def add_source(self, provider: str, environment: str, **details) -> None:
        self.sources.append({"provider": provider, "environment": environment, **details})

    def add_node(self, node_id: str, kind: str, **attrs) -> str:
        self.nodes[node_id] = {"id": node_id, "kind": kind, **attrs}
        return node_id

    def add_edge(self, src: str, rel: str, dst: str) -> None:
        edge = (src, rel, dst)
        if edge not in self.edges:
            self.edges.append(edge)

    def add_gap(self, scope: str, what: str, reason: str) -> None:
        self.gaps.append({"scope": scope, "what": what, "reason": reason})

    def out(self, src: str, rel: str) -> list[dict]:
        return [self.nodes[d] for s, r, d in self.edges if s == src and r == rel]

    def into(self, dst: str, rel: str) -> list[dict]:
        return [self.nodes[s] for s, r, d in self.edges if d == dst and r == rel]

    def of_kind(self, kind: str) -> list[dict]:
        return [n for n in self.nodes.values() if n["kind"] == kind]

    def to_json(self) -> str:
        return json.dumps({"schema_version": "0.1", "nodes": list(self.nodes.values()),
                           "edges": [list(e) for e in self.edges], "gaps": self.gaps,
                           "sources": self.sources}, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Graph":
        data = json.loads(text)
        graph = cls()
        for node in data["nodes"]:
            graph.nodes[node["id"]] = node
        graph.edges = [tuple(e) for e in data["edges"]]
        graph.gaps = data.get("gaps", [])
        graph.sources = data.get("sources", [])
        return graph
