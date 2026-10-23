import json
from pathlib import Path

ACCESS_SEVERITY = {
    "none": 0.20,
    "data": 0.50,
    "network": 0.85,
    "identity": 0.95,
    "code": 1.00,
}

DEFAULT_DECAY = 0.6


class Graph:
    def __init__(self, data):
        self.focal = data["focal"]
        self.nodes = {n["id"]: n for n in data["nodes"]}
        self.edges = data["edges"]
        self.out = {nid: [] for nid in self.nodes}
        for e in self.edges:
            if e["src"] not in self.nodes or e["dst"] not in self.nodes:
                raise ValueError(f"ребро ссылается на несуществующий узел: {e}")
            self.out[e["src"]].append(e)

    @staticmethod
    def transmission(edge):
        sev = ACCESS_SEVERITY[edge["access"]]
        return edge["crit"] * sev * (1.0 - edge["subst"])

    def direct_edge(self, node):
        for e in self.out.get(node, []):
            if e["dst"] == self.focal:
                return e
        return None

    def paths_to_focal(self, origin):
        results = []

        def dfs(node, visited, acc):
            if node == self.focal and acc:
                results.append(list(acc))
                return
            for e in self.out.get(node, []):
                nxt = e["dst"]
                if nxt in visited:
                    continue
                visited.add(nxt)
                acc.append(e)
                dfs(nxt, visited, acc)
                acc.pop()
                visited.remove(nxt)

        dfs(origin, {origin}, [])
        return results

    @staticmethod
    def path_strength(path, decay):
        s = 1.0
        for e in path:
            s *= Graph.transmission(e)
        return s * (decay ** (len(path) - 1))

    def systemic_shock(self, origin, decay=DEFAULT_DECAY):
        paths = self.paths_to_focal(origin)
        prod = 1.0
        for p in paths:
            prod *= (1.0 - self.path_strength(p, decay))
        return 1.0 - prod

    def direct_strength(self, node):
        e = self.direct_edge(node)
        return self.transmission(e) if e else 0.0

    def assess(self, decay=DEFAULT_DECAY):
        rows = []
        for nid, node in self.nodes.items():
            if nid == self.focal:
                continue
            p = node.get("p_incident", 0.0)
            direct = self.direct_strength(nid)
            shock = self.systemic_shock(nid, decay)
            fanout = self._fanout_to_direct_vendors(nid)
            rows.append({
                "id": nid,
                "label": node["label"],
                "kind": node.get("kind", ""),
                "p_incident": round(p, 3),
                "direct_strength": round(direct, 3),
                "direct_risk": round(p * direct, 4),
                "systemic_shock": round(shock, 3),
                "systemic_risk": round(p * shock, 4),
                "amplification": round(shock / direct, 2) if direct > 1e-9 else None,
                "fanout": fanout,
            })
        rows.sort(key=lambda r: r["systemic_risk"], reverse=True)
        return rows

    def _fanout_to_direct_vendors(self, node):
        direct_vendors = {e["src"] for e in self.edges if e["dst"] == self.focal}
        hit = set()
        for p in self.paths_to_focal(node):
            for e in p:
                if e["dst"] == self.focal and e["src"] in direct_vendors:
                    hit.add(e["src"])
        return len(hit)

    def chokepoints(self, decay=DEFAULT_DECAY):
        rows = self.assess(decay)
        rows2 = sorted(rows, key=lambda r: (r["systemic_shock"], r["fanout"]), reverse=True)
        return rows2


def load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Graph(data)
