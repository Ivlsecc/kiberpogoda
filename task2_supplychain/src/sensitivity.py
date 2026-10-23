import copy
import json
import random
import statistics
from pathlib import Path

from model import Graph


def perturb(data, delta, rng):
    d = copy.deepcopy(data)
    for n in d["nodes"]:
        if "p_incident" in n and n["p_incident"] > 0:
            n["p_incident"] = max(0.0, min(1.0, n["p_incident"] * (1 + rng.uniform(-delta, delta))))
    for e in d["edges"]:
        for k in ("crit", "subst"):
            e[k] = max(0.0, min(1.0, e[k] * (1 + rng.uniform(-delta, delta))))
    return d


def run(data_path, trials=2000, delta=0.25, top_k=4, seed=1):
    base = json.loads(Path(data_path).read_text(encoding="utf-8"))
    rng = random.Random(seed)

    base_rows = Graph(base).assess()
    base_order = [r["id"] for r in base_rows]

    ranks = {nid: [] for nid in base_order}
    top_hits = {nid: 0 for nid in base_order}

    for _ in range(trials):
        rows = Graph(perturb(base, delta, rng)).assess()
        order = [r["id"] for r in rows]
        for pos, nid in enumerate(order):
            ranks[nid].append(pos + 1)
            if pos < top_k:
                top_hits[nid] += 1

    result = {
        "trials": trials, "delta": delta, "top_k": top_k,
        "base_top": base_order[:top_k],
        "stability": {},
    }
    for nid in base_order:
        result["stability"][nid] = {
            "label": next(n["label"] for n in base["nodes"] if n["id"] == nid),
            "base_rank": base_order.index(nid) + 1,
            "mean_rank": round(statistics.mean(ranks[nid]), 2),
            "rank_std": round(statistics.pstdev(ranks[nid]), 2),
            "stays_in_top": round(top_hits[nid] / trials, 3),
        }
    return result


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    here = Path(__file__).resolve().parent
    res = run(here.parent / "data" / "dependencies.json")
    out = here.parent / "output"
    out.mkdir(exist_ok=True)
    (out / "sensitivity.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Монте-Карло: {res['trials']} прогонов, шум ±{int(res['delta']*100)}%\n")
    print(f"{'Зависимость':42} база  сред.ранг  ст.откл  в топ-{res['top_k']}")
    for nid, s in sorted(res["stability"].items(), key=lambda kv: kv[1]["mean_rank"]):
        print(f"  {s['label'][:40]:42} {s['base_rank']:>3}   {s['mean_rank']:>6}   {s['rank_std']:>5}    {s['stays_in_top']:.0%}")
