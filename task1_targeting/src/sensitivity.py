import argparse
import json
import random
import sys
from pathlib import Path

from collect import collect_all
from score import score_companies, PROFILE_WEIGHTS

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]


def perturb(weights, sigma, rng):
    noisy = {g: max(0.0, w * (1 + rng.gauss(0, sigma))) for g, w in weights.items()}
    s = sum(noisy.values()) or 1.0
    return {g: w / s for g, w in noisy.items()}


def run(data, profile, n, sigma, seed=42):
    rng = random.Random(seed)
    base = PROFILE_WEIGHTS[profile]
    names = [c["name"] for c in data["companies"]]
    ranks = {name: [] for name in names}
    top3 = {name: 0 for name in names}

    original = dict(PROFILE_WEIGHTS[profile])
    try:
        for _ in range(n):
            PROFILE_WEIGHTS[profile] = perturb(base, sigma, rng)
            res = score_companies(data, profile=profile)
            order = [r["name"] for r in res]
            for rank, name in enumerate(order, 1):
                ranks[name].append(rank)
                if rank <= 3:
                    top3[name] += 1
    finally:
        PROFILE_WEIGHTS[profile] = original

    summary = []
    for name in names:
        rs = ranks[name]
        mean = sum(rs) / len(rs)
        var = sum((x - mean) ** 2 for x in rs) / len(rs)
        summary.append({
            "name": name,
            "mean_rank": round(mean, 2),
            "std_rank": round(var ** 0.5, 2),
            "top3_share": round(top3[name] / n, 3),
        })
    summary.sort(key=lambda d: d["mean_rank"])
    return {"profile": profile, "n": n, "sigma": sigma, "summary": summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--profile", default="ransomware")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--sigma", type=float, default=0.25, help="сила возмущения весов (отн.)")
    args = ap.parse_args()

    data = collect_all(BASE / "data" / "companies.json", live=not args.offline,
                       monitor_path=BASE.parent / "task3_monitoring" / "output" / "posts.jsonl")
    res = run(data, args.profile, args.n, args.sigma)

    print(f"\n=== Чувствительность к весам (профиль {args.profile}, "
          f"N={args.n}, σ={args.sigma}) ===")
    print(f"{'компания':<14} {'ср.ранг':>8} {'σ ранга':>8} {'топ-3, %':>9}")
    for d in res["summary"]:
        print(f"{d['name']:<14} {d['mean_rank']:>8} {d['std_rank']:>8} {d['top3_share']*100:>8.0f}%")
    print("\nИнтерпретация: компании с top3_share≈100% и малым σ ранга — устойчивый вывод "
          "(не зависит от точной калибровки весов). Большой σ ранга = вывод чувствителен к весам, "
          "по такой компании нужна дополнительная проверка.")

    (BASE / "output").mkdir(exist_ok=True)
    (BASE / "output" / f"sensitivity_{args.profile}.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
