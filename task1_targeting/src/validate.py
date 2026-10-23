import argparse
import json
import sys
from pathlib import Path

from collect import collect_all
from score import score_companies

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]


def precision_recall_at_k(ranked_labels, k):
    topk = ranked_labels[:k]
    total_pos = sum(ranked_labels)
    tp = sum(topk)
    precision = tp / k if k else 0.0
    recall = tp / total_pos if total_pos else 0.0
    return precision, recall


def average_precision(ranked_labels):
    total_pos = sum(ranked_labels)
    if total_pos == 0:
        return 0.0
    hits = 0
    acc = 0.0
    for i, lbl in enumerate(ranked_labels, 1):
        if lbl:
            hits += 1
            acc += hits / i
    return acc / total_pos


def lift_at_k(ranked_labels, k):
    base_rate = sum(ranked_labels) / len(ranked_labels)
    if base_rate == 0:
        return 0.0
    prec_k, _ = precision_recall_at_k(ranked_labels, k)
    return prec_k / base_rate


def point_biserial(scores, labels):
    n = len(scores)
    if n < 2:
        return 0.0
    ms = sum(scores) / n
    ml = sum(labels) / n
    cov = sum((s - ms) * (l - ml) for s, l in zip(scores, labels))
    vs = sum((s - ms) ** 2 for s in scores) ** 0.5
    vl = sum((l - ml) ** 2 for l in labels) ** 0.5
    return cov / (vs * vl) if vs and vl else 0.0


def validate(data, gt, profile):
    results = score_companies(data, profile=profile)
    labels_map = gt["labels"]
    ranked = [(r["name"], r["score"], labels_map.get(r["name"], 0)) for r in results]
    ranked_labels = [l for _, _, l in ranked]
    scores = [s for _, s, _ in ranked]
    labels = [l for _, _, l in ranked]

    out = {"profile": profile, "n": len(ranked), "positives": sum(ranked_labels)}
    for k in (2, 3, 5):
        p, r = precision_recall_at_k(ranked_labels, k)
        out[f"P@{k}"] = round(p, 3)
        out[f"R@{k}"] = round(r, 3)
        out[f"lift@{k}"] = round(lift_at_k(ranked_labels, k), 2)
    out["AP"] = round(average_precision(ranked_labels), 3)
    out["corr(score,label)"] = round(point_biserial(scores, labels), 3)
    out["ranked"] = ranked
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--profile", default="ransomware")
    args = ap.parse_args()

    data = collect_all(BASE / "data" / "companies.json", live=not args.offline,
                       monitor_path=BASE.parent / "task3_monitoring" / "output" / "posts.jsonl")
    gt = json.loads((BASE / "data" / "ground_truth.json").read_text(encoding="utf-8"))
    res = validate(data, gt, args.profile)

    print(f"\n=== Валидация методологии (профиль: {args.profile}) ===")
    print(f"Компаний: {res['n']}, из них целей по разметке: {res['positives']}")
    print(f"{'ранг':>4} {'компания':<14} {'score':>6} {'метка':>6}")
    for i, (name, score, lbl) in enumerate(res["ranked"], 1):
        mark = "<- цель" if lbl else ""
        print(f"{i:>4} {name:<14} {score:>6} {mark:>8}")
    print("\nМетрики ранжирования:")
    for key in ("P@2", "P@3", "P@5", "R@3", "R@5", "lift@3", "AP", "corr(score,label)"):
        print(f"  {key:<18} {res[key]}")
    print("\nИнтерпретация: AP и lift@k заметно выше базового уровня означают, что модель "
          "поднимает реальные цели наверх ещё ДО инцидента. Метки иллюстративны (см. ground_truth.json).")

    (BASE / "output").mkdir(exist_ok=True)
    save = {k: v for k, v in res.items() if k != "ranked"}
    save["ranked"] = [{"rank": i, "name": n, "score": s, "label": l}
                      for i, (n, s, l) in enumerate(res["ranked"], 1)]
    (BASE / "output" / f"validation_{args.profile}.json").write_text(
        json.dumps(save, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
