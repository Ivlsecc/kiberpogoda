import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from classify import classify_rules

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]


def metrics(pred, gold):
    classes = sorted(set(gold.values()) | set(pred.values()))
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    correct = 0
    for pid, g in gold.items():
        p = pred.get(pid, "other")
        if p == g:
            correct += 1
            tp[g] += 1
        else:
            fp[p] += 1
            fn[g] += 1
    per = {}
    for c in classes:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        rec = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per[c] = {"precision": round(prec, 2), "recall": round(rec, 2),
                  "f1": round(f1, 2), "support": tp[c] + fn[c]}
    macro_f1 = round(sum(v["f1"] for v in per.values()) / len(per), 3) if per else 0.0
    return {"accuracy": round(correct / len(gold), 3), "macro_f1": macro_f1, "per_class": per}


def print_report(name, m):
    print(f"\n=== {name} ===")
    print(f"accuracy = {m['accuracy']}   macro-F1 = {m['macro_f1']}")
    print(f"{'класс':<18}{'prec':>6}{'rec':>6}{'f1':>6}{'n':>4}")
    for c, v in sorted(m["per_class"].items(), key=lambda kv: -kv[1]["support"]):
        if v["support"] == 0:
            continue
        print(f"{c:<18}{v['precision']:>6}{v['recall']:>6}{v['f1']:>6}{v['support']:>4}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true")
    args = ap.parse_args()

    gold = json.loads((BASE / "data" / "gold_labels.json").read_text(encoding="utf-8"))["labels"]
    posts = {p["post_id"]: p for p in
             (json.loads(l) for l in (BASE / "data" / "raw_posts.jsonl").read_text(encoding="utf-8").splitlines())}
    gold = {k: v for k, v in gold.items() if k in posts}
    print(f"Размечено постов: {len(gold)}")

    rules_pred = {pid: classify_rules(posts[pid]["text"])["event_type"] for pid in gold}
    m_rules = metrics(rules_pred, gold)
    print_report("Правила (rules)", m_rules)

    result = {"n": len(gold), "rules": m_rules}

    if args.llm:
        import llm
        if llm.available():
            print(f"\n[*] LLM: {llm.MODEL} — классифицирую {len(gold)} постов...")
            llm_pred = {}
            for pid in gold:
                r = llm.classify_llm(posts[pid]["text"])
                llm_pred[pid] = r["event_type"] if r else "other"
            m_llm = metrics(llm_pred, gold)
            print_report(f"Локальный LLM ({llm.MODEL})", m_llm)
            result["llm"] = m_llm
            print("\nРасхождения (gold | rules | llm):")
            for pid in gold:
                if rules_pred[pid] != gold[pid] or llm_pred[pid] != gold[pid]:
                    print(f"  {pid}: {gold[pid]:14} | {rules_pred[pid]:14} | {llm_pred[pid]}")
        else:
            print("\n[!] Ollama недоступен — LLM-сравнение пропущено. "
                  "Запустите `ollama serve` и `ollama pull qwen2.5:7b`.")

    (BASE / "output").mkdir(exist_ok=True)
    (BASE / "output" / "evaluation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] Сохранено: {BASE/'output'/'evaluation.json'}")


if __name__ == "__main__":
    main()
