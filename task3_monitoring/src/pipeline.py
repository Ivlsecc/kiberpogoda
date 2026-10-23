import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from classify import classify_rules
from ner import extract_entities
from dedup import cluster_posts
from enrich import cross_source_events, significance, activity_timeline
from store import save_sqlite, save_jsonl
from textutil import detect_lang

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]


def process(posts, use_llm=False):
    llm = None
    if use_llm:
        import llm as _llm
        if _llm.available():
            llm = _llm
            print(f"[*] LLM включён: {_llm.MODEL}")
        else:
            print("[!] Ollama недоступен — работаю на правилах (fallback).")

    out = []
    for p in posts:
        text = p["text"]
        rec = dict(p)
        rec["lang"] = detect_lang(text)

        cls = classify_rules(text)
        rec["event_type"] = cls["event_type"]
        rec["event_conf"] = cls["confidence"]
        rec["classifier"] = "rules"
        if llm:
            lc = llm.classify_llm(text)
            if lc:
                rec["event_type"] = lc["event_type"]
                rec["event_conf"] = lc["confidence"]
                rec["classifier"] = "llm"

        ent = extract_entities(text)
        if llm:
            le = llm.ner_llm(text)
            if le:
                ent["companies"] = sorted(set(ent["companies"]) | set(le["companies"]))
                ent["domains"] = sorted(set(ent["domains"]) | set(le["domains"]))
                ent["cves"] = sorted(set(ent["cves"]) | set(le["cves"]))
        rec["entities"] = ent
        out.append(rec)

    out = cluster_posts(out, threshold=0.6)
    out = cross_source_events(out, window_hours=72)
    now = dt.datetime.now(dt.timezone.utc)
    for rec in out:
        gsize = rec.get("event_group_size", 1)
        sig = significance(rec, now, group_size=gsize)
        rec.update(sig)
    return out


def export_task1_signals(posts, path):
    from enrich import TRACKED
    agg = {}
    for p in posts:
        for c in p.get("entities", {}).get("companies", []):
            if c.lower() in TRACKED:
                d = agg.setdefault(c.lower(), {"shadow_mentions_30d": 0, "data_leak": 0, "access_sale": 0})
                d["shadow_mentions_30d"] += 1
                if p["event_type"] == "data_leak":
                    d["data_leak"] += 1
                if p["event_type"] == "access_sale":
                    d["access_sale"] += 1
    path.write_text(json.dumps(agg, ensure_ascii=False, indent=2), encoding="utf-8")
    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(BASE / "data" / "raw_posts.jsonl"))
    ap.add_argument("--llm", action="store_true", help="использовать локальный LLM (Ollama)")
    args = ap.parse_args()

    posts = [json.loads(l) for l in Path(args.input).read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[*] Загружено публикаций: {len(posts)}")
    processed = process(posts, use_llm=args.llm)

    out_dir = BASE / "output"
    save_sqlite(processed, out_dir / "events.db")
    save_jsonl(processed, out_dir / "posts.jsonl")
    activity = activity_timeline(processed)
    (out_dir / "activity.json").write_text(json.dumps(activity, ensure_ascii=False, indent=2), encoding="utf-8")
    sigs = export_task1_signals(processed, out_dir / "task1_signals.json")

    from collections import Counter
    by_type = Counter(p["event_type"] for p in processed)
    clusters = len({p["event_cluster"] for p in processed if p.get("event_cluster", -1) >= 0})
    top = sorted(processed, key=lambda p: -p["significance"])[:5]
    print(f"[+] Типы событий: {dict(by_type)}")
    print(f"[+] Кросс-сорс событий (из >1 источника): {clusters}")
    print(f"[+] Дней со всплеском активности: {activity['spike_days']}")
    print(f"[+] Сигналы O/I для задачи 1 по отслеживаемым компаниям: {sigs}")
    print("\nТоп-5 по значимости:")
    for p in top:
        print(f"  [{p['significance']}] ({p['event_type']}) {p['text'][:68]}")
    print(f"\n[+] Сохранено: {out_dir/'events.db'}, {out_dir/'posts.jsonl'}, "
          f"{out_dir/'activity.json'}, {out_dir/'task1_signals.json'}")


if __name__ == "__main__":
    main()
