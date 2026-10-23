import argparse
import csv
import json
import sys
from pathlib import Path

from collect import collect_all
from score import score_companies, PROFILE_WEIGHTS

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "output"

PROFILE_RU = {"ransomware": "Шифровальщики", "hacktivist": "Хактивисты", "apt": "APT",
              "broker": "Брокер доступа (IAB)"}
DRIVER_RU = {
    "A": "высокая ценность (A)", "E": "широкая поверхность атаки (E)",
    "O": "готовая возможность — утечки/доступы (O)", "I": "активный интерес/тренд (I)",
}


def write_csv(results, profile):
    path = OUT / f"ranking_{profile}.csv"
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f, delimiter=";")
        wr.writerow(["rank", "company", "domain", "TargetScore", "Confidence",
                     "A", "E", "O", "I", "top_drivers"])
        for i, r in enumerate(results, 1):
            wr.writerow([i, r["name"], r["domain"], r["score"], r["confidence"],
                         r["groups"]["A"], r["groups"]["E"], r["groups"]["O"], r["groups"]["I"],
                         " + ".join(DRIVER_RU[d] for d in r["top_drivers"])])
    return path


def write_markdown(all_results, live):
    lines = ["# Задача 1 — результаты ранжирования целей\n"]
    if live:
        mode = "live (Wikipedia + hh.ru + CT)"
    else:
        mode = "offline: поверхность E — из реальных CT-данных (ct_real.json); A — оценки; O/I — seed до подключения Задачи 3"
    lines.append(f"Режим сбора: **{mode}**. "
                 "Балл нормирован внутри отраслевой выборки; рядом — уверенность (полнота данных).\n")
    for profile, results in all_results.items():
        w = PROFILE_WEIGHTS[profile]
        lines.append(f"\n## Профиль: {PROFILE_RU[profile]} "
                     f"(веса A={w['A']}, E={w['E']}, O={w['O']}, I={w['I']})\n")
        lines.append("| # | Компания | Score | Conf. | A | E | O | I | Ключевые драйверы |")
        lines.append("|---|----------|------:|------:|---:|---:|---:|---:|-------------------|")
        for i, r in enumerate(results, 1):
            g = r["groups"]
            drivers = " + ".join(DRIVER_RU[d] for d in r["top_drivers"])
            lines.append(f"| {i} | {r['name']} | **{r['score']}** | {r['confidence']} | "
                         f"{g['A']} | {g['E']} | {g['O']} | {g['I']} | {drivers} |")
    lines.append("\n> Балл = приоритет по *интересу/привлекательности* как цели, а не прогноз атаки. "
                 "Высокий балл при низкой уверенности — гипотеза «нужна доразведка», а не вывод.\n")
    (OUT / "ranking.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="не ходить в сеть, использовать seed")
    ap.add_argument("--profile", choices=list(PROFILE_WEIGHTS) + ["all"], default="all")
    args = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    live = not args.offline
    print(f"[*] Сбор сигналов (live={live}) ...")
    data = collect_all(BASE / "data" / "companies.json", live=live,
                       monitor_path=BASE.parent / "task3_monitoring" / "output" / "posts.jsonl")
    (OUT / "signals.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    profiles = list(PROFILE_WEIGHTS) if args.profile == "all" else [args.profile]
    all_results = {}
    for p in profiles:
        res = score_companies(data, profile=p)
        all_results[p] = res
        path = write_csv(res, p)
        print(f"[+] {PROFILE_RU[p]}: топ-1 = {res[0]['name']} ({res[0]['score']}) -> {path.name}")
    write_markdown(all_results, live)
    print(f"[+] Отчёт: {OUT / 'ranking.md'}")


if __name__ == "__main__":
    main()
