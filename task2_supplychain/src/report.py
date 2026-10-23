import csv
import json
from pathlib import Path

from model import Graph


def write_csv(rows, path):
    cols = ["id", "label", "kind", "p_incident", "direct_risk",
            "systemic_shock", "systemic_risk", "amplification", "fanout"]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _bar(x, width=10):
    n = int(round(x * width))
    return "#" * n + "." * (width - n)


def write_markdown(g, rows, path):
    lines = []
    lines.append("# Задача 2 — ранжирование зависимостей по риску\n")
    lines.append(f"Заказчик (focal): **{g.nodes[g.focal]['label']}**. "
                 f"Узлов: {len(g.nodes)}, связей: {len(g.edges)}.\n")
    lines.append("`direct_risk` — плоский взгляд (только прямое ребро на заказчика). "
                 "`systemic_risk` — с учётом всех путей, включая транзитивные "
                 "(поставщик поставщика, ДЗО, общий апстрим). `amplification` — "
                 "во сколько граф поднимает связь относительно плоского взгляда. "
                 "`fanout` — скольких прямых поставщиков заказчика заденет падение узла.\n")

    lines.append("## Ранжирование по системному риску\n")
    lines.append("| # | Зависимость | p(инц.) | direct | systemic | ампл. | fan-out |")
    lines.append("|---|---|---|---|---|---|---|")
    rmax = max(x["systemic_risk"] for x in rows)
    for i, r in enumerate(rows, 1):
        amp = "—" if r["amplification"] is None else f"×{r['amplification']}"
        lines.append(f"| {i} | {r['label']} | {r['p_incident']} | "
                     f"{r['direct_risk']} | **{r['systemic_risk']}** `{_bar(r['systemic_risk']/rmax)}` | {amp} | {r['fanout']} |")
    lines.append("")

    choke = g.chokepoints()
    lines.append("## Чокпоинты — что больнее всего, если упадёт именно это\n")
    lines.append("Ранжирование по чистому импакту (`systemic_shock`) и охвату (`fanout`), "
                 "без учёта вероятности. Отвечает на вопрос «где единая точка отказа».\n")
    lines.append("| Узел | systemic_shock | fan-out | тип |")
    lines.append("|---|---|---|---|")
    for r in choke[:6]:
        lines.append(f"| {r['label']} | {r['systemic_shock']} | {r['fanout']} | {r['kind']} |")
    lines.append("")

    lines.append("## Разбор верхних зависимостей\n")
    for r in rows[:5]:
        node = g.nodes[r["id"]]
        de = g.direct_edge(r["id"])
        lines.append(f"### {r['label']}")
        lines.append(f"- **Вероятность инцидента (оценка):** {r['p_incident']} — {node.get('why_p','')}")
        if de:
            lines.append(f"- **Характер связи:** {de['note']}")
            lines.append(f"- **Критичность процесса:** {de['crit']}, "
                         f"**уровень доступа:** {de['access']}, **замещаемость:** {de['subst']}")
        if r["amplification"] and r["amplification"] > 1.15:
            lines.append(f"- **Граф-эффект:** системный риск выше прямого в {r['amplification']}× — "
                         f"связь опаснее, чем кажется по плоской таблице (есть обходные/транзитивные пути).")
        if r["fanout"] >= 2:
            lines.append(f"- **Чокпоинт:** падение задевает {r['fanout']} прямых поставщиков сразу.")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_cascade(g, path):
    out = {"focal": g.focal, "decay": 0.6, "origins": {}}
    for nid in g.nodes:
        if nid == g.focal:
            continue
        paths = g.paths_to_focal(nid)
        out["origins"][nid] = {
            "label": g.nodes[nid]["label"],
            "systemic_shock": round(g.systemic_shock(nid), 3),
            "paths": [
                {
                    "hops": [e["src"] for e in p] + [g.focal],
                    "strength": round(Graph.path_strength(p, 0.6), 3),
                }
                for p in sorted(paths, key=lambda p: Graph.path_strength(p, 0.6), reverse=True)
            ],
        }
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
