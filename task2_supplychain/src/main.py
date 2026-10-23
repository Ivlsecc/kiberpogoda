import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model import load
import report
import viz
import build


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    here = Path(__file__).resolve().parent
    data_path = here.parent / "data" / "dependencies.json"
    out = here.parent / "output"
    out.mkdir(exist_ok=True)

    g = load(data_path)
    rows = g.assess()

    report.write_csv(rows, out / "ranking.csv")
    report.write_markdown(g, rows, out / "ranking.md")
    report.write_cascade(g, out / "cascade.json")

    viz.write_mermaid(g, out / "graph.mmd")
    viz.write_dot(g, out / "graph.dot")
    png_ok = viz.write_png(g, out / "graph.png")

    bridge = build.verify_bridge()
    (out / "bridge.json").write_text(json.dumps(bridge, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Заказчик: {g.nodes[g.focal]['label']}  |  узлов {len(g.nodes)}, связей {len(g.edges)}\n")
    print(f"{'#':>2}  {'Зависимость':42} {'p':>5} {'direct':>7} {'systemic':>9} {'ампл':>6} fan")
    for i, r in enumerate(rows, 1):
        amp = "  — " if r["amplification"] is None else f"×{r['amplification']:<4}"
        print(f"{i:>2}  {r['label'][:40]:42} {r['p_incident']:>5} {r['direct_risk']:>7} "
              f"{r['systemic_risk']:>9} {amp:>6} {r['fanout']}")

    print("\nЧокпоинты (импакт без учёта вероятности):")
    for r in g.chokepoints()[:4]:
        print(f"   {r['label'][:44]:46} shock={r['systemic_shock']:<5} fan-out={r['fanout']}")

    print(f"\nCT-бридж: {'подтверждён' if bridge['ok'] else 'есть расхождения — см. bridge.json'}"
          f" ({bridge.get('real_hosts_total','?')} реальных хостов)")
    print(f"Визуализация: {'graph.png + ' if png_ok else '(matplotlib нет) '}graph.dot + graph.mmd")
    print(f"Результаты: {out}")


if __name__ == "__main__":
    main()
