import textwrap
from pathlib import Path

from model import Graph


def _risk_by_node(g):
    rows = {r["id"]: r for r in g.assess()}
    return {nid: rows[nid]["systemic_risk"] if nid in rows else 0.0 for nid in g.nodes}


def _color_for(risk, rmax):
    if rmax <= 0:
        t = 0.0
    else:
        t = max(0.0, min(1.0, risk / rmax))
    r = int(255 + t * (200 - 255))
    gc = int(221 + t * (30 - 221))
    b = int(87 + t * (30 - 87))
    return f"#{r:02x}{gc:02x}{b:02x}"


def write_mermaid(g, path):
    risk = _risk_by_node(g)
    rmax = max(risk.values()) or 1.0
    lines = ["graph LR"]
    for nid, node in g.nodes.items():
        label = node["label"].replace('"', "'")
        shape = f'{nid}["{label}"]'
        lines.append(f"    {shape}")
    for e in g.edges:
        w = Graph.transmission(e)
        lines.append(f"    {e['src']} -->|{w:.2f}| {e['dst']}")
    for nid in g.nodes:
        if nid == g.focal:
            lines.append(f"    style {nid} fill:#1f3b57,color:#fff,stroke:#0b1b2b")
        else:
            lines.append(f"    style {nid} fill:{_color_for(risk[nid], rmax)},stroke:#333")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_dot(g, path):
    risk = _risk_by_node(g)
    rmax = max(risk.values()) or 1.0
    lines = ['digraph supplychain {', '  rankdir=LR;', '  node [style=filled, fontname="Arial"];']
    for nid, node in g.nodes.items():
        label = node["label"].replace('"', "'")
        if nid == g.focal:
            lines.append(f'  {nid} [label="{label}", fillcolor="#1f3b57", fontcolor="white"];')
        else:
            lines.append(f'  {nid} [label="{label}", fillcolor="{_color_for(risk[nid], rmax)}"];')
    for e in g.edges:
        w = Graph.transmission(e)
        pen = 1.0 + 4.0 * w
        lines.append(f'  {e["src"]} -> {e["dst"]} [label="{w:.2f}", penwidth={pen:.1f}];')
    lines.append("}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _wrap(text, width=16):
    return "\n".join(textwrap.wrap(text, width=width, max_lines=2, placeholder="…"))


def write_png(g, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import networkx as nx
    except Exception:
        return False

    risk = _risk_by_node(g)
    rmax = max(risk.values()) or 1.0

    direct = {e["src"] for e in g.edges if e["dst"] == g.focal}
    transitive = [nid for nid in g.nodes if nid != g.focal and nid not in direct]
    direct_sorted = sorted(direct, key=lambda n: risk.get(n, 0), reverse=True)

    G = nx.DiGraph()
    for nid, node in g.nodes.items():
        G.add_node(nid)
    for e in g.edges:
        G.add_edge(e["src"], e["dst"], w=Graph.transmission(e))

    pos = nx.shell_layout(G, nlist=[[g.focal], direct_sorted, transitive], rotate=0.3)

    fig, ax = plt.subplots(figsize=(14, 10))

    node_colors = ["#1f3b57" if nid == g.focal else _color_for(risk[nid], rmax) for nid in G.nodes]
    node_sizes = [2800 if nid == g.focal else 1200 + 2600 * (risk[nid] / rmax) for nid in G.nodes]
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes,
                           edgecolors="#222", linewidths=1.2, ax=ax)

    widths = [0.8 + 4.5 * G[u][v]["w"] for u, v in G.edges]
    nx.draw_networkx_edges(G, pos, width=widths, edge_color="#777",
                           arrowsize=14, arrowstyle="-|>", node_size=node_sizes,
                           connectionstyle="arc3,rad=0.08", ax=ax)

    for nid in G.nodes:
        x, y = pos[nid]
        is_focal = nid == g.focal
        ax.text(x, y - 0.11, _wrap(g.nodes[nid]["label"]),
                ha="center", va="top", fontsize=8.5 if is_focal else 7.5,
                fontweight="bold" if is_focal else "normal", color="#111",
                bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="#ccc", alpha=0.85))

    import matplotlib.patches as mpatches
    leg = [mpatches.Patch(color="#1f3b57", label="заказчик (focal)"),
           mpatches.Patch(color=_color_for(rmax, rmax), label="высокий systemic_risk"),
           mpatches.Patch(color=_color_for(0, rmax), label="низкий systemic_risk")]
    ax.legend(handles=leg, loc="lower right", fontsize=8, framealpha=0.9)

    ax.set_title("Граф зависимостей цепочки поставок — подсветка по системному риску\n"
                 "центр: заказчик · внутр. кольцо: прямые поставщики · внешнее: транзитивные (апстрим/ДЗО)\n"
                 "толщина ребра = проводимость деградации, размер и цвет узла = systemic_risk",
                 fontsize=11)
    ax.axis("off")
    ax.margins(0.12)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True
