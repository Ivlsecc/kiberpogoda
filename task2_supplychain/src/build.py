import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CT_REAL = ROOT / "task1_targeting" / "data" / "ct_real.json"
EVIDENCE = HERE.parent / "data" / "ct_evidence.json"


def verify_bridge():
    ev = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report = {"source": str(CT_REAL), "categories": {}, "ok": True}

    real_hosts = set()
    if CT_REAL.exists():
        ct = json.loads(CT_REAL.read_text(encoding="utf-8"))
        real_hosts = set(ct.get("data", {}).get("magnit.ru", []))
        report["real_hosts_total"] = len(real_hosts)
    else:
        report["ok"] = False
        report["warning"] = "ct_real.json не найден — пропускаю сверку (бридж не подтверждён)."
        return report

    for key, sig in ev["signals"].items():
        claimed = sig["hosts"]
        confirmed = [h for h in claimed if h in real_hosts]
        missing = [h for h in claimed if h not in real_hosts]
        report["categories"][key] = {
            "category": sig["category"],
            "claimed": len(claimed),
            "confirmed": len(confirmed),
            "missing": missing,
        }
        if missing:
            report["ok"] = False
    return report


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    rep = verify_bridge()
    print(f"Источник: {rep['source']}")
    print(f"Всего реальных хостов Магнита в CT: {rep.get('real_hosts_total', '—')}\n")
    for key, c in rep["categories"].items():
        mark = "OK " if not c["missing"] else "!! "
        print(f"  {mark}{c['category']:40} подтверждено {c['confirmed']}/{c['claimed']}")
        if c["missing"]:
            print(f"      не найдены в ct_real.json: {c['missing']}")
    print("\nБридж подтверждён целиком." if rep["ok"] else "\nЕсть хосты вне ct_real.json — проверь evidence.")
