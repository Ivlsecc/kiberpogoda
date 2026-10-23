import json
import sys
import time
from pathlib import Path

from collect import certspotter_subdomains

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]


def main():
    cfg = json.loads((BASE / "data" / "companies.json").read_text(encoding="utf-8"))
    data = {}
    for c in cfg["companies"]:
        dom = c["domain"]
        print(f"[*] {dom} ...", end=" ", flush=True)
        subs = certspotter_subdomains(dom)
        if subs:
            data[dom] = subs
            print(f"{len(subs)} хостов")
        else:
            print("нет данных (источник недоступен или пусто)")
        time.sleep(1.0)
    out = {
        "_source": "api.certspotter.com v1/issuances (Certificate Transparency), include_subdomains=true",
        "_collected": time.strftime("%Y-%m-%d"),
        "_note": "Поддомены из публичных CT-логов (пассивно). К хостам не подключались, "
                 "уязвимости не проверяли. certspotter free tier отдаёт ограниченное окно — списки неполны, но сравнимы.",
        "data": data,
    }
    path = BASE / "data" / "ct_real.json"
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] Сохранено: {path}  ({len(data)} доменов)")


if __name__ == "__main__":
    main()
