import argparse
import json
import re
import sys
import time
from pathlib import Path

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"}


def fetch_channel(channel, limit=40):
    if requests is None or BeautifulSoup is None:
        raise RuntimeError("Нужны requests и beautifulsoup4 (pip install -r requirements.txt)")
    posts = {}
    before = None
    for _ in range(6):
        url = f"https://t.me/s/{channel}" + (f"?before={before}" if before else "")
        try:
            r = requests.get(url, headers=HEADERS, timeout=20)
        except Exception as e:
            print(f"  [!] {channel}: сеть недоступна ({type(e).__name__})")
            break
        if r.status_code != 200:
            print(f"  [!] {channel}: HTTP {r.status_code}")
            break
        soup = BeautifulSoup(r.text, "html.parser")
        msgs = soup.select(".tgme_widget_message")
        if not msgs:
            break
        ids = []
        for m in msgs:
            dp = m.get("data-post", "")
            num = dp.split("/")[-1] if dp else ""
            if num.isdigit():
                ids.append(int(num))
            text_el = m.select_one(".tgme_widget_message_text")
            time_el = m.select_one(".tgme_widget_message_date time")
            text = text_el.get_text("\n").strip() if text_el else ""
            if not text or not dp:
                continue
            posts[dp] = {
                "channel": channel,
                "post_id": dp,
                "link": f"https://t.me/{dp}",
                "datetime": time_el.get("datetime", "") if time_el else "",
                "views": (m.select_one(".tgme_widget_message_views").get_text(strip=True)
                          if m.select_one(".tgme_widget_message_views") else ""),
                "text": re.sub(r"[ \t]+", " ", text),
            }
        if len(posts) >= limit or not ids:
            break
        before = min(ids)
        time.sleep(1.0)
    result = sorted(posts.values(), key=lambda p: p["datetime"])
    return result[-limit:] if limit else result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--config", default=str(BASE / "config.json"))
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    channels = cfg["channels"]
    all_posts = []
    for ch in channels:
        print(f"[*] {ch} ...")
        try:
            got = fetch_channel(ch, args.limit)
            print(f"    собрано {len(got)}")
            all_posts.extend(got)
        except Exception as e:
            print(f"    ошибка: {e}")

    if all_posts:
        out = BASE / "data" / "raw_posts.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for p in all_posts:
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
        print(f"\n[+] Сохранено {len(all_posts)} постов -> {out}")
    else:
        print("\n[!] Ничего не собрано (t.me недоступен?). Использую уже лежащий data/raw_posts.jsonl.")


if __name__ == "__main__":
    main()
