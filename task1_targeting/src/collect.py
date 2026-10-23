import datetime as dt
import json
import sys
import time
from pathlib import Path
from statistics import median
from urllib.parse import quote

try:
    import requests
except Exception:
    requests = None

HTTP_TIMEOUT = 15
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
}

TECH_KEYWORDS = [
    "1c", "1с", "bitrix", "битрикс", "php", "java", "python", "golang", "node",
    "react", "vue", "angular", "postgresql", "mysql", "mssql", "oracle", "mongodb",
    "redis", "kafka", "rabbitmq", "docker", "kubernetes", "k8s", "nginx", "apache",
    "aws", "azure", "gcp", "yandex cloud", "vmware", "gitlab", "jenkins",
]
SEC_KEYWORDS = [
    "информационной безопасности", "кибербезопасности", "ib", "иб ", "soc",
    "devsecops", "appsec", "pentest", "пентест", "pentester", "red team",
    "blue team", "security", "безопасник", "аналитик соц",
]
KNOWN_VULN_SOFTWARE = ["bitrix", "битрикс", "1c", "1с", "exchange", "confluence", "gitlab"]


def _get_json(url, retries=3, timeout=HTTP_TIMEOUT):
    if requests is None:
        return None
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                return r.json()
            if r.status_code in (403, 404):
                return None
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(1.2 * (attempt + 1))
    return None


def crtsh_subdomains(domain):
    url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    data = _get_json(url, retries=2, timeout=8)
    if not data:
        return None
    subs = set()
    for row in data:
        for field in ("name_value", "common_name"):
            val = row.get(field, "")
            for name in str(val).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    subs.add(name)
    return len(subs) if subs else None


def certspotter_subdomains(domain):
    url = (f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
           f"&include_subdomains=true&expand=dns_names")
    data = _get_json(url, retries=2, timeout=20)
    if not data or not isinstance(data, list):
        return None
    names = set()
    for item in data:
        for n in item.get("dns_names", []):
            n = n.lstrip("*.").lower()
            if n.endswith(domain):
                names.add(n)
    return sorted(names) if names else None


def hh_employer_id(hh_name):
    data = _get_json(f"https://api.hh.ru/employers?text={quote(hh_name)}&only_with_vacancies=true&per_page=5")
    if not data:
        return None
    items = data.get("items", [])
    return items[0]["id"] if items else None


def hh_tech_signals(hh_name):
    emp_id = hh_employer_id(hh_name)
    if not emp_id:
        return None
    data = _get_json(f"https://api.hh.ru/vacancies?employer_id={emp_id}&per_page=100")
    if not data:
        return None
    items = data.get("items", [])
    total = data.get("found", len(items))
    tech = set()
    sec = 0
    for v in items:
        blob = json.dumps(v, ensure_ascii=False).lower()
        for t in TECH_KEYWORDS:
            if t in blob:
                tech.add(t)
        if any(s in blob for s in SEC_KEYWORDS):
            sec += 1
    return {
        "it_vacancies": int(total),
        "sec_vacancies": int(sec),
        "tech_stack": sorted(tech),
        "new_cve_in_stack": int(any(t in KNOWN_VULN_SOFTWARE for t in tech)),
    }


def wiki_pageviews(article):
    if not article:
        return None
    end = dt.date.today().strftime("%Y%m01")
    start = (dt.date.today() - dt.timedelta(days=210)).strftime("%Y%m01")
    art = quote(article, safe="")
    url = (f"https://wikimedia.org/api/rest_v1/metrics/pageviews/per-article/"
           f"ru.wikipedia/all-access/all-agents/{art}/monthly/{start}/{end}")
    data = _get_json(url, retries=2)
    if not data or not data.get("items"):
        return None
    views = [it["views"] for it in data["items"]]
    completed = views[:-1] if len(views) > 1 else views
    if not completed:
        return None
    med = median(completed)
    base = median(completed[:-1]) if len(completed) > 1 else med
    trend = (completed[-1] / base) if base else 1.0
    return {"wiki_views_median": int(med), "wiki_views_trend": round(trend, 2)}


def load_surface(ct_path):
    if not ct_path.exists():
        return {}
    try:
        from surface import analyze
        ct = json.loads(ct_path.read_text(encoding="utf-8"))
        rows = analyze(ct)
        return {r["domain"]: r for r in rows}
    except Exception:
        return {}


def load_shadow_mentions(monitor_path):
    result = {}
    if not monitor_path.exists():
        return result
    try:
        for line in monitor_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            for comp in rec.get("entities", {}).get("companies", []):
                key = comp.lower()
                d = result.setdefault(key, {"shadow_mentions_30d": 0, "access_for_sale": 0, "leak_mentions": 0})
                d["shadow_mentions_30d"] += 1
                if rec.get("event_type") == "access_sale":
                    d["access_for_sale"] = 1
                if rec.get("event_type") == "data_leak":
                    d["leak_mentions"] += 1
    except Exception:
        pass
    return result


def collect_company(c, shadow, live, surface=None):
    name, domain = c["name"], c["domain"]
    seed = c.get("seed", {})
    surface = surface or {}
    rec = {"name": name, "domain": domain, "A": c.get("A", {}), "collected": {}}

    def pick(key, live_val):
        if live and live_val is not None:
            rec["collected"][key] = True
            return live_val
        rec["collected"][key] = False
        return seed.get(key)

    surf = surface.get(domain)
    if surf:
        rec["subdomains"] = surf["total"]
        rec["dev_share"] = surf["dev_share"]
        rec["high_value_count"] = surf["high_value_count"]
        rec["collected"]["subdomains"] = True
        rec["collected"]["surface"] = True
    else:
        subs = crtsh_subdomains(domain) if live else None
        rec["subdomains"] = pick("subdomains", subs)
        rec["dev_share"] = seed.get("dev_share")
        rec["high_value_count"] = seed.get("high_value_count")
        rec["collected"]["surface"] = False

    hh = hh_tech_signals(c.get("hh_name", name)) if live else None
    rec["it_vacancies"] = pick("it_vacancies", hh.get("it_vacancies") if hh else None)
    rec["sec_vacancies"] = pick("sec_vacancies", hh.get("sec_vacancies") if hh else None)
    rec["new_cve_in_stack"] = pick("new_cve_in_stack", hh.get("new_cve_in_stack") if hh else None)
    rec["tech_stack"] = hh.get("tech_stack") if hh else seed.get("tech_stack", [])

    wiki = wiki_pageviews(c.get("wiki", "")) if live else None
    if wiki:
        rec["wiki_views_median"] = wiki["wiki_views_median"]
        rec["wiki_views_trend"] = wiki["wiki_views_trend"]
        rec["collected"]["wiki"] = True
    else:
        rec["wiki_views_median"] = seed.get("wiki_views_median")
        rec["collected"]["wiki"] = False

    sm = shadow.get(name.lower(), {})
    rec["shadow_mentions_30d"] = sm.get("shadow_mentions_30d", seed.get("shadow_mentions_30d"))
    rec["access_for_sale"] = sm.get("access_for_sale", seed.get("access_for_sale"))
    rec["leak_mentions"] = sm.get("leak_mentions", seed.get("leak_mentions"))
    rec["collected"]["shadow"] = bool(sm)
    return rec


def collect_all(companies_path, live=True, monitor_path=None, ct_path=None):
    cfg = json.loads(companies_path.read_text(encoding="utf-8"))
    shadow = load_shadow_mentions(monitor_path) if monitor_path else {}
    if ct_path is None:
        ct_path = companies_path.parent / "ct_real.json"
    surface = load_surface(ct_path)
    out = []
    for c in cfg["companies"]:
        rec = collect_company(c, shadow, live, surface)
        out.append(rec)
        if live:
            time.sleep(0.5)
    return {"sector_trend": cfg.get("sector_trend", 0.5), "companies": out}


if __name__ == "__main__":
    base = Path(__file__).resolve().parents[1]
    live = "--offline" not in sys.argv
    res = collect_all(base / "data" / "companies.json", live=live,
                      monitor_path=base.parent / "task3_monitoring" / "output" / "posts.jsonl")
    (base / "output").mkdir(exist_ok=True)
    (base / "output" / "signals.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Собрано компаний: {len(res['companies'])} (live={live})")
