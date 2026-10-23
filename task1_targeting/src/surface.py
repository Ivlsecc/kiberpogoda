import json
import math
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]

CATEGORIES = {
    "remote_access": r"(?:^|[.\-])(vpn|avpn|sslvpn|remote|rdp|citrix|anyconnect|pulse|gateway|gw)(?:$|[.\-])",
    "dev_test":      r"(?:^|[.\-])(test|dev|stage|staging|uat|qa|demo|sandbox|preprod|pre-prod|canary|lab)(?:$|[.\-\d])",
    "legacy":        r"(?:^|[.\-])(old|legacy|backup|bak|archive|temp|mirror)(?:$|[.\-])",
    "devops":        r"(?:^|[.\-])(git|gitlab|jenkins|ci|nexus|artifactory|sonar|harbor|registry|argo|teamcity|awx|docker|kuberun|airflow)(?:$|[.\-])",
    "admin":         r"(?:^|[.\-])(admin|adm|panel|manage|console|backoffice|root|pgadmin)(?:$|[.\-])",
    "mail":          r"(?:^|[.\-])(mail|owa|exchange|smtp|imap|webmail|autodiscover|ews|exch|mx\d*|kmail\w*)(?:$|[.\-])",
    "auth":          r"(?:^|[.\-])(auth|sso|login|oauth|idp|keycloak|adfs|kc|pwd|id)(?:$|[.\-])",
    "data_bi":       r"(?:^|[.\-])(grafana|kibana|powerbi|bi|tableau|superset|metabase|clickhouse|dwh|db|sql|mysql|postgres|mongo|redis|vlogs|spark)(?:$|[.\-])",
    "infra":         r"(?:^|[.\-])(k8s|kube|rancher|openshift|minio|s3|vault|consul|nomad|zabbix|prometheus|elastic|netbox|cerbos|sentry|defectdojo)(?:$|[.\-])",
    "collab":        r"(?:^|[.\-])(jira|confluence|wiki|redmine|portal|intranet|internal|int|corp|webconf)(?:$|[.\-])",
}

HIGH_VALUE = {
    "vault": "менеджер секретов", "gitlab": "репозиторий исходников", "git": "репозиторий исходников",
    "jenkins": "CI/CD", "adfs": "федеративный вход (AD FS)", "sso": "единый вход", "keycloak": "единый вход",
    "consul": "service mesh/конфиги", "pgadmin": "админка БД", "grafana": "мониторинг", "kibana": "логи",
    "registry": "реестр образов", "docker": "реестр образов", "sorm": "СОРМ", "netbox": "IPAM/инвентарь сети",
    "zabbix": "мониторинг", "airflow": "оркестратор данных", "defectdojo": "трекер уязвимостей",
    "awx": "Ansible AWX", "srm": "портал поставщиков (SRM)", "sap": "SAP (ERP)", "dmz": "DMZ-хост",
    "powerbi": "BI", "dwh": "хранилище данных", "pwd": "сброс паролей",
}


def classify(host):
    cats = set()
    for cat, pat in CATEGORIES.items():
        if re.search(pat, host):
            cats.add(cat)
    return cats


def high_value_hits(host):
    hits = []
    for token, meaning in HIGH_VALUE.items():
        if re.search(rf"(?:^|[.\-]){re.escape(token)}(?:$|[.\-\d])", host):
            hits.append(f"{token} ({meaning})")
    return hits


def analyze(ct):
    rows = []
    for domain, names in ct["data"].items():
        if not isinstance(names, list):
            continue
        cat_counts = {c: 0 for c in CATEGORIES}
        hv = []
        for h in names:
            for c in classify(h):
                cat_counts[c] += 1
            hits = high_value_hits(h)
            if hits:
                hv.append((h, hits))
        total = len(names)
        dev_share = cat_counts["dev_test"] / total if total else 0
        exposure = (
            0.45 * math.log1p(total)
            + 0.25 * dev_share * 10
            + 0.30 * math.log1p(len(hv) * 2)
        )
        rows.append({
            "domain": domain, "total": total, "categories": cat_counts,
            "dev_share": round(dev_share, 2),
            "high_value": sorted(hv), "high_value_count": len(hv),
            "exposure_raw": round(exposure, 2),
        })
    rows.sort(key=lambda r: r["exposure_raw"], reverse=True)
    return rows


def main():
    ct = json.loads((BASE / "data" / "ct_real.json").read_text(encoding="utf-8"))
    rows = analyze(ct)
    print(f"Источник: {ct['_source']}  (собрано {ct['_collected']})\n")
    print(f"{'домен':<16}{'хостов':>7}{'dev/test':>9}{'high-value':>11}{'exposure':>9}")
    for r in rows:
        print(f"{r['domain']:<16}{r['total']:>7}{int(r['dev_share']*r['total']):>9}"
              f"{r['high_value_count']:>11}{r['exposure_raw']:>9}")
    print("\nВысокоценные хосты (видны в CT; к ним НЕ подключались):")
    for r in rows:
        if r["high_value"]:
            sample = "; ".join(h for h, _ in r["high_value"][:8])
            print(f"  {r['domain']}: {sample}")
    (BASE / "output").mkdir(exist_ok=True)
    (BASE / "output" / "surface_analysis.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
