import re

from textutil import strip_emoji

KNOWN_CANON = [
    (r"microsoft", "Microsoft"), (r"\bgoogle\w*", "Google"), (r"citrix", "Citrix"),
    (r"netscaler", "NetScaler"), (r"gitlab", "GitLab"), (r"github", "GitHub"),
    (r"drupal", "Drupal"), (r"wordpress", "WordPress"), (r"kubernetes|k8s", "Kubernetes"),
    (r"d-link", "D-Link"), (r"ubiquiti", "Ubiquiti"), (r"cisco", "Cisco"),
    (r"vmware", "VMware"), (r"confluence", "Confluence"), (r"\bjira\b", "Jira"),
    (r"\bphp\b", "PHP"), (r"wordpress", "WordPress"), (r"telegram", "Telegram"),
    (r"whatsapp", "WhatsApp"), (r"entra", "Microsoft Entra"), (r"bank of america", "Bank of America"),
    (r"\bdeere\b", "Deere"), (r"sharkninja", "SharkNinja"), (r"\bnpm\b", "npm"),
    (r"citrix|netscaler", "Citrix NetScaler"),
    (r"яндекс\w*", "Яндекс"), (r"сбер\w*", "Сбер"), (r"\bvk\b|вконтакте", "VK"),
    (r"dodo pizza|додо пицц\w*", "Dodo Pizza"), (r"firstvds", "FirstVDS"),
    (r"vmmanager", "VMmanager"), (r"wildberries", "Wildberries"), (r"\bozon\w*", "Ozon"),
    (r"\bмагнит\w*", "Магнит"), (r"\bлент[аы]\b", "Лента"), (r"м\.?видео", "М.Видео"),
    (r"lamoda", "Lamoda"), (r"детский мир", "Детский мир"), (r"мегамаркет", "Мегамаркет"),
    (r"\bкупер\b", "Купер"), (r"ростелеком", "Ростелеком"), (r"\bмтс\b|\bmts\b", "МТС"),
    (r"тинькофф|т-банк", "Т-Банк"), (r"positive technologies|pt\b", "Positive Technologies"),
    (r"kaspersky|касперск\w*", "Kaspersky"), (r"infosecurity|информзащит\w*", "Infosecurity"),
    (r"threatfabric", "ThreatFabric"), (r"greynoise", "GreyNoise"), (r"searchlight", "Searchlight Cyber"),
]
SECTOOLS = {"velociraptor", "sysmon", "capa", "strix", "tokensmith", "nmap", "wireshark",
            "siem", "edr", "soc"}

DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:ru|com|org|net|io|dev|gov|us|uk|by|kz|uz|tech|market|рф)\b", re.I)
CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
QUOTED = re.compile(r"[«\"]([A-ZА-ЯЁ][\w .\-]{2,40})[»\"]")
CAMEL = re.compile(r"\b([A-Z][a-z]+[A-Z][a-zA-Z]+)\b")
GOV = re.compile(r"\b(ФСТЭК|ФСБ|РКН|Роскомнадзор|Минцифр\w*|ЦБ|НКЦКИ|\d{1,3}-ФЗ|приказ\w*\s*№?\s*\d+|КИИ|ГОСТ\s?Р?\s?\d+)\b")
MONEY = re.compile(r"(\$\s?\d[\d  .,]*(?:тыс|млн|млрд|k|m|b)?|\d[\d  .,]*\s?(?:руб\w*|долл\w*|млн|млрд|тыс\w*))", re.I)

STOP_LATIN = {"The", "This", "And", "For", "You", "All", "New", "How", "CVE", "VQL", "RCE",
              "SSH", "TLS", "DNS", "API", "SOC", "SIEM", "EDR", "PoC", "VPN", "ИИ", "URL",
              "PHP", "OSINT", "MITRE", "ATT", "SMS", "XML"}


def extract_entities(text):
    t = strip_emoji(text)
    low = t.lower()

    domains = sorted({d.lower() for d in DOMAIN.findall(t)})
    cves = sorted({c.upper() for c in CVE.findall(t)})

    def canon(name):
        nl = name.lower()
        for root, c in KNOWN_CANON:
            if re.search(root, nl):
                return c
        return name

    companies = set()
    for root, c in KNOWN_CANON:
        if re.search(root, low):
            companies.add(c)
    for m in QUOTED.findall(t):
        companies.add(canon(m.strip()))
    for m in CAMEL.findall(t):
        if m in STOP_LATIN or m.lower() in SECTOOLS:
            continue
        if any(m.lower() in d for d in domains):
            continue
        companies.add(canon(m))
    comp = sorted(companies)
    comp = [c for c in comp if not any(c != o and c.lower() in o.lower() for o in comp)]

    tools = sorted({s for s in SECTOOLS if re.search(rf"\b{re.escape(s)}\b", low)})
    gov = sorted(set(GOV.findall(t)))
    money = sorted(set(m.strip() for m in MONEY.findall(t)))[:5]

    return {
        "companies": comp,
        "domains": domains,
        "cves": cves,
        "sec_tools": tools,
        "gov": gov,
        "money": money,
    }


if __name__ == "__main__":
    import json, sys
    from pathlib import Path
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    path = Path(__file__).resolve().parents[1] / "data" / "raw_posts.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines()[:10]:
        p = json.loads(line)
        e = extract_entities(p["text"])
        print(f"- {p['text'][:50]}...")
        print(f"    companies={e['companies']}  cves={e['cves']}  gov={e['gov']}")
