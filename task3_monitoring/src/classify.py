import re

from textutil import normalize

RULES = {
    "data_leak": [
        (r"утечк\w*", 3), (r"слит\w+|слил\w*", 3), (r"baz[ае]|баз[аы] данных", 1.5),
        (r"дамп\w*", 2.5), (r"скомпрометирова\w+ данн", 2), (r"похит\w+ данн|украл\w+ данн", 2.5),
        (r"выгруз\w+ баз", 3), (r"персональн\w+ данн", 1.5), (r"data breach|leak", 2.5),
    ],
    "access_sale": [
        (r"продаж\w* доступ", 4), (r"прода\w+ доступ", 4), (r"доступ\w* в продаж", 4),
        (r"продам доступ|куплю доступ", 4), (r"initial access|access for sale", 4),
        (r"залит\w+ шелл|вебшелл на продаж", 3),
    ],
    "attack_claim": [
        (r"взлом\w*", 3), (r"атак\w+ на|кибератак\w*", 2.5), (r"скомпрометирова\w+", 2),
        (r"захват\w+ (сервер|сайт|инфраструктур)", 3), (r"получил\w* доступ к", 2),
        (r"проник\w+ в (сеть|систем|инфраструктур)", 2.5), (r"взломал\w+", 3),
        (r"нарушил\w+ работу", 2),
    ],
    "ransomware": [
        (r"шифровальщик\w*", 4), (r"вымогател\w*", 3.5), (r"ransom\w*", 3.5),
        (r"зашифрова\w+", 2.5), (r"выкуп\w*", 2),
    ],
    "vuln_disclosure": [
        (r"уязвим\w*", 3), (r"cve-\d{4}-\d+", 3.5), (r"эксплойт\w*|эксплоит\w*|exploit", 3),
        (r"патч\w*|обновлени\w+ безопасн", 2), (r"rce|удал\w+ выполнени\w+ код", 3),
        (r"0-day|zero-day|0day", 3), (r"критическ\w+ уязвим", 3),
    ],
    "phishing_fraud": [
        (r"фишинг\w*", 3.5), (r"мошенник\w*|мошеннич\w*", 3), (r"scam|phishing", 3),
        (r"вишинг|смишинг", 3), (r"социальн\w+ инженер", 2.5), (r"поддельн\w+ (сайт|страниц)", 2),
    ],
    "malware": [
        (r"троян\w*|trojan", 3), (r"стилер\w*|stealer", 3), (r"вредонос\w*|malware", 2.5),
        (r"бэкдор\w*|backdoor", 3), (r"червь|worm", 2.5), (r"ботнет\w*|botnet", 2.5),
        (r"майнер\w*|miner", 2),
    ],
    "regulation": [
        (r"фстэк|фсб|ркн|минцифр", 3), (r"\d+-фз|\bфз\b|федеральн\w+ закон", 2.5),
        (r"приказ\w* №?\s?\d+", 2.5), (r"кии\b|критическ\w+ информацион", 2),
        (r"гост\s?р?\s?\d+", 2.5), (r"регулятор\w*|законопроект|нацплан", 2),
        (r"категорирован", 2.5),
    ],
    "tool_release": [
        (r"инструмент\w*|утилит\w*|tool\b", 2), (r"open[- ]?source|открыт\w+ инструмент", 2),
        (r"github\.com|репозитори\w+", 2), (r"релиз\w*|выпустил\w+ верси", 1.5),
        (r"фреймворк\w*|framework", 1.5),
    ],
}

PRIORITY = ["access_sale", "data_leak", "ransomware", "attack_claim", "malware",
            "vuln_disclosure", "phishing_fraud", "tool_release", "regulation"]


def classify_rules(text):
    norm = normalize(text)
    scores = {}
    matched = {}
    for cls, markers in RULES.items():
        s = 0.0
        hits = []
        for pat, w in markers:
            found = re.findall(pat, norm)
            if found:
                s += w * min(len(found), 3) ** 0.5
                hits.append(pat)
        if s > 0:
            scores[cls] = round(s, 2)
            matched[cls] = hits
    if not scores:
        return {"event_type": "other", "confidence": 0.0, "scores": {}, "matched": {}}
    best = max(scores, key=lambda c: (scores[c], -PRIORITY.index(c)))
    top = [c for c in scores if scores[c] >= scores[best] - 0.5]
    if len(top) > 1:
        best = min(top, key=lambda c: PRIORITY.index(c))
    total = sum(scores.values())
    confidence = round(scores[best] / total, 2) if total else 0.0
    return {"event_type": best, "confidence": confidence,
            "scores": scores, "matched": {best: matched[best]}}


if __name__ == "__main__":
    import json, sys
    from pathlib import Path
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    path = Path(__file__).resolve().parents[1] / "data" / "raw_posts.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines()[:12]:
        p = json.loads(line)
        r = classify_rules(p["text"])
        print(f"[{r['event_type']:16}] {p['text'][:70]}")
