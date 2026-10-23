import datetime as dt
import math
from collections import defaultdict

SEVERITY = {
    "access_sale": 1.0, "data_leak": 0.95, "ransomware": 0.9, "attack_claim": 0.8,
    "vuln_disclosure": 0.7, "malware": 0.6, "phishing_fraud": 0.5,
    "tool_release": 0.3, "regulation": 0.3, "other": 0.2,
}

TRACKED = {"wildberries", "ozon", "магнит", "лента", "м.видео", "dns", "lamoda",
           "детский мир", "мегамаркет", "купер", "dodo pizza"}
BIG_VENDORS = {"microsoft", "google", "citrix", "netscaler", "gitlab", "drupal",
               "wordpress", "vmware", "cisco", "яндекс", "сбер", "vk", "firstvds", "vmmanager"}


def _parse_dt(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _entity_importance(companies):
    low = [c.lower() for c in companies]
    hits_tracked = [c for c in companies if c.lower() in TRACKED]
    if hits_tracked:
        return 1.0, hits_tracked
    if any(c in BIG_VENDORS for c in low):
        return 0.7, [c for c in companies if c.lower() in BIG_VENDORS]
    if companies:
        return 0.4, companies[:2]
    return 0.1, []


def significance(post, now, group_size=1):
    sev = SEVERITY.get(post.get("event_type", "other"), 0.2)
    imp, why_ent = _entity_importance(post.get("entities", {}).get("companies", []))
    has_exploit = bool(post.get("entities", {}).get("cves")) and post.get("event_type") == "vuln_disclosure"
    pdt = _parse_dt(post.get("datetime", ""))
    age_days = (now - pdt).days if pdt else 30
    fresh = 0.5 ** (max(age_days, 0) / 7)
    corrob = 1 + math.log1p(max(group_size - 1, 0))
    raw = sev * (0.5 + 0.5 * imp) * fresh * corrob
    if has_exploit:
        raw *= 1.2
    score = max(0.0, min(1.0, raw))
    factors = {
        "severity": round(sev, 2), "entity_importance": round(imp, 2),
        "freshness": round(fresh, 2), "corroboration": round(corrob, 2),
        "exploit_boost": has_exploit, "key_entities": why_ent,
    }
    return {"significance": round(score, 3), "sig_factors": factors}


def cross_source_events(posts, window_hours=72):
    n = len(posts)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    INCIDENT = {"data_leak", "access_sale", "attack_claim", "ransomware",
                "vuln_disclosure", "malware"}

    AUTHOR_ORGS = {"positive technologies", "infosecurity", "информзащита", "kaspersky",
                   "bi.zone", "threatfabric", "greynoise", "searchlight cyber", "red security",
                   "securelist", "jumpsec", "norforge"}

    def keys(p):
        if p.get("event_type") not in INCIDENT:
            return set()
        ent = p.get("entities", {})
        ks = set()
        for c in ent.get("companies", []):
            if c.lower() in AUTHOR_ORGS:
                continue
            ks.add(("c", c.lower()))
        for cve in ent.get("cves", []):
            ks.add(("v", cve))
        for d in ent.get("domains", []):
            ks.add(("d", d))
        return ks

    times = [_parse_dt(p.get("datetime", "")) for p in posts]
    index = defaultdict(list)
    for i, p in enumerate(posts):
        for k in keys(p):
            index[k].append(i)
    for k, idxs in index.items():
        if len(idxs) > 6:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                i, j = idxs[a], idxs[b]
                if times[i] and times[j] and abs((times[i] - times[j]).total_seconds()) <= window_hours * 3600:
                    if posts[i].get("event_type") == posts[j].get("event_type") or \
                       {posts[i].get("event_type"), posts[j].get("event_type")} <= \
                       {"attack_claim", "data_leak", "access_sale", "ransomware", "vuln_disclosure"}:
                        union(i, j)

    clusters = defaultdict(list)
    for i in range(n):
        clusters[find(i)].append(i)
    out = [dict(p) for p in posts]
    cid = 0
    for root, members in sorted(clusters.items()):
        if len(members) < 2:
            out[members[0]]["event_cluster"] = -1
            out[members[0]]["is_primary_source"] = True
            out[members[0]]["event_sources"] = [posts[members[0]].get("channel")]
            continue
        members.sort(key=lambda i: posts[i].get("datetime", ""))
        srcs = sorted({posts[i].get("channel") for i in members})
        for rank, i in enumerate(members):
            out[i]["event_cluster"] = cid
            out[i]["is_primary_source"] = (rank == 0)
            out[i]["event_sources"] = srcs
            out[i]["event_group_size"] = len(members)
        cid += 1
    return out


def activity_timeline(posts):
    by_day = defaultdict(int)
    by_day_type = defaultdict(lambda: defaultdict(int))
    by_company = defaultdict(int)
    for p in posts:
        d = (p.get("datetime", "") or "")[:10]
        if d:
            by_day[d] += 1
            by_day_type[d][p.get("event_type", "other")] += 1
        for c in p.get("entities", {}).get("companies", []):
            by_company[c] += 1
    counts = list(by_day.values())
    mean = sum(counts) / len(counts) if counts else 0
    var = sum((x - mean) ** 2 for x in counts) / len(counts) if counts else 0
    std = var ** 0.5
    spikes = sorted([d for d, c in by_day.items() if c > mean + std])
    top_companies = sorted(by_company.items(), key=lambda kv: -kv[1])[:12]
    return {
        "by_day": dict(sorted(by_day.items())),
        "by_day_type": {d: dict(v) for d, v in sorted(by_day_type.items())},
        "spike_days": spikes,
        "top_companies": top_companies,
        "mean_per_day": round(mean, 1), "std_per_day": round(std, 1),
    }
