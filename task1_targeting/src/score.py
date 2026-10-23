import math

PROFILE_WEIGHTS = {
    "ransomware": {"A": 0.30, "E": 0.25, "O": 0.30, "I": 0.15},
    "hacktivist": {"A": 0.40, "E": 0.20, "O": 0.10, "I": 0.30},
    "apt": {"A": 0.35, "E": 0.20, "O": 0.15, "I": 0.30},
    "broker": {"A": 0.15, "E": 0.45, "O": 0.30, "I": 0.10},
}

SUBWEIGHTS = {
    "A": {"revenue": 0.35, "prominence": 0.25, "pii_scale": 0.25, "sector_criticality": 0.15},
    "E": {"subdomains": 0.30, "it_size": 0.15, "sec_weakness": 0.25, "sensitive_exposure": 0.30},
    "O": {"leak_mentions": 0.40, "access_for_sale": 0.40, "new_cve_in_stack": 0.20},
    "I": {"shadow_mentions": 0.55, "sector_trend": 0.25, "new_cve_in_stack": 0.20},
}


def _percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = p * (len(sorted_vals) - 1)
    lo_i = int(math.floor(rank))
    hi_i = int(math.ceil(rank))
    frac = rank - lo_i
    return sorted_vals[lo_i] + frac * (sorted_vals[hi_i] - sorted_vals[lo_i])


def _winsorized_minmax(values):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return lambda x: 0.0
    if len(vals) >= 8:
        lo = _percentile(vals, 0.05)
        hi = _percentile(vals, 0.95)
    else:
        lo, hi = vals[0], vals[-1]
    if hi <= lo:
        return lambda x: 0.5 if x is not None else 0.0

    def norm(x):
        if x is None:
            return None
        x = max(lo, min(hi, x))
        return (x - lo) / (hi - lo)
    return norm


def _log(x):
    return math.log1p(x) if x is not None else None


def build_normalizers(companies):
    def col(key, transform=lambda v: v):
        return [transform(c.get(key)) if c.get(key) is not None else None for c in companies]

    revenue = []
    for c in companies:
        rev = c["A"].get("revenue_rub_bln")
        revenue.append(_log(rev) if rev is not None else None)
    subdomains = col("subdomains", _log)
    it = col("it_vacancies", _log)
    leaks = col("leak_mentions", _log)
    shadow = col("shadow_mentions_30d", _log)
    wiki = col("wiki_views_median", _log)
    hv = col("high_value_count")
    return {
        "revenue": _winsorized_minmax(revenue),
        "subdomains": _winsorized_minmax(subdomains),
        "it_size": _winsorized_minmax(it),
        "leak_mentions": _winsorized_minmax(leaks),
        "shadow_mentions": _winsorized_minmax(shadow),
        "prominence_live": _winsorized_minmax(wiki),
        "high_value": _winsorized_minmax(hv),
    }


def _sensitive_exposure(c, norm):
    dev = c.get("dev_share")
    hv = c.get("high_value_count")
    if dev is None and hv is None:
        return None
    parts, weights = [], []
    if dev is not None:
        parts.append(min(1.0, dev * 2))
        weights.append(0.5)
    if hv is not None:
        parts.append(norm["high_value"](hv))
        weights.append(0.5)
    if not weights:
        return None
    return sum(p * w for p, w in zip(parts, weights)) / sum(weights)


def _prominence(c, norm):
    wv = c.get("wiki_views_median")
    if wv is not None:
        return norm["prominence_live"](_log(wv))
    return c.get("A", {}).get("prominence")


def _sec_weakness(c):
    it = c.get("it_vacancies")
    sec = c.get("sec_vacancies")
    if it is None or sec is None or it == 0:
        return None
    ratio = sec / it
    return max(0.0, 1.0 - min(1.0, ratio * 6))


def _bin(v):
    if v is None:
        return None
    return 1.0 if v else 0.0


def _group_scores(c, norm, sector_trend):
    A = c.get("A", {})
    feats = {
        "A": {
            "revenue": norm["revenue"](_log(A.get("revenue_rub_bln"))),
            "prominence": _prominence(c, norm),
            "pii_scale": A.get("pii_scale"),
            "sector_criticality": A.get("sector_criticality"),
        },
        "E": {
            "subdomains": norm["subdomains"](_log(c.get("subdomains"))),
            "it_size": norm["it_size"](_log(c.get("it_vacancies"))),
            "sec_weakness": _sec_weakness(c),
            "sensitive_exposure": _sensitive_exposure(c, norm),
        },
        "O": {
            "leak_mentions": norm["leak_mentions"](_log(c.get("leak_mentions"))),
            "access_for_sale": _bin(c.get("access_for_sale")),
            "new_cve_in_stack": _bin(c.get("new_cve_in_stack")),
        },
        "I": {
            "shadow_mentions": norm["shadow_mentions"](_log(c.get("shadow_mentions_30d"))),
            "sector_trend": sector_trend,
            "new_cve_in_stack": _bin(c.get("new_cve_in_stack")),
        },
    }
    groups, filled = {}, {}
    for g, subw in SUBWEIGHTS.items():
        num = den = 0.0
        present = 0
        for k, w in subw.items():
            v = feats[g].get(k)
            if v is not None:
                num += w * v
                den += w
                present += 1
        groups[g] = (num / den) if den > 0 else 0.0
        filled[g] = (present, len(subw))
    return groups, filled, feats


def score_companies(data, profile="ransomware"):
    companies = data["companies"]
    sector_trend = data.get("sector_trend", 0.5)
    norm = build_normalizers(companies)
    w = PROFILE_WEIGHTS[profile]
    results = []
    for c in companies:
        groups, filled, feats = _group_scores(c, norm, sector_trend)
        score = 100 * sum(w[g] * groups[g] for g in w)
        total_present = sum(p for p, _ in filled.values())
        total_feats = sum(t for _, t in filled.values())
        confidence = total_present / total_feats if total_feats else 0.0
        drivers = sorted(w, key=lambda g: w[g] * groups[g], reverse=True)
        results.append({
            "name": c["name"],
            "domain": c["domain"],
            "score": round(score, 1),
            "confidence": round(confidence, 2),
            "groups": {g: round(groups[g], 3) for g in groups},
            "contrib": {g: round(100 * w[g] * groups[g], 1) for g in groups},
            "top_drivers": drivers[:2],
            "features": feats,
        })
    results.sort(key=lambda r: r["score"], reverse=True)
    return results
