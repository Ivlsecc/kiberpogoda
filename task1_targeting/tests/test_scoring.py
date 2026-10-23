import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from score import (_percentile, _winsorized_minmax, _sec_weakness,
                   score_companies, build_normalizers, _prominence)


def test_percentile_known_values():
    v = list(range(1, 11))
    assert abs(_percentile(v, 0.0) - 1) < 1e-9
    assert abs(_percentile(v, 1.0) - 10) < 1e-9
    assert abs(_percentile(v, 0.5) - 5.5) < 1e-9


def test_percentile_stays_in_range():
    v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1000]
    assert _percentile(v, 0.95) <= max(v)
    assert _percentile(v, 0.05) >= min(v)


def test_winsor_outlier_maps_to_one():
    f = _winsorized_minmax([1, 2, 3, 4, 5, 6, 7, 8, 9, 1000])
    assert abs(f(1000) - 1.0) < 1e-9
    assert 0.0 <= f(5) <= 1.0
    assert f(None) is None


def test_winsor_empty_and_constant():
    assert _winsorized_minmax([])(5) == 0.0
    assert _winsorized_minmax([3, 3, 3, 3, 3])(3) == 0.5


def test_sec_weakness():
    assert _sec_weakness({"it_vacancies": 100, "sec_vacancies": 0}) == 1.0
    assert _sec_weakness({"it_vacancies": 100, "sec_vacancies": 20}) == 0.0
    assert _sec_weakness({"it_vacancies": None, "sec_vacancies": 5}) is None


def _toy_data():
    return {"sector_trend": 0.5, "companies": [
        {"name": "HighO", "domain": "a.ru", "A": {"revenue_rub_bln": 100, "prominence": 0.5, "pii_scale": 0.5, "sector_criticality": 0.5},
         "subdomains": 300, "it_vacancies": 100, "sec_vacancies": 5,
         "leak_mentions": 20, "access_for_sale": 1, "new_cve_in_stack": 1, "shadow_mentions_30d": 2},
        {"name": "HighI", "domain": "b.ru", "A": {"revenue_rub_bln": 100, "prominence": 0.9, "pii_scale": 0.5, "sector_criticality": 0.5},
         "subdomains": 300, "it_vacancies": 100, "sec_vacancies": 5,
         "leak_mentions": 1, "access_for_sale": 0, "new_cve_in_stack": 1, "shadow_mentions_30d": 30},
        {"name": "Low", "domain": "c.ru", "A": {"revenue_rub_bln": 10, "prominence": 0.2, "pii_scale": 0.2, "sector_criticality": 0.2},
         "subdomains": 10, "it_vacancies": 10, "sec_vacancies": 3,
         "leak_mentions": 0, "access_for_sale": 0, "new_cve_in_stack": 0, "shadow_mentions_30d": 0},
    ]}


def test_profile_reweighting_changes_order():
    data = _toy_data()
    rans = {r["name"]: i for i, r in enumerate(score_companies(data, "ransomware"))}
    hack = {r["name"]: i for i, r in enumerate(score_companies(data, "hacktivist"))}
    assert rans["HighO"] <= rans["HighI"]
    assert hack["HighI"] < rans["HighI"]


def test_confidence_drops_on_missing_data():
    data = {"sector_trend": 0.5, "companies": [
        {"name": "Full", "domain": "a.ru", "A": {"revenue_rub_bln": 100, "prominence": 0.5, "pii_scale": 0.5, "sector_criticality": 0.5},
         "subdomains": 300, "it_vacancies": 100, "sec_vacancies": 5,
         "leak_mentions": 5, "access_for_sale": 1, "new_cve_in_stack": 1, "shadow_mentions_30d": 5},
        {"name": "Sparse", "domain": "b.ru", "A": {"prominence": 0.5},
         "subdomains": 300},
    ]}
    res = {r["name"]: r for r in score_companies(data, "ransomware")}
    assert res["Full"]["confidence"] > res["Sparse"]["confidence"]
    assert res["Sparse"]["confidence"] < 0.6


def test_monotonicity_more_opportunity_raises_score():
    base = _toy_data()
    s_before = {r["name"]: r["score"] for r in score_companies(base, "ransomware")}["Low"]
    bumped = _toy_data()
    bumped["companies"][2]["leak_mentions"] = 50
    bumped["companies"][2]["access_for_sale"] = 1
    s_after = {r["name"]: r["score"] for r in score_companies(bumped, "ransomware")}["Low"]
    assert s_after > s_before


def test_prominence_prefers_live_wiki():
    norm = build_normalizers([
        {"A": {"prominence": 0.1}, "wiki_views_median": 100},
        {"A": {"prominence": 0.1}, "wiki_views_median": 100000},
    ])
    hi = _prominence({"A": {"prominence": 0.1}, "wiki_views_median": 100000}, norm)
    lo = _prominence({"A": {"prominence": 0.1}, "wiki_views_median": 100}, norm)
    assert hi > lo
    assert _prominence({"A": {"prominence": 0.42}}, norm) == 0.42


def run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(tests)} тестов прошли.")
    return passed == len(tests)


if __name__ == "__main__":
    ok = run_all()
    sys.exit(0 if ok else 1)
