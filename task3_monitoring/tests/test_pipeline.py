import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from classify import classify_rules
from ner import extract_entities
from dedup import cluster_posts
from enrich import significance, cross_source_events
from textutil import normalize, shingles, detect_lang


def test_classify_core_types():
    assert classify_rules("Продажа доступа к сети компании, цена договорная")["event_type"] == "access_sale"
    assert classify_rules("Произошла крупная утечка данных, база клиентов в сеть")["event_type"] == "data_leak"
    assert classify_rules("Критическая уязвимость CVE-2026-1234, опубликован эксплойт RCE")["event_type"] == "vuln_disclosure"
    assert classify_rules("Шифровальщик зашифровал серверы, требуют выкуп")["event_type"] == "ransomware"
    assert classify_rules("Приказ ФСТЭК №117 и 187-ФЗ о категорировании КИИ")["event_type"] == "regulation"


def test_classify_other_on_noise():
    assert classify_rules("Сегодня хорошая погода и вкусный кофе")["event_type"] == "other"


def test_ner_domains_cve_company():
    e = extract_entities("Взломали FirstVDS через CVE-2026-9999, затронут gitlab.magnit.ru и Drupal")
    assert "CVE-2026-9999" in e["cves"]
    assert "gitlab.magnit.ru" in e["domains"]
    assert "FirstVDS" in e["companies"]
    assert "Drupal" in e["companies"]


def test_ner_canonicalizes_morphology():
    e = extract_entities("Рекламная сеть «Яндекса» и данные Сбербанка")
    assert "Яндекс" in e["companies"]
    assert "Сбер" in e["companies"]


def test_dedup_catches_repost():
    base = {"post_id": "a/1", "channel": "a", "datetime": "2026-10-01T10:00:00+00:00",
            "text": "Хакеры взломали хостинг FirstVDS и украли SSH-ключи и пароли клиентов"}
    copy = {**base, "post_id": "b/1", "channel": "b", "datetime": "2026-10-01T12:00:00+00:00"}
    other = {"post_id": "c/1", "channel": "c", "datetime": "2026-10-02T10:00:00+00:00",
             "text": "Новый приказ ФСТЭК о категорировании объектов КИИ вступил в силу"}
    res = cluster_posts([base, copy, other], threshold=0.6)
    g = {r["post_id"]: r for r in res}
    assert g["a/1"]["dup_group"] == g["b/1"]["dup_group"]
    assert g["c/1"]["dup_group"] != g["a/1"]["dup_group"]


def test_significance_tracked_company_higher():
    now = dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc)
    tracked = {"event_type": "data_leak", "datetime": "2026-10-20T10:00:00+00:00",
               "entities": {"companies": ["Ozon"], "cves": []}}
    generic = {"event_type": "data_leak", "datetime": "2026-10-20T10:00:00+00:00",
               "entities": {"companies": ["НекийСтартап"], "cves": []}}
    assert significance(tracked, now)["significance"] > significance(generic, now)["significance"]


def test_significance_freshness_decay():
    now = dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc)
    fresh = {"event_type": "attack_claim", "datetime": "2026-10-21T00:00:00+00:00", "entities": {"companies": ["VK"]}}
    old = {"event_type": "attack_claim", "datetime": "2026-09-01T00:00:00+00:00", "entities": {"companies": ["VK"]}}
    assert significance(fresh, now)["significance"] > significance(old, now)["significance"]


def test_cross_source_matches_same_entity():
    posts = [
        {"post_id": "a/1", "channel": "a", "datetime": "2026-10-20T10:00:00+00:00",
         "event_type": "attack_claim", "entities": {"companies": ["FirstVDS"], "cves": [], "domains": []}},
        {"post_id": "b/1", "channel": "b", "datetime": "2026-10-20T14:00:00+00:00",
         "event_type": "attack_claim", "entities": {"companies": ["FirstVDS"], "cves": [], "domains": []}},
        {"post_id": "c/1", "channel": "c", "datetime": "2026-10-20T10:00:00+00:00",
         "event_type": "regulation", "entities": {"companies": ["ФСТЭК"], "cves": [], "domains": []}},
    ]
    res = cross_source_events(posts, window_hours=72)
    g = {r["post_id"]: r for r in res}
    assert g["a/1"]["event_cluster"] == g["b/1"]["event_cluster"] >= 0
    assert g["a/1"]["is_primary_source"] is True
    assert g["c/1"]["event_cluster"] == -1


def test_textutil():
    assert detect_lang("привет мир") == "ru"
    assert detect_lang("hello world") == "en"
    assert "cve" in normalize("CVE-2026-1 !!!")
    assert len(shingles("one two three four five", k=4)) == 2


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
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(0 if run_all() else 1)
