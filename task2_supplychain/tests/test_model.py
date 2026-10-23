import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from model import Graph, load, ACCESS_SEVERITY
import build

DATA = ROOT / "data" / "dependencies.json"


def _g():
    return load(DATA)


def test_transmission_monotonic():
    base = {"crit": 0.5, "access": "data", "subst": 0.5}
    t0 = Graph.transmission(base)
    assert Graph.transmission({**base, "crit": 0.9}) > t0
    assert Graph.transmission({**base, "access": "code"}) > t0
    assert Graph.transmission({**base, "subst": 0.1}) > t0
    assert Graph.transmission({**base, "subst": 0.9}) < t0


def test_access_order():
    assert ACCESS_SEVERITY["none"] < ACCESS_SEVERITY["data"] < ACCESS_SEVERITY["network"] < ACCESS_SEVERITY["code"]


def test_shock_bounded():
    g = _g()
    for nid in g.nodes:
        if nid == g.focal:
            continue
        s = g.systemic_shock(nid)
        assert 0.0 <= s <= 1.0


def test_decay_reduces_transitive():
    g = _g()
    hi = g.systemic_shock("SHARED_IAAS", decay=0.9)
    lo = g.systemic_shock("SHARED_IAAS", decay=0.3)
    assert hi > lo


def test_shared_iaas_is_chokepoint():
    g = _g()
    rows = {r["id"]: r for r in g.assess()}
    assert rows["SHARED_IAAS"]["fanout"] >= 3
    assert rows["SHARED_IAAS"]["direct_risk"] == 0.0
    assert rows["SHARED_IAAS"]["systemic_risk"] > 0.0


def test_idp_amplified_vs_direct():
    g = _g()
    rows = {r["id"]: r for r in g.assess()}
    idp = rows["IDP"]
    assert idp["amplification"] is not None and idp["amplification"] > 1.1


def test_transitive_only_node_has_systemic_but_no_direct():
    g = _g()
    rows = {r["id"]: r for r in g.assess()}
    for nid in ("INTEGRATOR_MSP", "TELEMATICS"):
        assert rows[nid]["direct_risk"] == 0.0
        assert rows[nid]["systemic_risk"] > 0.0


def test_deterministic():
    g = _g()
    a = g.assess()
    b = g.assess()
    assert [r["id"] for r in a] == [r["id"] for r in b]
    assert [r["systemic_risk"] for r in a] == [r["systemic_risk"] for r in b]


def test_paths_are_simple():
    g = _g()
    for p in g.paths_to_focal("SHARED_IAAS"):
        seen = [e["src"] for e in p] + [g.focal]
        assert len(seen) == len(set(seen))


def test_bridge_matches_real_ct():
    rep = build.verify_bridge()
    if not rep.get("real_hosts_total"):
        print("    (ct_real.json недоступен — сверка пропущена)")
        return
    assert rep["ok"], f"есть хосты вне ct_real.json: {rep}"


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
