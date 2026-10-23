import hashlib

from textutil import normalize, shingles

NUM_HASHES = 64
_MERSENNE = (1 << 61) - 1


def _minhash(sh, num=NUM_HASHES):
    if not sh:
        return [0] * num
    base = [int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big") for s in sh]
    sig = []
    for i in range(num):
        a = 2 * i + 1
        b = 2 * i + 3
        sig.append(min(((a * h + b) % _MERSENNE) for h in base))
    return sig


def _sig_sim(a, b):
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def cluster_posts(posts, threshold=0.6):
    n = len(posts)
    norms = [normalize(p["text"]) for p in posts]
    exact = {}
    sigs = []
    for i, p in enumerate(posts):
        h = hashlib.sha1(norms[i].encode()).hexdigest()
        exact.setdefault(h, []).append(i)
        sigs.append(_minhash(shingles(p["text"], k=4)))

    uf = _UF(n)
    for idxs in exact.values():
        for j in idxs[1:]:
            uf.union(idxs[0], j)
    best_sim = [0.0] * n
    for i in range(n):
        for j in range(i + 1, n):
            s = _sig_sim(sigs[i], sigs[j])
            if s >= threshold:
                uf.union(i, j)
                best_sim[i] = max(best_sim[i], s)
                best_sim[j] = max(best_sim[j], s)

    groups = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    gid_map = {}
    for k, (root, members) in enumerate(sorted(groups.items())):
        members.sort(key=lambda i: posts[i].get("datetime", ""))
        original = members[0]
        for m in members:
            gid_map[m] = {
                "dup_group": k,
                "group_size": len(members),
                "is_duplicate": (m != original) if len(members) > 1 else False,
                "original_id": posts[original].get("post_id", ""),
                "dup_sim": round(best_sim[m], 2),
            }
    out = []
    for i, p in enumerate(posts):
        out.append({**p, **gid_map[i]})
    return out


if __name__ == "__main__":
    import json, sys
    from pathlib import Path
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    path = Path(__file__).resolve().parents[1] / "data" / "raw_posts.jsonl"
    posts = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    clustered = cluster_posts(posts)
    multi = [c for c in clustered if c["group_size"] > 1]
    print(f"Постов: {len(clustered)}, в группах-дублях: {len(multi)}")
    seen = set()
    for c in clustered:
        if c["group_size"] > 1 and c["dup_group"] not in seen:
            seen.add(c["dup_group"])
            members = [x for x in clustered if x["dup_group"] == c["dup_group"]]
            print(f"\nГруппа {c['dup_group']} ({c['group_size']} шт):")
            for m in members:
                print(f"  [{m['channel']}] {m['text'][:70]}")
