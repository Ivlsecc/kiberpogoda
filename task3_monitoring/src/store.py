import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS posts (
    post_id       TEXT PRIMARY KEY,
    channel       TEXT,
    datetime      TEXT,
    link          TEXT,
    text          TEXT,
    lang          TEXT,
    event_type    TEXT,
    event_conf    REAL,
    companies     TEXT,
    domains       TEXT,
    cves          TEXT,
    gov           TEXT,
    dup_group     INTEGER,
    is_duplicate  INTEGER,
    event_cluster INTEGER,
    is_primary    INTEGER,
    significance  REAL,
    sig_factors   TEXT,
    classifier    TEXT
);
CREATE INDEX IF NOT EXISTS idx_event ON posts(event_type);
CREATE INDEX IF NOT EXISTS idx_sig ON posts(significance);
"""


def save_sqlite(posts, db_path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    con.execute("DELETE FROM posts")
    rows = []
    for p in posts:
        ent = p.get("entities", {})
        rows.append((
            p.get("post_id"), p.get("channel"), p.get("datetime"), p.get("link"),
            p.get("text"), p.get("lang"), p.get("event_type"), p.get("event_conf"),
            json.dumps(ent.get("companies", []), ensure_ascii=False),
            json.dumps(ent.get("domains", []), ensure_ascii=False),
            json.dumps(ent.get("cves", []), ensure_ascii=False),
            json.dumps(ent.get("gov", []), ensure_ascii=False),
            p.get("dup_group"), int(bool(p.get("is_duplicate"))),
            p.get("event_cluster", -1), int(bool(p.get("is_primary_source", True))),
            p.get("significance"), json.dumps(p.get("sig_factors", {}), ensure_ascii=False),
            p.get("classifier", "rules"),
        ))
    con.executemany(
        "INSERT OR REPLACE INTO posts VALUES (" + ",".join(["?"] * 19) + ")", rows)
    con.commit()
    con.close()


def save_jsonl(posts, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for p in posts:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
