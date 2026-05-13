"""SQLite-backed store. Uses stdlib ``sqlite3``; no async to keep deps light.

Schema mirrors the ars0n-port plan: engagements, targets, tool_runs (polymorphic),
assets, url_facts, endpoints+params, findings, notes.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import DB_PATH
from .finding import Finding


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS engagements (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT UNIQUE NOT NULL,
  type         TEXT NOT NULL,
  authorized_by TEXT,
  start_date   TEXT, end_date TEXT,
  scope_path   TEXT, created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,                    -- domain|wildcard|cidr|url
  value         TEXT NOT NULL,
  in_scope      INTEGER NOT NULL DEFAULT 1,
  added_at      REAL NOT NULL,
  UNIQUE(engagement_id, kind, value)
);

CREATE TABLE IF NOT EXISTS tool_runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER REFERENCES engagements(id) ON DELETE CASCADE,
  target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  tool          TEXT NOT NULL,
  command       TEXT NOT NULL,
  status        TEXT NOT NULL,                    -- ok|failed|skipped|refused
  exit_code     INTEGER,
  stdout_path   TEXT, stderr_path TEXT,
  started_at    REAL, finished_at REAL,
  duration_s    REAL,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,                    -- asn|cidr|ip|fqdn|url|web_server|cloud
  identifier    TEXT NOT NULL,
  parent_id     INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  first_seen    REAL, last_seen REAL,
  newly_discovered  INTEGER NOT NULL DEFAULT 1,
  no_longer_live    INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT,
  UNIQUE(engagement_id, kind, identifier)
);

CREATE TABLE IF NOT EXISTS url_facts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id      INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  status_code   INTEGER, title TEXT, server TEXT,
  technologies  TEXT,                              -- JSON list
  content_length INTEGER,
  ssl_flags_json TEXT, response_headers_json TEXT,
  response_body_path TEXT, dns_records_json TEXT,
  screenshot_path TEXT,
  roi_score     INTEGER NOT NULL DEFAULT 50,
  roi_breakdown_json TEXT,
  newly_discovered  INTEGER NOT NULL DEFAULT 1,
  no_longer_live    INTEGER NOT NULL DEFAULT 0,
  updated_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  method        TEXT NOT NULL, url TEXT NOT NULL, source TEXT,
  UNIQUE(engagement_id, method, url)
);

CREATE TABLE IF NOT EXISTS endpoint_params (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint_id   INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name          TEXT NOT NULL, location TEXT NOT NULL, value_example TEXT,
  UNIQUE(endpoint_id, name, location)
);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid          TEXT UNIQUE NOT NULL,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  asset         TEXT NOT NULL,
  code          TEXT NOT NULL, title TEXT NOT NULL,
  severity      TEXT NOT NULL, cvss REAL, confidence TEXT,
  description   TEXT, evidence_json TEXT, recommendation TEXT,
  references_json TEXT,
  wstg_id       TEXT, bbb_chapter TEXT, cwe TEXT, owasp_top10 TEXT,
  dedup_key     TEXT,
  created_at    REAL NOT NULL,
  UNIQUE(engagement_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS notes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  body_md       TEXT, created_at REAL NOT NULL
);
"""


def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def store() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ----- helpers --------------------------------------------------------------

def get_or_create_engagement(conn: sqlite3.Connection, name: str, type_: str = "lab",
                              authorized_by: str = "", start: str = "", end: str = "",
                              scope_path: str = "") -> int:
    row = conn.execute("SELECT id FROM engagements WHERE name=?", (name,)).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO engagements(name,type,authorized_by,start_date,end_date,scope_path,created_at) VALUES(?,?,?,?,?,?,?)",
        (name, type_, authorized_by, start, end, scope_path, time.time()),
    )
    return cur.lastrowid


def add_target(conn: sqlite3.Connection, engagement_id: int, value: str, kind: str = "domain",
               in_scope: bool = True) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO targets(engagement_id,kind,value,in_scope,added_at) VALUES(?,?,?,?,?)",
        (engagement_id, kind, value, 1 if in_scope else 0, time.time()),
    )
    row = conn.execute(
        "SELECT id FROM targets WHERE engagement_id=? AND kind=? AND value=?",
        (engagement_id, kind, value),
    ).fetchone()
    return row["id"]


def record_tool_run(conn: sqlite3.Connection, engagement_id: int | None, target_id: int | None,
                    tool: str, command: str, status: str,
                    exit_code: int | None = None, stdout_path: str = "", stderr_path: str = "",
                    started_at: float = 0.0, finished_at: float = 0.0,
                    metadata: dict[str, Any] | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO tool_runs(engagement_id,target_id,tool,command,status,exit_code,stdout_path,stderr_path,"
        "started_at,finished_at,duration_s,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (engagement_id, target_id, tool, command, status, exit_code, stdout_path, stderr_path,
         started_at, finished_at, max(0.0, finished_at - started_at) if started_at else None,
         json.dumps(metadata or {})),
    )
    return cur.lastrowid


def upsert_asset(conn: sqlite3.Connection, engagement_id: int, kind: str, identifier: str,
                 parent_id: int | None = None, metadata: dict[str, Any] | None = None) -> int:
    now = time.time()
    conn.execute(
        "INSERT INTO assets(engagement_id,kind,identifier,parent_id,first_seen,last_seen,metadata_json) "
        "VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(engagement_id,kind,identifier) DO UPDATE SET last_seen=excluded.last_seen, "
        "  newly_discovered=0, metadata_json=COALESCE(excluded.metadata_json, assets.metadata_json)",
        (engagement_id, kind, identifier, parent_id, now, now, json.dumps(metadata or {})),
    )
    row = conn.execute(
        "SELECT id FROM assets WHERE engagement_id=? AND kind=? AND identifier=?",
        (engagement_id, kind, identifier),
    ).fetchone()
    return row["id"]


def upsert_url_fact(conn: sqlite3.Connection, asset_id: int, **fields: Any) -> int:
    fields.setdefault("updated_at", time.time())
    cols = list(fields.keys())
    placeholders = ",".join("?" * (len(cols) + 1))
    vals = [asset_id] + [fields[k] if not isinstance(fields[k], (list, dict)) else json.dumps(fields[k]) for k in cols]
    set_clause = ",".join(f"{c}=excluded.{c}" for c in cols)
    conn.execute(
        f"INSERT INTO url_facts(asset_id,{','.join(cols)}) VALUES({placeholders}) "
        f"ON CONFLICT(asset_id) DO UPDATE SET {set_clause}",
        vals,
    )
    row = conn.execute("SELECT id FROM url_facts WHERE asset_id=?", (asset_id,)).fetchone()
    return row["id"]


def insert_finding(conn: sqlite3.Connection, engagement_id: int, f: Finding) -> int | None:
    key = f.dedup_key()
    try:
        cur = conn.execute(
            "INSERT INTO findings(uuid,engagement_id,asset,code,title,severity,cvss,confidence,description,"
            "evidence_json,recommendation,references_json,wstg_id,bbb_chapter,cwe,owasp_top10,dedup_key,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, engagement_id, f.asset, f.code, f.title, f.severity, f.cvss, f.confidence,
             f.description, json.dumps(f.evidence), f.recommendation, json.dumps(f.references),
             f.wstg_id, f.bbb_chapter, f.cwe, f.owasp_top10, key, f.created_at),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None  # duplicate


def dump_engagement_findings(engagement_name: str, reports_root: Path) -> Path | None:
    """Write ``reports/<engagement>/findings.json`` with every finding for that
    engagement, plus a tiny ``findings_summary.txt``. Returns the JSON path or
    ``None`` if the engagement doesn't exist in the store.

    Safe to call after every scan — overwrites cleanly each time.
    """
    with store() as conn:
        row = conn.execute("SELECT id FROM engagements WHERE name=?", (engagement_name,)).fetchone()
        if not row:
            return None
        findings = list_findings(conn, row["id"])
    out_dir = Path(reports_root) / engagement_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # findings.json — machine-readable dump
    fjson = out_dir / "findings.json"
    fjson.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")

    # findings_summary.txt — quick human glance
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1
    summary = (
        f"engagement: {engagement_name}\n"
        f"findings:   {len(findings)}\n"
        f"  critical: {counts['critical']}\n"
        f"  high:     {counts['high']}\n"
        f"  medium:   {counts['medium']}\n"
        f"  low:      {counts['low']}\n"
        f"  info:     {counts['info']}\n"
    )
    (out_dir / "findings_summary.txt").write_text(summary, encoding="utf-8")
    return fjson


def list_findings(conn: sqlite3.Connection, engagement_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE engagement_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
        " WHEN 'low' THEN 1 ELSE 0 END DESC, created_at ASC",
        (engagement_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for jcol in ("evidence_json", "references_json"):
            if d.get(jcol):
                try:
                    d[jcol.replace("_json", "")] = json.loads(d[jcol])
                except json.JSONDecodeError:
                    pass
        out.append(d)
    return out
