"""Incident and device database (SQLite).

Live mode: the database lives in /var/lib/sentinel on the RAM overlay and is
lost at shutdown unless the user exports a report. Persistent mode: the same
path is on the encrypted persistence partition.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .rules import Device, Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  key TEXT PRIMARY KEY, rule TEXT, level TEXT, severity TEXT,
  src TEXT, dst TEXT, first_ts REAL, last_ts REAL, count INTEGER,
  facts TEXT, evidence TEXT, status TEXT DEFAULT 'aperto', ack_ts REAL
);
CREATE TABLE IF NOT EXISTS devices (
  key TEXT PRIMARY KEY, mac TEXT, ip TEXT, hostname TEXT, mdns TEXT, services TEXT,
  first_seen REAL, last_seen REAL, is_gateway INTEGER, is_self INTEGER, new INTEGER
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, action TEXT, target TEXT,
  result TEXT, undone_ts REAL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS agent_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, incident_key TEXT, action TEXT, target TEXT,
  params TEXT, status TEXT, reason TEXT, result TEXT, expires_ts REAL, updated_ts REAL
);
CREATE TABLE IF NOT EXISTS agent_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, text TEXT, task_id INTEGER
);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        try:
            # The daemon (user sentinel, umask 007) creates the file; SQLite would make it 0640, so the
            # Security Center (user analyst, group sentinel) could not record actions or close alarms.
            if self.path.stat().st_uid == os.getuid():
                os.chmod(self.path, 0o660)
        except OSError:
            pass
        try:                                        # added in 0.2: end of a user-started scan
            self.db.execute("ALTER TABLE actions ADD COLUMN end_ts REAL")
        except sqlite3.OperationalError:
            pass

    # ---------------------------------------------------------- writes
    def upsert_incident(self, i: Incident) -> None:
        self.db.execute(
            """INSERT INTO incidents(key,rule,level,severity,src,dst,first_ts,last_ts,count,facts,evidence)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET level=excluded.level, severity=excluded.severity,
                 last_ts=excluded.last_ts, count=excluded.count, facts=excluded.facts,
                 evidence=excluded.evidence,
                 status=CASE WHEN incidents.status='chiuso' AND excluded.last_ts>incidents.ack_ts
                             THEN 'aperto' ELSE incidents.status END""",
            (i.key, i.rule, i.level, i.severity, i.src, i.dst, i.first_ts, i.last_ts, i.count,
             json.dumps(i.facts), json.dumps(i.evidence)))

    def upsert_device(self, k: str, d: Device) -> None:
        self.db.execute(
            """INSERT INTO devices(key,mac,ip,hostname,mdns,services,first_seen,last_seen,is_gateway,is_self,new)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET mac=excluded.mac, ip=excluded.ip, hostname=excluded.hostname,
                 mdns=excluded.mdns, services=excluded.services, last_seen=excluded.last_seen,
                 is_gateway=excluded.is_gateway, is_self=excluded.is_self""",
            (k, d.mac, d.ip, d.hostname, json.dumps(d.mdns_names), json.dumps(d.services),
             d.first_seen, d.last_seen, int(d.is_gateway), int(d.is_self), int(d.new)))

    def close_incident(self, key: str) -> None:
        self.db.execute("UPDATE incidents SET status='chiuso', ack_ts=? WHERE key=?", (time.time(), key))
        self.db.commit()

    def log_action(self, action: str, target: str, result: str) -> int:
        cur = self.db.execute("INSERT INTO actions(ts,action,target,result) VALUES(?,?,?,?)",
                              (time.time(), action, target, result))
        self.db.commit()
        return cur.lastrowid

    def finish_action(self, action_id: int, result: str) -> None:
        """Close a user-started scan: its end bounds the "your own activity" window."""
        self.db.execute("UPDATE actions SET end_ts=?, result=? WHERE id=?", (time.time(), result, action_id))
        self.db.commit()

    def scan_windows(self, since: float = 0.0) -> list[tuple]:
        """(start, end, kind, target) of the scans the user started from the Security Center."""
        rows = self.db.execute("SELECT ts, end_ts, action, target FROM actions "
                               "WHERE action LIKE 'scansione%' AND ts>=?", (since,)).fetchall()
        return [(r["ts"], r["end_ts"], r["action"], r["target"]) for r in rows]

    def mark_undone(self, action_id: int) -> None:
        self.db.execute("UPDATE actions SET undone_ts=? WHERE id=?", (time.time(), action_id))
        self.db.commit()

    def set_meta(self, k: str, v, commit: bool = False) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, json.dumps(v)))
        if commit:
            self.db.commit()

    # ---------------------------------------------------------- agent (0.3)
    def add_task(self, incident_key, action, target, params, status, reason, result=None) -> int:
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO agent_tasks(ts,incident_key,action,target,params,status,reason,result,updated_ts) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (now, incident_key, action, target, json.dumps(params or {}), status, reason,
             json.dumps(result) if result is not None else None, now))
        self.db.commit()
        return cur.lastrowid

    def update_task(self, task_id: int, **fields) -> None:
        if "result" in fields and fields["result"] is not None and not isinstance(fields["result"], str):
            fields["result"] = json.dumps(fields["result"])
        fields["updated_ts"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE agent_tasks SET {cols} WHERE id=?", (*fields.values(), task_id))
        self.db.commit()

    def tasks(self, limit: int = 300) -> list[dict]:
        out = []
        for r in self.db.execute("SELECT * FROM agent_tasks ORDER BY id DESC LIMIT ?", (limit,)).fetchall():
            d = dict(r)
            d["params"] = json.loads(d["params"] or "{}")
            try:
                d["result"] = json.loads(d["result"]) if d["result"] else None
            except ValueError:
                pass
            out.append(d)
        return out

    def task(self, task_id: int) -> dict | None:
        return next((t for t in self.tasks(1000) if t["id"] == task_id), None)

    def agent_log(self, text: str, task_id: int | None = None) -> None:
        self.db.execute("INSERT INTO agent_log(ts,text,task_id) VALUES(?,?,?)", (time.time(), text, task_id))
        self.db.commit()

    def agent_logs(self, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM agent_log ORDER BY id DESC LIMIT ?",
                                                 (limit,)).fetchall()]

    def commit(self) -> None:
        self.db.commit()

    # ---------------------------------------------------------- reads
    def incidents(self, since: float = 0.0, only_open: bool = False) -> list[dict]:
        q = "SELECT * FROM incidents WHERE last_ts>=?" + (" AND status='aperto'" if only_open else "")
        rows = self.db.execute(q + " ORDER BY last_ts DESC", (since,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["facts"] = json.loads(d["facts"] or "{}")
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    def devices(self) -> list[dict]:
        out = []
        for r in self.db.execute("SELECT * FROM devices ORDER BY is_gateway DESC, ip").fetchall():
            d = dict(r)
            d["mdns"] = json.loads(d["mdns"] or "[]")
            d["services"] = json.loads(d["services"] or "[]")
            out.append(d)
        return out

    def actions(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM actions ORDER BY ts DESC").fetchall()]

    def meta(self, k: str, default=None):
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default
