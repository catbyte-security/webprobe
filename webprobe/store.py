"""SQLite storage layer for captured HTTP traffic and findings."""

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Optional

DEFAULT_DB = "webprobe.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    method TEXT,
    url TEXT,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    path TEXT,
    query TEXT,
    request_headers TEXT,
    request_body BLOB,
    request_content_type TEXT,
    response_status INTEGER,
    response_reason TEXT,
    response_headers TEXT,
    response_body BLOB,
    response_content_type TEXT,
    response_length INTEGER,
    duration_ms REAL,
    source TEXT DEFAULT 'proxy',
    tags TEXT DEFAULT '[]',
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    category TEXT,
    severity TEXT,
    title TEXT,
    detail TEXT,
    evidence TEXT,
    created_at REAL,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT UNIQUE,
    scope_type TEXT DEFAULT 'include'
);

CREATE TABLE IF NOT EXISTS params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    location TEXT,
    name TEXT,
    value TEXT,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE INDEX IF NOT EXISTS idx_req_host ON requests(host);
CREATE INDEX IF NOT EXISTS idx_req_path ON requests(path);
CREATE INDEX IF NOT EXISTS idx_req_method ON requests(method);
CREATE INDEX IF NOT EXISTS idx_req_status ON requests(response_status);
CREATE INDEX IF NOT EXISTS idx_req_source ON requests(source);
CREATE INDEX IF NOT EXISTS idx_findings_cat ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_params_name ON params(name);
"""


class Store:
    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ── Requests ──────────────────────────────────────────────

    def insert_request(self, **kw) -> int:
        kw.setdefault("timestamp", time.time())
        kw.setdefault("tags", "[]")
        kw.setdefault("notes", "")
        cols = ", ".join(kw.keys())
        placeholders = ", ".join(["?"] * len(kw))
        cur = self.conn.execute(
            f"INSERT INTO requests ({cols}) VALUES ({placeholders})",
            list(kw.values()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_request(self, req_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM requests WHERE id = ?", (req_id,)
        ).fetchone()
        return dict(row) if row else None

    def query_requests(
        self,
        method: str = None,
        host: str = None,
        path_contains: str = None,
        status: int = None,
        status_range: tuple = None,
        source: str = None,
        has_params: bool = None,
        content_type: str = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict]:
        clauses, params = [], []
        if method:
            clauses.append("method = ?")
            params.append(method.upper())
        if host:
            clauses.append("host LIKE ?")
            params.append(f"%{host}%")
        if path_contains:
            clauses.append("path LIKE ?")
            params.append(f"%{path_contains}%")
        if status is not None:
            clauses.append("response_status = ?")
            params.append(status)
        if status_range:
            clauses.append("response_status BETWEEN ? AND ?")
            params.extend(status_range)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if content_type:
            clauses.append("response_content_type LIKE ?")
            params.append(f"%{content_type}%")

        where = " AND ".join(clauses) if clauses else "1=1"
        sql = f"SELECT * FROM requests WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self.conn.execute(sql, params).fetchall()
        results = [dict(r) for r in rows]

        if has_params is not None:
            if has_params:
                results = [
                    r for r in results
                    if r.get("query") or r.get("request_body")
                ]
            else:
                results = [
                    r for r in results
                    if not r.get("query") and not r.get("request_body")
                ]
        return results

    def count_requests(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]

    def get_unique_hosts(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT host FROM requests ORDER BY host"
        ).fetchall()
        return [r[0] for r in rows]

    def get_endpoints(self, host: str = None) -> list[dict]:
        """Get unique method+path combinations with hit counts."""
        if host:
            rows = self.conn.execute(
                """SELECT method, path, host, COUNT(*) as hits,
                   GROUP_CONCAT(DISTINCT response_status) as statuses
                   FROM requests WHERE host LIKE ?
                   GROUP BY method, path ORDER BY hits DESC""",
                (f"%{host}%",),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT method, path, host, COUNT(*) as hits,
                   GROUP_CONCAT(DISTINCT response_status) as statuses
                   FROM requests GROUP BY method, path ORDER BY hits DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Findings ──────────────────────────────────────────────

    def insert_finding(self, request_id: int, category: str, severity: str,
                       title: str, detail: str, evidence: str = "") -> int:
        cur = self.conn.execute(
            """INSERT INTO findings (request_id, category, severity, title, detail, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (request_id, category, severity, title, detail, evidence, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_findings(self, category: str = None, severity: str = None,
                     request_id: int = None, limit: int = 500) -> list[dict]:
        clauses, params = [], []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if request_id:
            clauses.append("request_id = ?")
            params.append(request_id)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY id DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_findings(self):
        self.conn.execute("DELETE FROM findings")
        self.conn.commit()

    # ── Scope ─────────────────────────────────────────────────

    def add_scope(self, pattern: str, scope_type: str = "include"):
        self.conn.execute(
            "INSERT OR IGNORE INTO scope (pattern, scope_type) VALUES (?, ?)",
            (pattern, scope_type),
        )
        self.conn.commit()

    def remove_scope(self, pattern: str):
        self.conn.execute("DELETE FROM scope WHERE pattern = ?", (pattern,))
        self.conn.commit()

    def get_scope(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM scope ORDER BY scope_type, pattern").fetchall()
        return [dict(r) for r in rows]

    def is_in_scope(self, host: str) -> bool:
        scope = self.get_scope()
        if not scope:
            return True
        includes = [s["pattern"] for s in scope if s["scope_type"] == "include"]
        excludes = [s["pattern"] for s in scope if s["scope_type"] == "exclude"]
        for ex in excludes:
            if ex in host or host.endswith(ex):
                return False
        if not includes:
            return True
        for inc in includes:
            if inc in host or host.endswith(inc):
                return True
        return False

    # ── Params ────────────────────────────────────────────────

    def insert_params(self, request_id: int, params_list: list[dict]):
        self.conn.executemany(
            "INSERT INTO params (request_id, location, name, value) VALUES (?, ?, ?, ?)",
            [(request_id, p["location"], p["name"], p["value"]) for p in params_list],
        )
        self.conn.commit()

    def get_unique_params(self) -> list[dict]:
        rows = self.conn.execute(
            """SELECT name, location, COUNT(DISTINCT request_id) as seen_in,
                      COUNT(DISTINCT value) as unique_values
               FROM params GROUP BY name, location ORDER BY seen_in DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Fingerprinting ────────────────────────────────────────

    def get_response_fingerprints(self, host: str = None) -> list[dict]:
        """Group requests by response body hash to detect SPA catch-all patterns."""
        clause = "WHERE host LIKE ?" if host else ""
        params = [f"%{host}%"] if host else []
        rows = self.conn.execute(
            f"SELECT id, path, host, response_status, response_body, response_length, response_content_type FROM requests {clause}",
            params,
        ).fetchall()

        by_hash: dict[str, list] = {}
        for r in rows:
            body = r["response_body"]
            if not body:
                continue
            if isinstance(body, bytes):
                h = hashlib.md5(body).hexdigest()
            else:
                h = hashlib.md5(body.encode()).hexdigest()
            by_hash.setdefault(h, []).append({
                "id": r["id"], "path": r["path"], "host": r["host"],
                "status": r["response_status"], "length": r["response_length"],
                "content_type": r["response_content_type"],
            })

        groups = []
        for body_hash, reqs in sorted(by_hash.items(), key=lambda x: -len(x[1])):
            if len(reqs) >= 2:
                groups.append({
                    "body_hash": body_hash,
                    "count": len(reqs),
                    "is_spa_catchall": len(reqs) >= 5 and "text/html" in (reqs[0].get("content_type") or ""),
                    "sample_paths": [r["path"] for r in reqs[:15]],
                    "status_codes": list(set(r["status"] for r in reqs)),
                    "response_length": reqs[0]["length"],
                    "requests": reqs,
                })
        return groups

    def get_status_anomalies(self, host: str = None) -> list[dict]:
        """Find paths returning 403 when most unknowns return 404 (protected paths)."""
        clause = "WHERE host LIKE ?" if host else ""
        params = [f"%{host}%"] if host else []
        rows = self.conn.execute(
            f"SELECT path, host, response_status, url FROM requests {clause} ORDER BY host, response_status",
            params,
        ).fetchall()

        # Group by host
        by_host: dict[str, list] = {}
        for r in rows:
            by_host.setdefault(r["host"], []).append(dict(r))

        anomalies = []
        for h, reqs in by_host.items():
            status_counts: dict[int, int] = {}
            for r in reqs:
                s = r["response_status"] or 0
                status_counts[s] = status_counts.get(s, 0) + 1

            # If 404 is common, paths returning 403 are interesting
            total_404 = status_counts.get(404, 0)
            total_403 = status_counts.get(403, 0)
            if total_404 > 3 and total_403 > 0:
                protected = [r for r in reqs if r["response_status"] == 403]
                for p in protected:
                    anomalies.append({
                        "host": h,
                        "path": p["path"],
                        "url": p["url"],
                        "status": 403,
                        "reason": f"Returns 403 while {total_404} other paths return 404 - path exists but is protected",
                    })

            # Paths returning different-length 200s vs the SPA shell
            ok_reqs = [r for r in reqs if r["response_status"] == 200]
            # More anomaly patterns can be added here

        return anomalies

    def get_js_bodies(self) -> list[dict]:
        """Get all captured JavaScript file contents."""
        rows = self.conn.execute(
            """SELECT id, url, host, response_body, response_length
               FROM requests
               WHERE (response_content_type LIKE '%javascript%' OR url LIKE '%.js')
               AND response_status = 200 AND response_length > 100"""
        ).fetchall()
        results = []
        for r in rows:
            body = r["response_body"]
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            results.append({"id": r["id"], "url": r["url"], "host": r["host"],
                           "body": body, "length": r["response_length"]})
        return results

    def extract_subdomains(self) -> list[dict]:
        """Extract all subdomains seen across requests, headers, and response bodies."""
        subdomains: dict[str, set] = {}  # domain -> set of sources

        # From request hosts
        hosts = self.get_unique_hosts()
        for h in hosts:
            subdomains.setdefault(h, set()).add("request_host")

        # From response bodies and headers
        domain_pattern = re.compile(r'(?:https?://)?([a-zA-Z][a-zA-Z0-9\-]{0,61}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,61})*\.[a-zA-Z]{2,})')

        # Get scope domains for filtering
        scope = self.get_scope()
        scope_patterns = [s["pattern"] for s in scope if s["scope_type"] == "include"]

        rows = self.conn.execute(
            "SELECT response_body, response_headers FROM requests WHERE response_body IS NOT NULL"
        ).fetchall()

        for r in rows:
            for field in ("response_body", "response_headers"):
                data = r[field]
                if not data:
                    continue
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                for match in domain_pattern.findall(data):
                    match = match.lower().rstrip(".")
                    if scope_patterns:
                        if any(p in match for p in scope_patterns):
                            subdomains.setdefault(match, set()).add(f"response_{field}")
                    else:
                        subdomains.setdefault(match, set()).add(f"response_{field}")

        return [
            {"domain": d, "sources": sorted(s), "in_scope": self.is_in_scope(d)}
            for d, s in sorted(subdomains.items())
        ]

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        c = self.conn
        return {
            "total_requests": c.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
            "unique_hosts": c.execute("SELECT COUNT(DISTINCT host) FROM requests").fetchone()[0],
            "unique_endpoints": c.execute("SELECT COUNT(DISTINCT path) FROM requests").fetchone()[0],
            "methods": dict(c.execute(
                "SELECT method, COUNT(*) FROM requests GROUP BY method"
            ).fetchall()),
            "status_codes": dict(c.execute(
                "SELECT response_status, COUNT(*) FROM requests WHERE response_status IS NOT NULL GROUP BY response_status"
            ).fetchall()),
            "sources": dict(c.execute(
                "SELECT source, COUNT(*) FROM requests GROUP BY source"
            ).fetchall()),
            "findings_by_severity": dict(c.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            ).fetchall()),
            "findings_by_category": dict(c.execute(
                "SELECT category, COUNT(*) FROM findings GROUP BY category"
            ).fetchall()),
            "total_findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "content_types": dict(c.execute(
                "SELECT response_content_type, COUNT(*) FROM requests WHERE response_content_type IS NOT NULL GROUP BY response_content_type ORDER BY COUNT(*) DESC LIMIT 20"
            ).fetchall()),
        }

    def request_to_dict(self, req: dict, include_body: bool = False) -> dict:
        """Convert a request row to a clean dict for JSON output."""
        out = {
            "id": req["id"],
            "timestamp": req["timestamp"],
            "method": req["method"],
            "url": req["url"],
            "host": req["host"],
            "path": req["path"],
            "query": req["query"],
            "status": req["response_status"],
            "content_type": req["response_content_type"],
            "response_length": req["response_length"],
            "duration_ms": req["duration_ms"],
            "source": req["source"],
        }
        if include_body:
            out["request_headers"] = json.loads(req["request_headers"] or "{}")
            out["response_headers"] = json.loads(req["response_headers"] or "{}")
            req_body = req.get("request_body")
            if isinstance(req_body, bytes):
                try:
                    out["request_body"] = req_body.decode("utf-8", errors="replace")
                except Exception:
                    out["request_body"] = f"<binary {len(req_body)} bytes>"
            else:
                out["request_body"] = req_body
            resp_body = req.get("response_body")
            if isinstance(resp_body, bytes):
                try:
                    out["response_body"] = resp_body.decode("utf-8", errors="replace")
                except Exception:
                    out["response_body"] = f"<binary {len(resp_body)} bytes>"
            else:
                out["response_body"] = resp_body
        else:
            out["request_headers"] = json.loads(req["request_headers"] or "{}")
        return out
