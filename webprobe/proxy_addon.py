"""
mitmproxy addon that captures all HTTP traffic to SQLite.

This script runs INSIDE mitmdump's Python runtime, so it must only use
stdlib + mitmproxy imports. No third-party deps from our venv.

Usage: mitmdump -s proxy_addon.py --set db_path=webprobe.db
"""

import json
import os
import sqlite3
import time
from urllib.parse import urlparse, parse_qs

from mitmproxy import http, ctx


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
"""


class WebProbeAddon:
    def __init__(self):
        self.db = None
        self.flow_start = {}

    def _get_db(self):
        if self.db is None:
            db_path = os.environ.get("WEBPROBE_DB", "webprobe.db")
            self.db = sqlite3.connect(db_path, check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)
            self.db.commit()
            ctx.log.info(f"[webprobe] DB opened: {db_path}")
        return self.db

    def _is_in_scope(self, host: str) -> bool:
        db = self._get_db()
        rows = db.execute("SELECT pattern, scope_type FROM scope").fetchall()
        if not rows:
            return True
        includes = [r[0] for r in rows if r[1] == "include"]
        excludes = [r[0] for r in rows if r[1] == "exclude"]
        for ex in excludes:
            if ex in host or host.endswith(ex):
                return False
        if not includes:
            return True
        for inc in includes:
            if inc in host or host.endswith(inc):
                return True
        return False

    def request(self, flow: http.HTTPFlow):
        self.flow_start[id(flow)] = time.time()

    def response(self, flow: http.HTTPFlow):
        try:
            self._save_flow(flow)
        except Exception as e:
            ctx.log.error(f"[webprobe] Error saving flow: {e}")

    def _save_flow(self, flow: http.HTTPFlow):
        req = flow.request
        resp = flow.response

        host = req.pretty_host
        if not self._is_in_scope(host):
            return

        start_time = self.flow_start.pop(id(flow), time.time())
        duration = (time.time() - start_time) * 1000

        req_headers = dict(req.headers)
        resp_headers = dict(resp.headers) if resp else {}

        req_body = req.get_content(strict=False)
        resp_body = resp.get_content(strict=False) if resp else b""

        # Truncate large response bodies (keep first 500KB)
        max_body = 512 * 1024
        if resp_body and len(resp_body) > max_body:
            resp_body = resp_body[:max_body]

        req_ct = req.headers.get("content-type", "")
        resp_ct = resp.headers.get("content-type", "") if resp else ""

        db = self._get_db()
        cur = db.execute(
            """INSERT INTO requests
               (timestamp, method, url, scheme, host, port, path, query,
                request_headers, request_body, request_content_type,
                response_status, response_reason, response_headers,
                response_body, response_content_type, response_length,
                duration_ms, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                start_time,
                req.method,
                req.pretty_url,
                req.scheme,
                host,
                req.port,
                req.path,
                req.query,
                json.dumps(req_headers),
                req_body,
                req_ct,
                resp.status_code if resp else None,
                resp.reason if resp else None,
                json.dumps(resp_headers),
                resp_body,
                resp_ct,
                len(resp_body) if resp_body else 0,
                round(duration, 2),
                "proxy",
            ),
        )
        req_id = cur.lastrowid

        # Extract and store parameters
        self._extract_params(db, req_id, req)

        db.commit()

        status = resp.status_code if resp else "?"
        size = len(resp_body) if resp_body else 0
        ctx.log.info(
            f"[webprobe] {req.method} {req.pretty_url} -> {status} ({size}B) [{round(duration)}ms]"
        )

    def _extract_params(self, db, req_id, req):
        params = []

        # Query string params
        if req.query:
            parsed = parse_qs(req.query, keep_blank_values=True)
            for name, values in parsed.items():
                for val in values:
                    params.append((req_id, "query", name, val))

        # Body params (form-encoded)
        ct = req.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in ct:
            try:
                body = req.get_content(strict=False).decode("utf-8", errors="replace")
                parsed = parse_qs(body, keep_blank_values=True)
                for name, values in parsed.items():
                    for val in values:
                        params.append((req_id, "body", name, val))
            except Exception:
                pass

        # JSON body params (top-level keys)
        if "application/json" in ct:
            try:
                body = json.loads(req.get_content(strict=False))
                if isinstance(body, dict):
                    for name, val in body.items():
                        params.append((req_id, "body", name, json.dumps(val) if not isinstance(val, str) else val))
            except Exception:
                pass

        # Cookie params
        cookies = req.headers.get("cookie", "")
        if cookies:
            for part in cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    name, val = part.split("=", 1)
                    params.append((req_id, "cookie", name.strip(), val.strip()))

        if params:
            db.executemany(
                "INSERT INTO params (request_id, location, name, value) VALUES (?, ?, ?, ?)",
                params,
            )


addons = [WebProbeAddon()]
