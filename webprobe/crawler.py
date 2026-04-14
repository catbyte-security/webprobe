"""Async web crawler for endpoint discovery."""

import asyncio
import hashlib
import json
import re
import time
from collections import deque
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import httpx
from bs4 import BeautifulSoup

from .store import Store

# Regex patterns for extracting endpoints from JavaScript
JS_ENDPOINT_PATTERNS = [
    re.compile(r"""["'](\/(?:api|v[0-9]|graphql|rest|auth|admin|internal)\/[^"'\s<>]{2,})["']""", re.I),
    re.compile(r"""["'](\/[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,5})["']"""),  # /path/file.ext
    re.compile(r"""(?:fetch|axios|xhr|ajax|get|post|put|delete|patch)\s*\(\s*["'`](\/[^"'`\s]{2,})["'`]""", re.I),
    re.compile(r"""(?:url|endpoint|path|href|action|src)\s*[:=]\s*["'`](\/[^"'`\s]{2,})["'`]""", re.I),
    re.compile(r"""["'](https?://[^"'\s<>]{5,})["']"""),  # Full URLs
]

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".zip", ".tar", ".gz", ".rar",
    ".pdf", ".doc", ".docx",
}

# Common paths to probe
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json", "/v2/api-docs",
    "/.env", "/config.json", "/package.json",
    "/wp-json/wp/v2/users", "/wp-login.php",
    "/admin", "/login", "/register", "/dashboard",
    "/debug", "/status", "/health", "/info",
    "/server-status", "/server-info",
    "/.git/HEAD", "/.svn/entries",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]


class Crawler:
    def __init__(
        self,
        store: Store,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 15,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        headers: dict = None,
        cookies: dict = None,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        probe_common: bool = True,
        extract_js: bool = True,
        on_request: Callable = None,
    ):
        self.store = store
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra_headers = headers or {}
        self.cookies = cookies or {}
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.probe_common = probe_common
        self.extract_js = extract_js
        self.on_request = on_request

        self.visited: set[str] = set()
        self.queued: set[str] = set()
        self.js_endpoints: set[str] = set()
        self.forms: list[dict] = []
        self.stats = {"pages": 0, "js_files": 0, "forms": 0, "endpoints": 0, "errors": 0}

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for dedup."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _should_crawl(self, url: str, base_host: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not self.store.is_in_scope(parsed.hostname or ""):
            if parsed.hostname != base_host:
                return False
        ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path.split("/")[-1] else ""
        if ext in SKIP_EXTENSIONS:
            return False
        norm = self._normalize_url(url)
        if norm in self.visited or norm in self.queued:
            return False
        return True

    def _resolve_base_href(self, soup, page_url: str) -> str:
        """Resolve <base href> tag to get the correct base URL for relative paths."""
        base_tag = soup.find("base", href=True)
        if base_tag:
            base_href = base_tag["href"]
            # Resolve relative base href against page URL
            return urljoin(page_url, base_href)
        return page_url

    def _is_spa_shell(self, content_type: str, body: str, url: str) -> bool:
        """Detect if response is an SPA HTML shell instead of the actual resource."""
        if "javascript" in (content_type or ""):
            return False
        if "text/html" in (content_type or ""):
            # If we requested a .js/.css file but got HTML back, it's a catch-all
            if any(url.endswith(ext) for ext in (".js", ".css", ".json", ".map")):
                return True
        return False

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML, respecting <base href> for SPA apps."""
        urls = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        # Resolve <base href> - critical for SPA apps like Angular
        effective_base = self._resolve_base_href(soup, base_url)

        # <a href>, <area href>
        for tag in soup.find_all(["a", "area"], href=True):
            urls.append(urljoin(effective_base, tag["href"]))

        # <form action>
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            resolved = urljoin(effective_base, action) if action else effective_base
            urls.append(resolved)

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            self.forms.append({
                "action": resolved,
                "method": method,
                "inputs": inputs,
            })
            self.stats["forms"] += 1

        # <script src> - resolve against <base href>, not page URL
        for tag in soup.find_all("script", src=True):
            urls.append(urljoin(effective_base, tag["src"]))
        for tag in soup.find_all("link", href=True):
            urls.append(urljoin(effective_base, tag["href"]))
        for tag in soup.find_all("iframe", src=True):
            urls.append(urljoin(effective_base, tag["src"]))

        # Meta refresh
        for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            content = meta.get("content", "")
            if "url=" in content.lower():
                redir_url = content.split("url=", 1)[-1].strip().strip("'\"")
                urls.append(urljoin(effective_base, redir_url))

        return urls

    def _extract_js_endpoints(self, js_content: str, base_url: str) -> list[str]:
        """Extract API endpoints from JavaScript source."""
        endpoints = set()
        for pattern in JS_ENDPOINT_PATTERNS:
            for match in pattern.findall(js_content):
                endpoint = match.strip()
                if endpoint.startswith("/"):
                    endpoints.add(urljoin(base_url, endpoint))
                elif endpoint.startswith("http"):
                    endpoints.add(endpoint)
        return list(endpoints)

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
        try:
            resp = await client.get(
                url,
                follow_redirects=self.follow_redirects,
                timeout=self.timeout,
            )
            return resp
        except Exception:
            self.stats["errors"] += 1
            return None

    def _save_response(self, url: str, resp: httpx.Response, start_time: float):
        """Save a crawl response to the store."""
        parsed = urlparse(str(resp.url))
        duration = (time.time() - start_time) * 1000

        req_headers = dict(resp.request.headers)
        resp_headers = dict(resp.headers)

        body = resp.content
        if len(body) > 512 * 1024:
            body = body[:512 * 1024]

        req_id = self.store.insert_request(
            method="GET",
            url=str(resp.url),
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.path,
            query=parsed.query,
            request_headers=json.dumps(req_headers),
            request_body=b"",
            request_content_type="",
            response_status=resp.status_code,
            response_reason=resp.reason_phrase,
            response_headers=json.dumps(resp_headers),
            response_body=body,
            response_content_type=resp.headers.get("content-type", ""),
            response_length=len(resp.content),
            duration_ms=round(duration, 2),
            source="crawler",
        )

        # Extract params from query string
        if parsed.query:
            params = []
            for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
                for val in values:
                    params.append({"location": "query", "name": name, "value": val})
            if params:
                self.store.insert_params(req_id, params)

        self.stats["endpoints"] += 1
        return req_id

    async def _crawl_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        base_host: str,
        queue: asyncio.Queue,
    ):
        norm = self._normalize_url(url)
        if norm in self.visited:
            return
        self.visited.add(norm)

        if self.stats["pages"] >= self.max_pages:
            return

        start = time.time()
        resp = await self._fetch(client, url)
        if resp is None:
            return

        self.stats["pages"] += 1
        req_id = self._save_response(url, resp, start)

        if self.on_request:
            self.on_request(resp.request.method, str(resp.url), resp.status_code, len(resp.content))

        ct = resp.headers.get("content-type", "")

        # Detect SPA catch-all: we requested .js/.css but got HTML back
        if self._is_spa_shell(ct, resp.text[:500], url):
            # Don't parse this HTML as real content - it's a catch-all shell
            # The actual JS is probably at a different path (base href resolved)
            return

        # Parse HTML for links
        if "text/html" in ct and depth < self.max_depth:
            text = resp.text
            links = self._extract_links(text, str(resp.url))
            for link in links:
                if self._should_crawl(link, base_host):
                    self.queued.add(self._normalize_url(link))
                    await queue.put((link, depth + 1))

            # Also extract JS endpoints from inline scripts
            if self.extract_js:
                for ep in self._extract_js_endpoints(text, str(resp.url)):
                    self.js_endpoints.add(ep)

        # Parse JavaScript files for endpoints
        elif ("javascript" in ct or url.endswith(".js")) and self.extract_js:
            self.stats["js_files"] += 1
            for ep in self._extract_js_endpoints(resp.text, str(resp.url)):
                self.js_endpoints.add(ep)

    async def crawl(self, start_url: str) -> dict:
        """Main crawl entry point. Returns crawl summary."""
        parsed = urlparse(start_url)
        base_host = parsed.hostname

        # Add target to scope if scope is empty
        scope = self.store.get_scope()
        if not scope:
            self.store.add_scope(base_host, "include")

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            **self.extra_headers,
        }

        async with httpx.AsyncClient(
            headers=headers,
            cookies=self.cookies,
            verify=self.verify_ssl,
            limits=httpx.Limits(
                max_connections=self.concurrency,
                max_keepalive_connections=self.concurrency,
            ),
        ) as client:
            queue: asyncio.Queue = asyncio.Queue()
            await queue.put((start_url, 0))
            self.queued.add(self._normalize_url(start_url))

            # Probe common paths
            if self.probe_common:
                base = f"{parsed.scheme}://{parsed.netloc}"
                for path in COMMON_PATHS:
                    probe_url = base + path
                    if self._should_crawl(probe_url, base_host):
                        self.queued.add(self._normalize_url(probe_url))
                        await queue.put((probe_url, 1))

            sem = asyncio.Semaphore(self.concurrency)

            async def worker():
                while True:
                    try:
                        url, depth = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    async with sem:
                        await self._crawl_url(client, url, depth, base_host, queue)
                    queue.task_done()

            # Process queue in waves
            while not queue.empty() and self.stats["pages"] < self.max_pages:
                tasks = []
                batch_size = min(queue.qsize(), self.concurrency * 2)
                for _ in range(batch_size):
                    if not queue.empty():
                        tasks.append(asyncio.create_task(worker()))
                if tasks:
                    await asyncio.gather(*tasks)

            # Crawl discovered JS endpoints
            if self.js_endpoints:
                js_queue: asyncio.Queue = asyncio.Queue()
                for ep in self.js_endpoints:
                    if self._should_crawl(ep, base_host):
                        await js_queue.put((ep, self.max_depth))  # Don't recurse further

                async def js_worker():
                    while True:
                        try:
                            url, depth = js_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        async with sem:
                            norm = self._normalize_url(url)
                            if norm not in self.visited and self.stats["pages"] < self.max_pages:
                                self.visited.add(norm)
                                start = time.time()
                                resp = await self._fetch(client, url)
                                if resp:
                                    self.stats["pages"] += 1
                                    self._save_response(url, resp, start)
                                    if self.on_request:
                                        self.on_request("GET", str(resp.url), resp.status_code, len(resp.content))
                        js_queue.task_done()

                js_tasks = [asyncio.create_task(js_worker()) for _ in range(min(js_queue.qsize(), self.concurrency))]
                if js_tasks:
                    await asyncio.gather(*js_tasks)

        return {
            "target": start_url,
            "pages_crawled": self.stats["pages"],
            "js_files_parsed": self.stats["js_files"],
            "forms_found": self.stats["forms"],
            "unique_endpoints": self.stats["endpoints"],
            "js_endpoints_extracted": len(self.js_endpoints),
            "errors": self.stats["errors"],
            "forms": self.forms[:50],  # Cap at 50 for output
            "js_endpoints": sorted(self.js_endpoints)[:100],
        }


def run_crawl(store: Store, url: str, **kwargs) -> dict:
    """Synchronous wrapper for the crawler."""
    crawler = Crawler(store, **kwargs)
    return asyncio.run(crawler.crawl(url))
