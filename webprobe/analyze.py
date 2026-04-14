"""Passive analysis engine - scans captured traffic for security issues."""

import json
import re
from typing import Optional
from urllib.parse import urlparse

from .store import Store

# ── Security Header Checks ─────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "medium",
        "title": "Missing Strict-Transport-Security (HSTS)",
        "detail": "HSTS not set. Browser may allow HTTP downgrade attacks.",
    },
    "content-security-policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy",
        "detail": "No CSP header. XSS attacks have no browser-level mitigation.",
    },
    "x-content-type-options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "detail": "Browser may MIME-sniff responses, enabling content-type confusion attacks.",
    },
    "x-frame-options": {
        "severity": "low",
        "title": "Missing X-Frame-Options",
        "detail": "Page may be framed. Clickjacking possible unless CSP frame-ancestors is set.",
    },
    "permissions-policy": {
        "severity": "info",
        "title": "Missing Permissions-Policy",
        "detail": "No restrictions on browser features (camera, geolocation, etc.).",
    },
    "referrer-policy": {
        "severity": "info",
        "title": "Missing Referrer-Policy",
        "detail": "Browser default referrer behavior may leak sensitive URL paths.",
    },
}

WEAK_CSP_PATTERNS = [
    (r"unsafe-inline", "CSP allows unsafe-inline scripts"),
    (r"unsafe-eval", "CSP allows unsafe-eval"),
    (r"\*", "CSP has wildcard source"),
    (r"data:", "CSP allows data: URIs"),
    (r"blob:", "CSP allows blob: URIs"),
]

# ── Technology Fingerprints ────────────────────────────────────

TECH_HEADERS = {
    "x-powered-by": "technology",
    "server": "server",
    "x-aspnet-version": "technology",
    "x-aspnetmvc-version": "technology",
    "x-drupal-cache": "technology",
    "x-generator": "technology",
    "x-shopify-stage": "technology",
    "x-amz-cf-id": "infrastructure",
    "x-amz-request-id": "infrastructure",
    "x-vercel-id": "infrastructure",
    "cf-ray": "infrastructure",
    "x-cache": "infrastructure",
    "fly-request-id": "infrastructure",
}

COOKIE_TECH = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "CFID": "ColdFusion",
    "CFTOKEN": "ColdFusion",
    "ci_session": "CodeIgniter",
    "laravel_session": "Laravel",
    "rack.session": "Ruby/Rack",
    "_rails": "Ruby on Rails",
    "connect.sid": "Node.js/Express",
    "next-auth": "Next.js",
    "wp-settings": "WordPress",
    "_csrf": "CSRF token framework",
    "__stripe": "Stripe",
}

# ── Information Disclosure Patterns ────────────────────────────

INFO_DISCLOSURE = [
    (re.compile(r"(?:stack ?trace|traceback|exception|error.*at\s+\w+\.\w+)", re.I),
     "Stack trace / error details in response"),
    (re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"),
     "Internal IP address disclosed"),
    (re.compile(r"(?:mysql|postgres|oracle|sqlite|mongodb|redis).*(?:error|exception|warning)", re.I),
     "Database error message exposed"),
    (re.compile(r"(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?\w+", re.I),
     "Potential credential/secret in response"),
    (re.compile(r"<title>(?:Index of|Directory listing)", re.I),
     "Directory listing enabled"),
    (re.compile(r"(?:phpinfo|php_uname|SERVER_SOFTWARE)", re.I),
     "PHP info/debug page"),
    (re.compile(r"(?:DEBUG\s*=\s*True|DJANGO_SETTINGS|settings\.py)", re.I),
     "Debug mode / framework config exposed"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
     "Private key exposed in response"),
    (re.compile(r"(?:AWS_ACCESS_KEY|AKIA[0-9A-Z]{16})"),
     "AWS credentials potentially exposed"),
]

# Internal hostname patterns (check headers + body)
INTERNAL_HOSTNAME_PATTERN = re.compile(
    r"[a-zA-Z0-9\-]+\.(?:corp|local|internal|intranet|private|staging\.corp|dev\.corp)[a-zA-Z0-9./\-]*",
    re.I,
)

# Cloud metadata extraction patterns
CLOUD_METADATA_PATTERNS = [
    # Azure tenant ID from WWW-Authenticate or error responses
    (re.compile(r"login\.microsoftonline\.(?:com|us)/([0-9a-f\-]{36})", re.I),
     "Azure AD Tenant ID", "high"),
    # Azure resource ID
    (re.compile(r"resource_id=(https://[^\s&\"']+)", re.I),
     "Azure Resource ID", "low"),
    # AWS account ID from ARNs
    (re.compile(r"arn:aws[a-z\-]*:\w+:[a-z0-9\-]*:(\d{12}):", re.I),
     "AWS Account ID", "medium"),
    # GCP project ID
    (re.compile(r"projects/([a-z][a-z0-9\-]{4,28}[a-z0-9])/", re.I),
     "GCP Project ID", "medium"),
    # Azure storage account name
    (re.compile(r"([a-z0-9]{3,24})\.blob\.core\.(?:windows\.net|usgovcloudapi\.net)", re.I),
     "Azure Storage Account", "low"),
    # Azure subscription ID
    (re.compile(r"subscriptions/([0-9a-f\-]{36})", re.I),
     "Azure Subscription ID", "high"),
]

# ── CORS Patterns ──────────────────────────────────────────────

INTERESTING_PATHS = re.compile(
    r"(?:admin|debug|internal|staging|test|backup|old|dev|swagger|graphql|"
    r"api-?docs|phpinfo|\.env|\.git|\.svn|config|setup|install|wp-admin|"
    r"actuator|metrics|health|status|trace|dump|console|shell|exec|eval)",
    re.I,
)


class Analyzer:
    def __init__(self, store: Store):
        self.store = store
        self._spa_paths: set[str] = set()

    def _build_spa_path_set(self):
        """Pre-compute SPA catch-all paths from fingerprint data."""
        fingerprints = self.store.get_response_fingerprints()
        for g in fingerprints:
            if g["is_spa_catchall"]:
                for r in g["requests"]:
                    self._spa_paths.add(r["path"])

    def analyze_all(self, clear_previous: bool = True) -> dict:
        """Run all passive analysis checks on captured traffic."""
        if clear_previous:
            self.store.clear_findings()

        # Build SPA path set to suppress false positives
        self._build_spa_path_set()

        requests = self.store.query_requests(limit=10000)
        summary = {
            "total_requests_analyzed": len(requests),
            "findings": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "categories": {},
        }

        seen_findings: set[str] = set()

        for req in requests:
            findings = []
            findings.extend(self._check_security_headers(req))
            findings.extend(self._check_cookies(req))
            findings.extend(self._check_cors(req))
            findings.extend(self._check_info_disclosure(req))
            findings.extend(self._check_tech_fingerprint(req))
            findings.extend(self._check_interesting_patterns(req))
            findings.extend(self._check_redirects(req))
            findings.extend(self._check_internal_hostnames(req))

            for f in findings:
                # Dedup by title+host
                key = f"{f['title']}:{req.get('host', '')}"
                if key in seen_findings:
                    continue
                seen_findings.add(key)

                self.store.insert_finding(
                    request_id=req["id"],
                    category=f["category"],
                    severity=f["severity"],
                    title=f["title"],
                    detail=f["detail"],
                    evidence=f.get("evidence", ""),
                )
                summary["findings"][f["severity"]] += 1
                summary["categories"][f["category"]] = summary["categories"].get(f["category"], 0) + 1

        return summary

    def analyze_request(self, req_id: int) -> list[dict]:
        """Analyze a single request."""
        req = self.store.get_request(req_id)
        if not req:
            return []
        findings = []
        findings.extend(self._check_security_headers(req))
        findings.extend(self._check_cookies(req))
        findings.extend(self._check_cors(req))
        findings.extend(self._check_info_disclosure(req))
        findings.extend(self._check_tech_fingerprint(req))
        findings.extend(self._check_interesting_patterns(req))
        findings.extend(self._check_redirects(req))
        return findings

    def _get_resp_headers(self, req: dict) -> dict:
        try:
            return {k.lower(): v for k, v in json.loads(req.get("response_headers") or "{}").items()}
        except (json.JSONDecodeError, AttributeError):
            return {}

    def _get_req_headers(self, req: dict) -> dict:
        try:
            return {k.lower(): v for k, v in json.loads(req.get("request_headers") or "{}").items()}
        except (json.JSONDecodeError, AttributeError):
            return {}

    def _get_body_text(self, req: dict, field: str = "response_body") -> str:
        body = req.get(field)
        if not body:
            return ""
        if isinstance(body, bytes):
            try:
                return body.decode("utf-8", errors="replace")[:100000]
            except Exception:
                return ""
        return str(body)[:100000]

    # ── Check: Security Headers ─────────────────────────────

    def _check_security_headers(self, req: dict) -> list[dict]:
        findings = []
        ct = req.get("response_content_type", "")
        if "text/html" not in ct:
            return findings

        status = req.get("response_status") or 0
        if status < 200 or status >= 400:
            return findings

        headers = self._get_resp_headers(req)

        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in headers:
                findings.append({
                    "category": "security_header",
                    "severity": info["severity"],
                    "title": info["title"],
                    "detail": info["detail"],
                    "evidence": f"URL: {req.get('url', '')}",
                })

        # Check for weak CSP
        csp = headers.get("content-security-policy", "")
        if csp:
            for pattern, desc in WEAK_CSP_PATTERNS:
                if re.search(pattern, csp):
                    findings.append({
                        "category": "security_header",
                        "severity": "medium",
                        "title": f"Weak CSP: {desc}",
                        "detail": f"Content-Security-Policy contains weak directive.",
                        "evidence": f"CSP: {csp[:200]}",
                    })

        return findings

    # ── Check: Cookies ──────────────────────────────────────

    def _check_cookies(self, req: dict) -> list[dict]:
        findings = []
        headers = self._get_resp_headers(req)
        scheme = req.get("scheme", "")

        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return findings

        cookies = [set_cookie] if isinstance(set_cookie, str) else set_cookie
        for cookie in cookies:
            parts = cookie.split(";")
            name_val = parts[0].strip()
            name = name_val.split("=")[0].strip() if "=" in name_val else name_val
            flags = cookie.lower()

            if "httponly" not in flags:
                findings.append({
                    "category": "cookie",
                    "severity": "low",
                    "title": f"Cookie '{name}' missing HttpOnly flag",
                    "detail": "Cookie accessible via JavaScript. XSS can steal it.",
                    "evidence": cookie[:200],
                })

            if scheme == "https" and "secure" not in flags:
                findings.append({
                    "category": "cookie",
                    "severity": "medium",
                    "title": f"Cookie '{name}' missing Secure flag on HTTPS",
                    "detail": "Cookie may be sent over unencrypted HTTP connections.",
                    "evidence": cookie[:200],
                })

            if "samesite" not in flags:
                findings.append({
                    "category": "cookie",
                    "severity": "low",
                    "title": f"Cookie '{name}' missing SameSite attribute",
                    "detail": "Cookie sent on cross-site requests. CSRF possible.",
                    "evidence": cookie[:200],
                })

        return findings

    # ── Check: CORS ─────────────────────────────────────────

    def _check_cors(self, req: dict) -> list[dict]:
        findings = []
        headers = self._get_resp_headers(req)

        acao = headers.get("access-control-allow-origin", "")
        if not acao:
            return findings

        if acao == "*":
            acac = headers.get("access-control-allow-credentials", "")
            if acac.lower() == "true":
                findings.append({
                    "category": "cors",
                    "severity": "high",
                    "title": "CORS wildcard with credentials",
                    "detail": "Access-Control-Allow-Origin: * with Allow-Credentials: true. Any origin can read authenticated responses.",
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                })
            else:
                findings.append({
                    "category": "cors",
                    "severity": "low",
                    "title": "CORS wildcard origin",
                    "detail": "Access-Control-Allow-Origin: * allows any origin to read responses (without credentials).",
                    "evidence": f"ACAO: {acao}",
                })

        elif acao == "null":
            findings.append({
                "category": "cors",
                "severity": "medium",
                "title": "CORS allows null origin",
                "detail": "null origin accepted. Sandboxed iframes and data: URIs can exploit this.",
                "evidence": f"ACAO: {acao}",
            })

        # Check if origin is reflected
        req_headers = self._get_req_headers(req)
        origin = req_headers.get("origin", "")
        if origin and acao == origin and origin not in ("null", "*"):
            findings.append({
                "category": "cors",
                "severity": "medium",
                "title": "CORS origin reflection detected",
                "detail": "Server reflects the Origin header. May accept any origin. Needs verification with arbitrary origin.",
                "evidence": f"Origin sent: {origin}, ACAO: {acao}",
            })

        return findings

    # ── Check: Information Disclosure ───────────────────────

    def _check_info_disclosure(self, req: dict) -> list[dict]:
        findings = []
        body = self._get_body_text(req)
        if not body:
            return findings

        status = req.get("response_status") or 0

        for pattern, desc in INFO_DISCLOSURE:
            match = pattern.search(body)
            if match:
                evidence = body[max(0, match.start() - 50):match.end() + 50].strip()
                severity = "medium" if "credential" in desc.lower() or "private key" in desc.lower() else "low"
                findings.append({
                    "category": "info_disclosure",
                    "severity": severity,
                    "title": desc,
                    "detail": f"Found in response body at {req.get('url', '')}",
                    "evidence": evidence[:300],
                })

        # Check for verbose error pages
        if status >= 500:
            if len(body) > 500:
                findings.append({
                    "category": "info_disclosure",
                    "severity": "low",
                    "title": f"Verbose {status} error page",
                    "detail": f"Server error with {len(body)} byte response body. May contain debug info.",
                    "evidence": body[:300],
                })

        return findings

    # ── Check: Technology Fingerprint ───────────────────────

    def _check_tech_fingerprint(self, req: dict) -> list[dict]:
        findings = []
        headers = self._get_resp_headers(req)

        for header, category in TECH_HEADERS.items():
            val = headers.get(header, "")
            if val:
                findings.append({
                    "category": "technology",
                    "severity": "info",
                    "title": f"Technology detected: {header}: {val}",
                    "detail": f"Response header reveals {category} information.",
                    "evidence": f"{header}: {val}",
                })

        # Cookie-based tech detection
        req_headers = self._get_req_headers(req)
        cookies = req_headers.get("cookie", "")
        for cookie_name, tech in COOKIE_TECH.items():
            if cookie_name.lower() in cookies.lower():
                findings.append({
                    "category": "technology",
                    "severity": "info",
                    "title": f"Technology detected via cookie: {tech}",
                    "detail": f"Cookie '{cookie_name}' suggests {tech} backend.",
                    "evidence": f"Cookie contains: {cookie_name}",
                })

        return findings

    # ── Check: Interesting Patterns ─────────────────────────

    def _check_interesting_patterns(self, req: dict) -> list[dict]:
        findings = []
        path = req.get("path", "")
        status = req.get("response_status") or 0
        url = req.get("url", "")

        # Interesting paths - skip SPA catch-all paths (they return 200 for everything)
        if INTERESTING_PATHS.search(path):
            if 200 <= status < 400 and path not in self._spa_paths:
                findings.append({
                    "category": "interesting",
                    "severity": "medium" if any(x in path.lower() for x in (".env", ".git", "admin", "debug", "phpinfo", "config")) else "info",
                    "title": f"Interesting endpoint accessible: {path}",
                    "detail": f"Responded with {status}. Worth manual investigation.",
                    "evidence": url,
                })

        # JSON API responses
        ct = req.get("response_content_type", "")
        if "application/json" in ct:
            body = self._get_body_text(req)
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    keys = set(data.keys())
                    sensitive_keys = keys & {"password", "secret", "token", "api_key", "apikey",
                                             "private_key", "access_token", "refresh_token", "ssn",
                                             "credit_card", "email", "phone"}
                    if sensitive_keys:
                        findings.append({
                            "category": "info_disclosure",
                            "severity": "high",
                            "title": f"Sensitive data in API response",
                            "detail": f"JSON response contains sensitive-looking keys: {', '.join(sensitive_keys)}",
                            "evidence": f"Keys found: {', '.join(sensitive_keys)} at {url}",
                        })
            except (json.JSONDecodeError, ValueError):
                pass

        # JSONP endpoints
        if "callback=" in (req.get("query") or ""):
            findings.append({
                "category": "interesting",
                "severity": "low",
                "title": "JSONP endpoint detected",
                "detail": "JSONP callback parameter found. Test for information leakage.",
                "evidence": url,
            })

        # File upload forms (check for multipart)
        req_ct = req.get("request_content_type", "")
        if "multipart/form-data" in req_ct:
            findings.append({
                "category": "interesting",
                "severity": "info",
                "title": "File upload endpoint",
                "detail": "Multipart form data detected. Test for unrestricted file upload.",
                "evidence": f"{req.get('method')} {url}",
            })

        return findings

    # ── Check: Redirects ────────────────────────────────────

    def _check_redirects(self, req: dict) -> list[dict]:
        findings = []
        status = req.get("response_status") or 0

        if status in (301, 302, 303, 307, 308):
            headers = self._get_resp_headers(req)
            location = headers.get("location", "")
            query = req.get("query", "") or ""

            # Check for open redirect indicators
            for param_val in query.split("&"):
                if "=" in param_val:
                    _, val = param_val.split("=", 1)
                    if val and (val in location or val.replace("%2F", "/") in location):
                        findings.append({
                            "category": "interesting",
                            "severity": "medium",
                            "title": "Potential open redirect",
                            "detail": f"Query parameter value appears in redirect Location header.",
                            "evidence": f"Param value: {val[:100]}, Location: {location[:200]}",
                        })
                        break

            # Redirect to different scheme (https -> http)
            if req.get("scheme") == "https" and location.startswith("http://"):
                findings.append({
                    "category": "security_header",
                    "severity": "medium",
                    "title": "HTTPS to HTTP redirect",
                    "detail": "Redirect downgrades from HTTPS to HTTP.",
                    "evidence": f"Location: {location[:200]}",
                })

        return findings

    # ── Check: Internal Hostnames ───────────────────────────

    def _check_internal_hostnames(self, req: dict) -> list[dict]:
        findings = []
        seen = set()

        # Check headers (especially CSP, Location, etc.)
        headers = self._get_resp_headers(req)
        for hname, hval in headers.items():
            for match in INTERNAL_HOSTNAME_PATTERN.findall(hval):
                if match not in seen:
                    seen.add(match)
                    findings.append({
                        "category": "info_disclosure",
                        "severity": "high",
                        "title": f"Internal hostname leaked: {match}",
                        "detail": f"Internal/corp hostname found in response header '{hname}'. Reveals internal infrastructure naming.",
                        "evidence": f"Header: {hname}: ...{match}... at {req.get('url', '')}",
                    })

        # Check body
        body = self._get_body_text(req)
        if body:
            for match in INTERNAL_HOSTNAME_PATTERN.findall(body):
                if match not in seen:
                    seen.add(match)
                    findings.append({
                        "category": "info_disclosure",
                        "severity": "high",
                        "title": f"Internal hostname leaked: {match}",
                        "detail": f"Internal/corp hostname found in response body. Reveals internal infrastructure.",
                        "evidence": f"Found in body at {req.get('url', '')}",
                    })

        # Cloud metadata extraction (from headers + body)
        all_text = " ".join(f"{k}: {v}" for k, v in headers.items())
        if body:
            all_text += " " + body[:50000]
        for pattern, label, severity in CLOUD_METADATA_PATTERNS:
            for match in pattern.findall(all_text):
                key = f"{label}:{match}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "category": "cloud_metadata",
                        "severity": severity,
                        "title": f"{label}: {match}",
                        "detail": f"Cloud infrastructure identifier extracted from response at {req.get('url', '')}",
                        "evidence": match,
                    })

        return findings

    def generate_report(self, include_requests: bool = False) -> dict:
        """Generate a comprehensive JSON report for AI analysis."""
        from .js_analyze import JSAnalyzer as JSA

        stats = self.store.get_stats()
        findings = self.store.get_findings(limit=1000)
        endpoints = self.store.get_endpoints()
        params = self.store.get_unique_params()
        scope = self.store.get_scope()

        # Group findings by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity.setdefault(sev, []).append({
                "title": f["title"],
                "category": f["category"],
                "detail": f["detail"],
                "evidence": f["evidence"],
                "request_id": f["request_id"],
            })

        # SPA detection via response fingerprinting
        fingerprints = self.store.get_response_fingerprints()
        spa_groups = [g for g in fingerprints if g["is_spa_catchall"]]
        real_endpoints = endpoints
        spa_paths: set[str] = set()
        if spa_groups:
            for g in spa_groups:
                for r in g["requests"]:
                    spa_paths.add(r["path"])
            real_endpoints = [e for e in endpoints if e["path"] not in spa_paths]

        # 403/404 anomaly detection
        status_anomalies = self.store.get_status_anomalies()

        # Subdomain extraction
        subdomains = self.store.extract_subdomains()

        # Deep JS analysis
        js_results = JSA(self.store).analyze_all()

        report = {
            "summary": {
                "total_requests": stats["total_requests"],
                "unique_hosts": stats["unique_hosts"],
                "unique_endpoints": stats["unique_endpoints"],
                "total_findings": stats["total_findings"],
                "critical": stats["findings_by_severity"].get("critical", 0),
                "high": stats["findings_by_severity"].get("high", 0),
                "medium": stats["findings_by_severity"].get("medium", 0),
                "low": stats["findings_by_severity"].get("low", 0),
                "info": stats["findings_by_severity"].get("info", 0),
                "spa_detected": len(spa_groups) > 0,
                "protected_paths_403": len(status_anomalies),
                "subdomains_found": len(subdomains),
                "js_files_analyzed": js_results["js_files_analyzed"],
            },
            "scope": scope,
            "hosts": self.store.get_unique_hosts(),
            "subdomains": subdomains,
            "findings": by_severity,
            "real_endpoints": real_endpoints[:200],
            "all_endpoints": endpoints[:200],
            "parameters": params[:200],
            "technologies": [
                f for f in findings if f.get("category") == "technology"
            ],

            # SPA analysis
            "spa_detection": {
                "is_spa": len(spa_groups) > 0,
                "catchall_groups": [{
                    "body_hash": g["body_hash"],
                    "paths_count": g["count"],
                    "sample_paths": g["sample_paths"],
                    "response_length": g["response_length"],
                } for g in spa_groups],
                "spa_shell_paths": sorted(spa_paths),
                "real_endpoint_count": len(real_endpoints),
            },

            # Protected paths (403 vs 404 anomaly)
            "protected_paths": status_anomalies,

            # Response fingerprinting
            "response_fingerprints": [{
                "hash": g["body_hash"],
                "count": g["count"],
                "is_spa": g["is_spa_catchall"],
                "sample_paths": g["sample_paths"][:5],
                "length": g["response_length"],
                "statuses": g["status_codes"],
            } for g in fingerprints[:20]],

            # Deep JS analysis
            "js_analysis": {
                "api_endpoints": js_results["api_endpoints"],
                "fetch_calls": js_results["fetch_calls"],
                "framework_routes": js_results["framework_routes"],
                "graphql_operations": js_results["graphql_operations"],
                "secrets": js_results["secrets"],
                "interesting_strings": js_results["interesting_strings"],
                "external_domains": js_results["domains"],
            },

            "attack_surface": {
                "forms": [
                    f for f in findings if "upload" in (f.get("title") or "").lower()
                ],
                "api_endpoints": [
                    e for e in real_endpoints
                    if any(p in (e.get("path") or "").lower() for p in ("/api", "/graphql", "/v1", "/v2", "/rest"))
                ],
                "auth_endpoints": [
                    e for e in real_endpoints
                    if any(p in (e.get("path") or "").lower() for p in ("login", "auth", "register", "signup", "password", "token", "oauth", "session"))
                ],
                "interesting_params": [
                    p for p in params
                    if any(k in p.get("name", "").lower() for k in ("id", "user", "admin", "token", "key", "file", "path", "url", "redirect", "callback", "cmd", "exec", "query", "search"))
                ],
                "protected_paths": status_anomalies,
                "js_discovered_endpoints": js_results["api_endpoints"][:50],
                "js_discovered_routes": js_results["framework_routes"][:50],
            },
            "status_distribution": stats["status_codes"],
            "content_types": stats["content_types"],
        }

        if include_requests:
            all_reqs = self.store.query_requests(limit=1000)
            report["requests"] = [self.store.request_to_dict(r) for r in all_reqs]

        return report
