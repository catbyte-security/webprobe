"""Deep JavaScript bundle analysis - extract routes, secrets, APIs, GraphQL ops."""

import re
from typing import Optional
from .store import Store


# ── API Endpoint Patterns ──────────────────────────────────────

API_ROUTE_PATTERNS = [
    re.compile(r"""["'](/api/[^"'\s\\]{2,})["']"""),
    re.compile(r"""["'](/v[0-9]+/[^"'\s\\]{2,})["']"""),
    re.compile(r"""["'](/graphql[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/auth/[^"'\s\\]{2,})["']"""),
    re.compile(r"""["'](/user[s]?/[^"'\s\\]{2,})["']"""),
    re.compile(r"""["'](/admin[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/internal[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/webhook[s]?[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/oauth[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/token[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/upload[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/download[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/export[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/import[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/search[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/account[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/settings[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/profile[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/billing[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/payment[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/order[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/notification[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/message[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/report[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/dashboard[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/config[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/debug[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/status[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/health[^"'\s\\]*)["']"""),
    re.compile(r"""["'](/metrics[^"'\s\\]*)["']"""),
]

# Fetch/XHR call patterns
FETCH_PATTERNS = [
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'`](/[^"'`\s]{2,})["'`]""", re.I),
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'`](https?://[^"'`\s]{5,})["'`]""", re.I),
    re.compile(r"""(?:url|endpoint|apiUrl|baseUrl|apiBase)\s*[:=+]\s*["'`](/[^"'`\s]{2,})["'`]""", re.I),
    re.compile(r"""(?:url|endpoint|apiUrl|baseUrl|apiBase)\s*[:=+]\s*["'`](https?://[^"'`\s]{5,})["'`]""", re.I),
    re.compile(r"""\.(?:open|send)\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'`]([^"'`\s]+)["'`]""", re.I),
]

# ── Angular / React / Vue Route Patterns ──────────────────────

FRAMEWORK_ROUTE_PATTERNS = [
    # Angular
    re.compile(r"""path:\s*["']([^"']{1,100})["']"""),
    re.compile(r"""redirectTo:\s*["']([^"']{1,100})["']"""),
    re.compile(r"""loadChildren:\s*\(\)\s*=>\s*\w+\(\s*["']([^"']+)["']"""),
    re.compile(r"""component:\s*(\w+Component)"""),
    # React Router
    re.compile(r"""<Route\s+path=["']([^"']+)["']"""),
    re.compile(r"""path:\s*["']([^"']{1,80})["']"""),
    # Vue Router
    re.compile(r"""path:\s*['"]([^'"]{1,80})['"]"""),
]

# ── Secret / Token Patterns ───────────────────────────────────

SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|apikey|api_secret|apiSecret)\s*[:=]\s*["']([^"']{10,})["']""", re.I), "API Key"),
    (re.compile(r"""(?:secret[_-]?key|secretKey|client[_-]?secret|clientSecret)\s*[:=]\s*["']([^"']{10,})["']""", re.I), "Secret Key"),
    (re.compile(r"""(?:access[_-]?token|accessToken)\s*[:=]\s*["']([^"']{10,})["']""", re.I), "Access Token"),
    (re.compile(r"""(?:private[_-]?key|privateKey)\s*[:=]\s*["']([^"']{10,})["']""", re.I), "Private Key"),
    (re.compile(r"""(?:password|passwd)\s*[:=]\s*["']([^"']{6,})["']""", re.I), "Password"),
    (re.compile(r"""(?:AKIA|ASIA)[A-Z0-9]{16}"""), "AWS Access Key ID"),
    (re.compile(r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"""), "GitHub Token"),
    (re.compile(r"""sk_(?:live|test)_[A-Za-z0-9]{20,}"""), "Stripe Secret Key"),
    (re.compile(r"""pk_(?:live|test)_[A-Za-z0-9]{20,}"""), "Stripe Publishable Key"),
    (re.compile(r"""xox[bpors]-[A-Za-z0-9\-]{10,}"""), "Slack Token"),
    (re.compile(r"""ya29\.[A-Za-z0-9_-]{20,}"""), "Google OAuth Token"),
    (re.compile(r"""eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+"""), "JWT Token"),
    (re.compile(r"""(?:firebase|supabase|sentry)[A-Za-z]*[:=]\s*["']([^"']{10,})["']""", re.I), "Service Config"),
    (re.compile(r"""(?:mapbox|stripe|twilio|sendgrid|mailgun|algolia|pusher)[A-Za-z_]*[:=]\s*["']([^"']{10,})["']""", re.I), "Third-party Key"),
    (re.compile(r"""(?:captchaKey|siteKey|recaptcha|hcaptcha)[A-Za-z_]*[:=]\s*["']([^"']{10,})["']""", re.I), "Captcha Key (public)"),
]

# ── GraphQL Patterns ──────────────────────────────────────────

GRAPHQL_PATTERNS = [
    re.compile(r"""(?:query|mutation|subscription)\s+(\w{2,50})[\s({]"""),
    re.compile(r'"(?:query|operationName)"\s*:\s*"([^"]+)"'),
    re.compile(r"""name:\s*["'](\w+)["'].*(?:query|mutation)"""),
    re.compile(r"""gql\s*`[^`]*(?:query|mutation|subscription)\s+(\w+)"""),
    re.compile(r"""__typename.*?["'](\w+)["']"""),
]

# ── Interesting String Patterns ───────────────────────────────

INTERESTING_PATTERNS = [
    (re.compile(r"""(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::(\d+))?"""), "localhost reference"),
    (re.compile(r"""(?:staging|stage|stg|dev|development|test|internal|debug|sandbox|preprod|uat)\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}""", re.I), "non-prod hostname"),
    (re.compile(r"""(?:mongodb|postgres|mysql|redis|amqp|kafka)://[^\s"']+""", re.I), "database connection string"),
    (re.compile(r"""wss?://[^\s"']+"""), "WebSocket URL"),
    (re.compile(r"""(?:s3|gs)://[^\s"']+"""), "cloud storage URI"),
    (re.compile(r"""(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"""), "internal IP"),
    (re.compile(r"""(?:TODO|FIXME|HACK|XXX|BUG|TEMP)[:.\s]([^\n]{5,80})"""), "developer comment"),
    (re.compile(r"""(?:Bearer|Basic)\s+[A-Za-z0-9_=-]{10,}"""), "auth header value"),
    (re.compile(r"""data:application/[^;]+;base64,[A-Za-z0-9+/]{50,}"""), "embedded base64 data"),
]

# ── URL / Domain Extraction ───────────────────────────────────

FULL_URL_PATTERN = re.compile(r"""["'](https?://[^\s"'<>]{5,})["']""")
# Require at least one alpha label and a valid TLD to filter SVG path noise
DOMAIN_PATTERN = re.compile(r"""(?:https?://)?([a-zA-Z][a-zA-Z0-9\-]{0,61}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,61})*\.(?:com|org|net|io|ai|dev|co|us|edu|gov|app|cloud|xyz|info|biz|me|tv|cc|uk|de|fr|jp|au|ca|nl|ru|br|in|kr|cn|es|it|se|no|fi|dk|pl|cz|ch|at|be|pt|ie|nz|za|mx|ar|cl|tw|sg|hk|ph|my|th|id|vn|ae|sa|il|tr|eg))""")
VALID_TLD = re.compile(r'\.[a-zA-Z]{2,}$')

# Skip noise
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                   ".woff", ".woff2", ".ttf", ".eot", ".map", ".css"}


def _is_noise(endpoint: str) -> bool:
    """Filter out obvious noise from extracted endpoints."""
    if len(endpoint) > 200:
        return True
    # Template expressions
    if "${" in endpoint or "{{" in endpoint:
        return True
    ext = "." + endpoint.rsplit(".", 1)[-1].lower() if "." in endpoint.split("/")[-1] else ""
    if ext in SKIP_EXTENSIONS:
        return True
    # Skip pure numeric/hash paths
    parts = endpoint.strip("/").split("/")
    if all(re.match(r'^[0-9a-f]{8,}$', p) for p in parts if p):
        return True
    return False


def _is_valid_route(route: str) -> bool:
    """Filter framework routes - skip template expressions and noise."""
    if not route or len(route) > 150:
        return False
    if "${" in route or "{{" in route or "this." in route:
        return False
    if route.startswith("_") or route.startswith("."):
        return False
    # Must have at least one alpha char
    if not re.search(r'[a-zA-Z]', route):
        return False
    return True


class JSAnalyzer:
    def __init__(self, store: Store):
        self.store = store

    def analyze_all(self) -> dict:
        """Run deep analysis on all captured JS files."""
        js_files = self.store.get_js_bodies()

        results = {
            "js_files_analyzed": len(js_files),
            "api_endpoints": [],
            "framework_routes": [],
            "graphql_operations": [],
            "secrets": [],
            "interesting_strings": [],
            "external_urls": [],
            "domains": [],
            "fetch_calls": [],
            "by_file": [],
        }

        all_endpoints: set[str] = set()
        all_routes: set[str] = set()
        all_gql: set[str] = set()
        all_secrets: list[dict] = []
        all_interesting: list[dict] = []
        all_urls: set[str] = set()
        all_domains: set[str] = set()
        all_fetches: set[str] = set()

        for js in js_files:
            body = js["body"]
            url = js["url"]
            file_result = {"file": url, "size": js["length"]}

            # API endpoints
            file_endpoints = set()
            for p in API_ROUTE_PATTERNS:
                for m in p.findall(body):
                    if not _is_noise(m):
                        file_endpoints.add(m)
                        all_endpoints.add(m)

            # Fetch/XHR calls
            file_fetches = set()
            for p in FETCH_PATTERNS:
                for m in p.findall(body):
                    if not _is_noise(m):
                        file_fetches.add(m)
                        all_fetches.add(m)

            # Framework routes
            file_routes = set()
            for p in FRAMEWORK_ROUTE_PATTERNS:
                for m in p.findall(body):
                    if _is_valid_route(m):
                        file_routes.add(m)
                        all_routes.add(m)

            # GraphQL
            file_gql = set()
            for p in GRAPHQL_PATTERNS:
                for m in p.findall(body):
                    if 2 < len(m) < 100 and not m[0].islower():
                        # Skip common JS keywords
                        if m not in ("function", "return", "export", "import", "default", "Object", "Array", "String", "Number", "Boolean"):
                            file_gql.add(m)
                            all_gql.add(m)

            # Secrets
            file_secrets = []
            for p, label in SECRET_PATTERNS:
                for m in p.findall(body):
                    if isinstance(m, str) and 8 < len(m) < 200:
                        entry = {"type": label, "value": m[:120], "file": url}
                        file_secrets.append(entry)
                        all_secrets.append(entry)

            # Interesting strings
            file_interesting = []
            for p, label in INTERESTING_PATTERNS:
                for m in p.findall(body):
                    val = m if isinstance(m, str) else m
                    if val and len(val) > 2:
                        entry = {"type": label, "value": val[:200], "file": url}
                        file_interesting.append(entry)
                        all_interesting.append(entry)

            # Full URLs
            for m in FULL_URL_PATTERN.findall(body):
                if not _is_noise(m):
                    all_urls.add(m)

            # Domains
            for m in DOMAIN_PATTERN.findall(body):
                m = m.lower().rstrip(".")
                if "." in m and len(m) > 4:
                    all_domains.add(m)

            file_result["endpoints"] = sorted(file_endpoints)
            file_result["fetch_calls"] = sorted(file_fetches)
            file_result["routes"] = sorted(file_routes)
            file_result["graphql_ops"] = sorted(file_gql)
            file_result["secrets"] = file_secrets
            file_result["interesting"] = file_interesting

            if any([file_endpoints, file_fetches, file_routes, file_gql, file_secrets, file_interesting]):
                results["by_file"].append(file_result)

        results["api_endpoints"] = sorted(all_endpoints)
        results["fetch_calls"] = sorted(all_fetches)
        results["framework_routes"] = sorted(all_routes)
        results["graphql_operations"] = sorted(all_gql)
        results["secrets"] = _dedup_secrets(all_secrets)
        results["interesting_strings"] = _dedup_interesting(all_interesting)
        results["external_urls"] = sorted(all_urls)
        results["domains"] = sorted(all_domains)

        return results


def _dedup_secrets(secrets: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for s in secrets:
        key = (s["type"], s["value"])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _dedup_interesting(items: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for i in items:
        key = (i["type"], i["value"])
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out
