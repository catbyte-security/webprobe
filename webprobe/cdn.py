"""CDN/WAF fingerprinting and behavior detection.

Detects CDN properties that affect attack strategy:
- Query string handling (stripped? cached? forwarded?)
- Method filtering (only GET allowed?)
- Path whitelisting
- Cache behavior
- WAF signatures
"""

import hashlib
import json
import random
import string
import time
from typing import Optional
from urllib.parse import urlparse, urlencode

import httpx

from .store import Store


# Known CDN/WAF signatures from response headers
CDN_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-cache": "CDN (generic)",
    "x-served-by": "Fastly",
    "x-fastly-request-id": "Fastly",
    "x-vercel-id": "Vercel",
    "x-vercel-cache": "Vercel",
    "x-azure-ref": "Azure Front Door",
    "x-fd-int-roxy-purgeid": "Azure Front Door",
    "x-cache-info": "Azure CDN",
    "fly-request-id": "Fly.io",
    "x-nf-request-id": "Netlify",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri WAF",
    "server": None,  # Checked separately
}

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-mitigated"],
    "aws_waf": ["x-amzn-waf-", "aws-waf-token"],
    "azure_frontdoor": ["x-azure-ref", "x-fd-int-roxy-purgeid"],
    "akamai": ["x-akamai-transformed", "akamai-grn"],
    "imperva": ["x-iinfo", "x-cdn"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "f5": ["x-wa-info", "bigipserver"],
}


class CDNFingerprinter:
    def __init__(self, store: Store, timeout: float = 10.0, verify_ssl: bool = False):
        self.store = store
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _rand_string(self, n=8):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def _fetch(self, url: str, method: str = "GET", headers: dict = None,
               body: bytes = None) -> Optional[httpx.Response]:
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout,
                             follow_redirects=False) as client:
                return client.request(method, url, headers=headers or {}, content=body)
        except Exception:
            return None

    def _save(self, method: str, resp: httpx.Response, tags: list = None):
        if not resp:
            return
        p = urlparse(str(resp.url))
        self.store.insert_request(
            method=method, url=str(resp.url), scheme=p.scheme,
            host=p.hostname or "", port=p.port or 443,
            path=p.path, query=p.query or "",
            request_headers=json.dumps(dict(resp.request.headers)),
            request_body=b"", request_content_type="",
            response_status=resp.status_code, response_reason=resp.reason_phrase or "",
            response_headers=json.dumps(dict(resp.headers)),
            response_body=resp.content[:50000],
            response_content_type=resp.headers.get("content-type", ""),
            response_length=len(resp.content),
            duration_ms=0, source="cdn_fingerprint",
            tags=json.dumps(tags or ["cdn"]),
        )

    def fingerprint(self, url: str) -> dict:
        """Full CDN/WAF fingerprint for a URL."""
        result = {
            "url": url,
            "cdn_provider": None,
            "waf_detected": [],
            "query_params_stripped": None,
            "query_params_cached": None,
            "methods_allowed": [],
            "methods_blocked": [],
            "cache_behavior": {},
            "path_filtering": None,
            "headers_of_interest": {},
        }

        # Phase 1: Baseline request + CDN identification
        baseline = self._fetch(url)
        if not baseline:
            result["error"] = "Could not reach URL"
            return result

        self._save("GET", baseline, ["cdn", "baseline"])
        bl_hash = hashlib.md5(baseline.content).hexdigest()
        bl_headers = {k.lower(): v for k, v in baseline.headers.items()}

        # Identify CDN
        for header, provider in CDN_SIGNATURES.items():
            if header in bl_headers:
                if header == "server":
                    server = bl_headers["server"].lower()
                    if "cloudflare" in server:
                        result["cdn_provider"] = "Cloudflare"
                    elif "cloudfront" in server:
                        result["cdn_provider"] = "AWS CloudFront"
                    elif "nginx" in server:
                        result["headers_of_interest"]["server"] = bl_headers["server"]
                else:
                    result["cdn_provider"] = provider
                    result["headers_of_interest"][header] = bl_headers[header]

        # Detect WAF
        for waf_name, waf_headers in WAF_SIGNATURES.items():
            for wh in waf_headers:
                if any(wh in k for k in bl_headers):
                    result["waf_detected"].append(waf_name)
                    break

        # Phase 2: Query string behavior
        result.update(self._test_query_behavior(url, bl_hash, bl_headers))

        # Phase 3: Method filtering
        result.update(self._test_methods(url, baseline.status_code))

        # Phase 4: Cache analysis
        result["cache_behavior"] = self._analyze_cache(bl_headers)

        return result

    def _test_query_behavior(self, url: str, baseline_hash: str,
                              baseline_headers: dict) -> dict:
        """Test if CDN strips, caches, or forwards query parameters."""
        result = {
            "query_params_stripped": False,
            "query_params_cached": False,
            "query_params_forwarded": True,
        }

        # Add a random cache-buster param
        sep = "&" if "?" in url else "?"
        bust = self._rand_string()
        busted_url = f"{url}{sep}_cb={bust}"

        resp = self._fetch(busted_url)
        if not resp:
            return result

        self._save("GET", resp, ["cdn", "query-test"])
        resp_hash = hashlib.md5(resp.content).hexdigest()
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Same content hash = params are stripped or cached
        if resp_hash == baseline_hash:
            # Check cache headers
            cache_status = resp_headers.get("x-cache", resp_headers.get("cf-cache-status", ""))
            if "HIT" in cache_status.upper():
                result["query_params_cached"] = True
                result["query_params_stripped"] = True
                result["query_params_forwarded"] = False
            else:
                # Same content but not a cache hit - server ignores params
                result["query_params_stripped"] = True
                result["query_params_forwarded"] = False

        # Test with a second different buster to confirm
        bust2 = self._rand_string()
        busted_url2 = f"{url}{sep}_cb={bust2}"
        resp2 = self._fetch(busted_url2)
        if resp2:
            resp2_hash = hashlib.md5(resp2.content).hexdigest()
            if resp2_hash == baseline_hash == resp_hash:
                result["query_params_stripped"] = True
                result["query_params_forwarded"] = False

        return result

    def _test_methods(self, url: str, baseline_status: int) -> dict:
        """Test which HTTP methods are allowed vs blocked."""
        allowed = ["GET"]
        blocked = []

        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            resp = self._fetch(url, method=method)
            if not resp:
                blocked.append(method)
                continue

            self._save(method, resp, ["cdn", f"method-{method.lower()}"])

            if resp.status_code == 405:
                blocked.append(method)
            elif resp.status_code == 403:
                blocked.append(method)
            elif resp.status_code in (200, 201, 204, 301, 302, 400, 401):
                allowed.append(method)
            else:
                blocked.append(method)

        return {"methods_allowed": allowed, "methods_blocked": blocked}

    def _analyze_cache(self, headers: dict) -> dict:
        """Extract cache behavior from headers."""
        cache = {}
        for key in ("cache-control", "x-cache", "cf-cache-status", "x-cache-info",
                     "age", "x-varnish", "x-served-by", "server-timing"):
            if key in headers:
                cache[key] = headers[key]
        return cache

    def test_path_whitelist(self, base_url: str, known_good_path: str,
                            test_paths: list[str] = None) -> dict:
        """Test if CDN has a path whitelist by comparing responses to known-good vs random paths."""
        if test_paths is None:
            test_paths = [
                "/admin", "/api/admin", "/_internal", "/debug",
                f"/{self._rand_string(12)}", f"/api/{self._rand_string(8)}",
            ]

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        good_resp = self._fetch(f"{base}{known_good_path}")
        if not good_resp:
            return {"error": "Could not reach known-good path"}

        good_status = good_resp.status_code
        results = {"known_good": {"path": known_good_path, "status": good_status}}
        test_results = []

        for path in test_paths:
            resp = self._fetch(f"{base}{path}")
            if resp:
                test_results.append({
                    "path": path,
                    "status": resp.status_code,
                    "blocked": resp.status_code == 403 and good_status == 200,
                    "length": len(resp.content),
                })

        blocked = [t for t in test_results if t["blocked"]]
        results["tested_paths"] = test_results
        results["has_path_whitelist"] = len(blocked) > len(test_results) * 0.5

        return results


def fingerprint_url(store: Store, url: str) -> dict:
    """Quick fingerprint of a single URL."""
    fp = CDNFingerprinter(store)
    return fp.fingerprint(url)
