"""OAuth/OIDC security testing - automated discovery and misconfiguration detection.

Probes well-known endpoints, enumerates supported grant types via error parsing,
tests userinfo with fake tokens, and checks redirect_uri manipulation on authorize.
"""

import json
import time
from typing import Optional
from urllib.parse import urlparse, urlencode, urljoin, parse_qs

import httpx

from .store import Store


# Grant types to enumerate
GRANT_TYPES = [
    "client_credentials",
    "authorization_code",
    "password",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
]

# Well-known discovery paths
WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/webfinger",
]

# Redirect URI manipulation payloads
REDIRECT_URI_PAYLOADS = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "https://evil.com@legit.com",
    "https://legit.com.evil.com",
    "https://legit.com%40evil.com",
    "https://legit.com/.evil.com",
    "https://legit.com%2F.evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://legit.com#@evil.com",
    "https://legit.com?next=https://evil.com",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
]

# Fake bearer tokens to test userinfo
FAKE_BEARERS = [
    "test",
    "invalid",
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
]

# Default user-agent matching the rest of webprobe
DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


class OIDCTester:
    """Automated OAuth/OIDC endpoint testing."""

    def __init__(self, store: Store, base_url: str, timeout: float = 10.0,
                 verify_ssl: bool = False):
        self.store = store
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {
            "User-Agent": DEFAULT_UA,
            "Accept": "application/json, text/html, */*",
        }
        self._discovered_config: Optional[dict] = None

    # ── Helpers ───────────────────────────────────────────────

    def _request(self, method: str, url: str, headers: dict = None,
                 data: dict = None, allow_redirects: bool = False) -> dict:
        """Send a request, save to store, return structured result."""
        merged_headers = {**self.headers, **(headers or {})}
        parsed = urlparse(url)
        start = time.time()

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout,
                              follow_redirects=allow_redirects) as client:
                resp = client.request(
                    method, url,
                    headers=merged_headers,
                    data=data,
                )
                elapsed = (time.time() - start) * 1000

                resp_headers = dict(resp.headers)
                resp_body = resp.text[:100000]

                # Save to store
                req_id = self.store.insert_request(
                    method=method,
                    url=url,
                    scheme=parsed.scheme or "https",
                    host=parsed.hostname or "",
                    port=parsed.port or (443 if (parsed.scheme or "https") == "https" else 80),
                    path=parsed.path,
                    query=parsed.query or "",
                    request_headers=json.dumps(merged_headers),
                    request_body=(urlencode(data).encode() if data else b""),
                    request_content_type="application/x-www-form-urlencoded" if data else "",
                    response_status=resp.status_code,
                    response_reason=resp.reason_phrase or "",
                    response_headers=json.dumps(resp_headers),
                    response_body=resp_body.encode("utf-8", errors="replace")[:100000],
                    response_content_type=resp_headers.get("content-type", ""),
                    response_length=len(resp.content),
                    duration_ms=round(elapsed, 2),
                    source="oidc",
                    tags=json.dumps(["oidc"]),
                )

                # Try to parse JSON body
                json_body = None
                try:
                    json_body = resp.json()
                except Exception:
                    pass

                return {
                    "request_id": req_id,
                    "url": url,
                    "method": method,
                    "status": resp.status_code,
                    "headers": resp_headers,
                    "body": resp_body,
                    "json": json_body,
                    "length": len(resp.content),
                    "duration_ms": round(elapsed, 2),
                    "error": None,
                }

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return {
                "request_id": None,
                "url": url,
                "method": method,
                "status": 0,
                "headers": {},
                "body": "",
                "json": None,
                "length": 0,
                "duration_ms": round(elapsed, 2),
                "error": str(e),
            }

    def _save_finding(self, request_id: int, category: str, severity: str,
                      title: str, detail: str, evidence: str = ""):
        """Insert a finding into the store."""
        if request_id:
            self.store.insert_finding(
                request_id=request_id,
                category=category,
                severity=severity,
                title=title,
                detail=detail,
                evidence=evidence,
            )

    # ── Discovery ─────────────────────────────────────────────

    def discover(self) -> dict:
        """Try well-known endpoints, return discovered config."""
        results = {
            "endpoints_found": [],
            "endpoints_missing": [],
            "openid_config": None,
            "jwks": None,
            "authorization_server": None,
            "webfinger": None,
            "extracted_endpoints": {},
        }

        for path in WELL_KNOWN_PATHS:
            url = self.base_url + path
            resp = self._request("GET", url)

            if resp["error"]:
                results["endpoints_missing"].append({
                    "path": path,
                    "error": resp["error"],
                })
                continue

            if resp["status"] == 200 and resp["json"]:
                results["endpoints_found"].append({
                    "path": path,
                    "status": resp["status"],
                    "request_id": resp["request_id"],
                })

                if "openid-configuration" in path:
                    results["openid_config"] = resp["json"]
                    self._discovered_config = resp["json"]

                    # Extract known endpoint URLs
                    for key in ("authorization_endpoint", "token_endpoint",
                                "userinfo_endpoint", "revocation_endpoint",
                                "introspection_endpoint", "device_authorization_endpoint",
                                "registration_endpoint", "end_session_endpoint",
                                "jwks_uri"):
                        val = resp["json"].get(key)
                        if val:
                            results["extracted_endpoints"][key] = val

                    # Extract supported grant types / scopes / response types
                    for key in ("grant_types_supported", "response_types_supported",
                                "scopes_supported", "token_endpoint_auth_methods_supported",
                                "claims_supported", "subject_types_supported"):
                        val = resp["json"].get(key)
                        if val:
                            results["extracted_endpoints"][key] = val

                    # Finding: OIDC config exposed
                    self._save_finding(
                        resp["request_id"], "oidc_discovery", "info",
                        "OpenID Connect configuration exposed",
                        f"OIDC discovery endpoint returned configuration at {url}",
                        json.dumps(list(results["extracted_endpoints"].keys())),
                    )

                elif "jwks.json" in path:
                    results["jwks"] = resp["json"]
                    self._save_finding(
                        resp["request_id"], "oidc_discovery", "info",
                        "JWKS endpoint accessible",
                        f"JSON Web Key Set exposed at {url}",
                        json.dumps(resp["json"])[:500],
                    )

                elif "oauth-authorization-server" in path:
                    results["authorization_server"] = resp["json"]

                elif "webfinger" in path:
                    results["webfinger"] = resp["json"]

            else:
                results["endpoints_missing"].append({
                    "path": path,
                    "status": resp["status"],
                    "request_id": resp["request_id"],
                })

        return results

    # ── Grant Enumeration ─────────────────────────────────────

    def enumerate_grants(self, token_endpoint: str = None,
                         client_id: str = None) -> dict:
        """POST to token endpoint with each grant_type, parse error responses."""
        # Resolve token endpoint
        endpoint = token_endpoint
        if not endpoint and self._discovered_config:
            endpoint = self._discovered_config.get("token_endpoint")
        if not endpoint:
            # Try common paths
            for path in ("/oauth/token", "/token", "/oauth2/token",
                         "/connect/token", "/as/token.oauth2"):
                endpoint = self.base_url + path
                probe = self._request("POST", endpoint, data={"grant_type": "test"})
                if probe["status"] != 404:
                    break
            else:
                endpoint = self.base_url + "/oauth/token"

        cid = client_id or "test_client"

        results = {
            "token_endpoint": endpoint,
            "client_id_used": cid,
            "grants": {},
            "supported": [],
            "unsupported": [],
            "needs_credentials": [],
            "errors": [],
        }

        for grant_type in GRANT_TYPES:
            data = {
                "grant_type": grant_type,
                "client_id": cid,
            }

            # Add grant-specific params to get more meaningful errors
            if grant_type == "authorization_code":
                data["code"] = "test_code"
                data["redirect_uri"] = self.base_url + "/callback"
            elif grant_type == "password":
                data["username"] = "test@test.com"
                data["password"] = "test"
            elif grant_type == "refresh_token":
                data["refresh_token"] = "test_refresh_token"
            elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
                data["device_code"] = "test_device_code"
            elif grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                data["assertion"] = "test_jwt_assertion"

            resp = self._request("POST", endpoint, data=data)

            grant_result = {
                "grant_type": grant_type,
                "status": resp["status"],
                "request_id": resp["request_id"],
                "error": None,
                "error_description": None,
                "inference": "unknown",
            }

            if resp["error"]:
                grant_result["error"] = resp["error"]
                grant_result["inference"] = "endpoint_error"
                results["errors"].append(grant_type)
            elif resp["json"]:
                error_code = resp["json"].get("error", "")
                error_desc = resp["json"].get("error_description", "")
                grant_result["error"] = error_code
                grant_result["error_description"] = error_desc

                if error_code == "unsupported_grant_type":
                    grant_result["inference"] = "unsupported"
                    results["unsupported"].append(grant_type)
                elif error_code == "invalid_client":
                    grant_result["inference"] = "supported_needs_creds"
                    results["needs_credentials"].append(grant_type)
                    self._save_finding(
                        resp["request_id"], "oidc_grant", "medium",
                        f"Grant type '{grant_type}' supported (needs valid client)",
                        f"Token endpoint accepts {grant_type} but requires valid client credentials",
                        f"Error: {error_code} - {error_desc}",
                    )
                elif error_code in ("invalid_request", "invalid_grant",
                                    "invalid_scope", "unauthorized_client"):
                    grant_result["inference"] = "supported"
                    results["supported"].append(grant_type)
                    severity = "high" if grant_type == "password" else "medium"
                    self._save_finding(
                        resp["request_id"], "oidc_grant", severity,
                        f"Grant type '{grant_type}' supported",
                        f"Token endpoint accepts {grant_type} grant. "
                        f"Error '{error_code}' indicates the grant type is recognized.",
                        f"Error: {error_code} - {error_desc}",
                    )
                elif not error_code and resp["status"] == 200:
                    # Token was actually issued (very interesting)
                    grant_result["inference"] = "token_issued"
                    results["supported"].append(grant_type)
                    self._save_finding(
                        resp["request_id"], "oidc_grant", "high",
                        f"Token issued for '{grant_type}' with test credentials",
                        f"Token endpoint returned 200 for {grant_type} with test client_id '{cid}'",
                        resp["body"][:500],
                    )
                else:
                    # Other error codes -- still informative
                    grant_result["inference"] = "supported" if resp["status"] != 404 else "unknown"
                    if resp["status"] != 404:
                        results["supported"].append(grant_type)
            elif resp["status"] == 405:
                grant_result["inference"] = "method_not_allowed"
            elif resp["status"] == 404:
                grant_result["inference"] = "endpoint_not_found"
            elif resp["status"] in (401, 403):
                grant_result["inference"] = "supported_needs_creds"
                results["needs_credentials"].append(grant_type)
            else:
                # Non-JSON error response -- try to parse body
                body_lower = resp["body"].lower()
                if "unsupported_grant_type" in body_lower:
                    grant_result["inference"] = "unsupported"
                    results["unsupported"].append(grant_type)
                elif "invalid_client" in body_lower:
                    grant_result["inference"] = "supported_needs_creds"
                    results["needs_credentials"].append(grant_type)
                elif "invalid_request" in body_lower or "invalid_grant" in body_lower:
                    grant_result["inference"] = "supported"
                    results["supported"].append(grant_type)

            results["grants"][grant_type] = grant_result

        # Check for ROPC (password grant) -- high risk
        if "password" in results["supported"]:
            self._save_finding(
                results["grants"]["password"]["request_id"],
                "oidc_grant", "high",
                "Resource Owner Password Credentials (ROPC) grant supported",
                "The password grant type is supported. This allows direct username/password "
                "authentication which is considered insecure and deprecated in OAuth 2.1.",
                f"Token endpoint: {endpoint}",
            )

        return results

    # ── Userinfo Testing ──────────────────────────────────────

    def test_userinfo(self, userinfo_endpoint: str = None) -> dict:
        """Test /userinfo with various auth headers."""
        # Resolve userinfo endpoint
        endpoint = userinfo_endpoint
        if not endpoint and self._discovered_config:
            endpoint = self._discovered_config.get("userinfo_endpoint")
        if not endpoint:
            endpoint = self.base_url + "/userinfo"

        results = {
            "userinfo_endpoint": endpoint,
            "tests": [],
            "findings": [],
        }

        # Test 1: No auth header
        resp = self._request("GET", endpoint)
        test_result = {
            "test": "no_auth",
            "status": resp["status"],
            "request_id": resp["request_id"],
            "has_data": bool(resp["json"]),
            "error": resp.get("error"),
        }
        results["tests"].append(test_result)

        if resp["status"] == 200 and resp["json"]:
            finding = "Userinfo endpoint returns data without authentication"
            results["findings"].append(finding)
            self._save_finding(
                resp["request_id"], "oidc_userinfo", "high",
                "Userinfo accessible without authentication",
                finding,
                resp["body"][:500],
            )

        # Test 2: Various fake bearer tokens
        for token in FAKE_BEARERS:
            auth_headers = {"Authorization": f"Bearer {token}"}
            resp = self._request("GET", endpoint, headers=auth_headers)

            token_label = token[:30] + "..." if len(token) > 30 else token
            test_result = {
                "test": f"bearer_{token_label}",
                "status": resp["status"],
                "request_id": resp["request_id"],
                "has_data": bool(resp["json"]),
                "error": resp.get("error"),
            }
            results["tests"].append(test_result)

            if resp["status"] == 200 and resp["json"]:
                # Check if it returned actual user data (not just an error in JSON)
                data = resp["json"]
                user_keys = {"sub", "email", "name", "preferred_username",
                             "given_name", "family_name", "picture"}
                if user_keys & set(data.keys()):
                    finding = f"Userinfo returns user data with fake bearer token: {token_label}"
                    results["findings"].append(finding)
                    self._save_finding(
                        resp["request_id"], "oidc_userinfo", "critical",
                        "Userinfo returns data with invalid/fake bearer token",
                        finding,
                        resp["body"][:500],
                    )

            # Check for verbose error messages
            if resp["json"] and resp["json"].get("error_description"):
                desc = resp["json"]["error_description"]
                # Verbose errors may leak info about token validation
                if any(kw in desc.lower() for kw in
                       ("expired", "signature", "algorithm", "decode", "parse",
                        "malformed", "key", "issuer")):
                    finding = f"Userinfo leaks token validation details: {desc}"
                    results["findings"].append(finding)
                    self._save_finding(
                        resp["request_id"], "oidc_userinfo", "low",
                        "Verbose token validation error",
                        f"Userinfo error description reveals validation internals",
                        f"error_description: {desc[:300]}",
                    )

        # Test 3: POST method (some implementations accept POST)
        resp = self._request("POST", endpoint,
                             headers={"Authorization": "Bearer test"},
                             data={"access_token": "test"})
        test_result = {
            "test": "post_method",
            "status": resp["status"],
            "request_id": resp["request_id"],
            "has_data": bool(resp["json"]),
            "error": resp.get("error"),
        }
        results["tests"].append(test_result)

        if resp["status"] == 200 and resp["json"]:
            user_keys = {"sub", "email", "name", "preferred_username"}
            if user_keys & set(resp["json"].keys()):
                finding = "Userinfo accepts POST with token in body"
                results["findings"].append(finding)
                self._save_finding(
                    resp["request_id"], "oidc_userinfo", "high",
                    "Userinfo returns data via POST with fake token",
                    finding,
                    resp["body"][:500],
                )

        return results

    # ── Redirect URI Manipulation ─────────────────────────────

    def test_redirect_uri(self, authorize_endpoint: str = None,
                          client_id: str = None) -> list:
        """Test redirect_uri manipulation on the authorize endpoint."""
        # Resolve authorize endpoint
        endpoint = authorize_endpoint
        if not endpoint and self._discovered_config:
            endpoint = self._discovered_config.get("authorization_endpoint")
        if not endpoint:
            endpoint = self.base_url + "/oauth/authorize"

        cid = client_id or "test_client"

        results = []

        for payload in REDIRECT_URI_PAYLOADS:
            params = {
                "response_type": "code",
                "client_id": cid,
                "redirect_uri": payload,
                "scope": "openid",
                "state": "webprobe_test",
            }

            url = endpoint + "?" + urlencode(params)
            resp = self._request("GET", url)

            test_result = {
                "redirect_uri": payload,
                "status": resp["status"],
                "request_id": resp["request_id"],
                "location": resp["headers"].get("location", ""),
                "vulnerable": False,
                "error": resp.get("error"),
            }

            location = resp["headers"].get("location", "")

            # Check if the server redirected to our evil URI
            if resp["status"] in (301, 302, 303, 307, 308) and location:
                parsed_loc = urlparse(location)

                # Direct redirect to evil domain
                if "evil.com" in (parsed_loc.hostname or ""):
                    test_result["vulnerable"] = True
                    test_result["vuln_type"] = "open_redirect"
                    self._save_finding(
                        resp["request_id"], "oidc_redirect", "high",
                        f"OAuth redirect_uri allows external domain: {payload}",
                        f"Authorization endpoint redirected to attacker-controlled URI. "
                        f"Location: {location[:200]}",
                        f"redirect_uri={payload}, Location: {location[:300]}",
                    )

                # Redirect to localhost/127.0.0.1 (SSRF potential)
                elif parsed_loc.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
                    test_result["vulnerable"] = True
                    test_result["vuln_type"] = "localhost_redirect"
                    self._save_finding(
                        resp["request_id"], "oidc_redirect", "medium",
                        f"OAuth redirect_uri allows localhost: {payload}",
                        f"Authorization endpoint accepts localhost redirect URI. "
                        f"Location: {location[:200]}",
                        f"redirect_uri={payload}, Location: {location[:300]}",
                    )

                # Check if payload value appears in the redirect location query params
                if payload in location or payload.replace("https://", "").replace("http://", "") in location:
                    if not test_result["vulnerable"]:
                        test_result["vulnerable"] = True
                        test_result["vuln_type"] = "reflected_redirect"
                        self._save_finding(
                            resp["request_id"], "oidc_redirect", "medium",
                            f"OAuth redirect_uri reflected in redirect: {payload[:60]}",
                            f"The redirect_uri value appears in the Location header. "
                            f"May allow redirect manipulation.",
                            f"redirect_uri={payload}, Location: {location[:300]}",
                        )

            # Check if the response body contains the redirect_uri (rendered in error page)
            elif resp["status"] == 200 and payload in resp["body"]:
                test_result["vuln_type"] = "reflected_in_body"
                test_result["vulnerable"] = True
                self._save_finding(
                    resp["request_id"], "oidc_redirect", "low",
                    f"redirect_uri reflected in authorize page body",
                    f"The redirect_uri parameter value is reflected in the HTML response. "
                    f"Potential for XSS if not properly escaped.",
                    f"redirect_uri={payload}",
                )

            results.append(test_result)

        return results

    # ── Full Audit ────────────────────────────────────────────

    def run_all(self, client_id: str = None) -> dict:
        """Run full OIDC audit and return JSON results."""
        report = {
            "target": self.base_url,
            "timestamp": time.time(),
            "phases": {},
            "summary": {
                "total_requests": 0,
                "findings_by_severity": {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                },
                "key_findings": [],
            },
        }

        # Phase 1: Discovery
        discovery = self.discover()
        report["phases"]["discovery"] = discovery

        # Phase 2: Grant enumeration
        token_ep = None
        if discovery.get("extracted_endpoints"):
            token_ep = discovery["extracted_endpoints"].get("token_endpoint")
        grants = self.enumerate_grants(
            token_endpoint=token_ep,
            client_id=client_id,
        )
        report["phases"]["grants"] = grants

        # Phase 3: Userinfo testing
        userinfo_ep = None
        if discovery.get("extracted_endpoints"):
            userinfo_ep = discovery["extracted_endpoints"].get("userinfo_endpoint")
        userinfo = self.test_userinfo(userinfo_endpoint=userinfo_ep)
        report["phases"]["userinfo"] = userinfo

        # Phase 4: Redirect URI manipulation
        auth_ep = None
        if discovery.get("extracted_endpoints"):
            auth_ep = discovery["extracted_endpoints"].get("authorization_endpoint")
        redirects = self.test_redirect_uri(
            authorize_endpoint=auth_ep,
            client_id=client_id,
        )
        report["phases"]["redirect_uri"] = redirects

        # Build summary
        findings = self.store.get_findings(category=None, severity=None, limit=1000)
        oidc_findings = [f for f in findings if f.get("category", "").startswith("oidc_")]

        for f in oidc_findings:
            sev = f.get("severity", "info")
            report["summary"]["findings_by_severity"][sev] = (
                report["summary"]["findings_by_severity"].get(sev, 0) + 1
            )
            if sev in ("critical", "high"):
                report["summary"]["key_findings"].append({
                    "severity": sev,
                    "title": f["title"],
                    "detail": f["detail"],
                })

        # Count total requests made by this module
        reqs = self.store.query_requests(source="oidc", limit=10000)
        report["summary"]["total_requests"] = len(reqs)
        report["summary"]["total_findings"] = len(oidc_findings)

        return report
