"""Response analysis - compare fuzzed responses against baselines to detect vulns."""

import json
import re
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from .store import Store


class FuzzResult:
    """Result of a single fuzz attempt."""
    def __init__(self, param: str, location: str, payload: str, vuln_class: str,
                 original_url: str, request_id: int = None):
        self.param = param
        self.location = location
        self.payload = payload
        self.vuln_class = vuln_class
        self.original_url = original_url
        self.request_id = request_id
        self.response_status: int = 0
        self.response_length: int = 0
        self.response_time_ms: float = 0
        self.response_body: str = ""
        self.response_headers: dict = {}
        self.baseline_status: int = 0
        self.baseline_length: int = 0
        self.baseline_time_ms: float = 0
        self.hits: list[dict] = []  # matched findings
        self.confidence: str = "none"  # none, low, medium, high
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "param": self.param,
            "location": self.location,
            "payload": self.payload,
            "vuln_class": self.vuln_class,
            "url": self.original_url,
            "confidence": self.confidence,
            "hits": self.hits,
            "response_status": self.response_status,
            "response_length": self.response_length,
            "response_time_ms": self.response_time_ms,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "baseline_time_ms": self.baseline_time_ms,
            "status_changed": self.response_status != self.baseline_status,
            "length_diff": self.response_length - self.baseline_length,
            "time_diff_ms": self.response_time_ms - self.baseline_time_ms,
            "error": self.error,
        }


class Detector:
    """Analyze fuzz responses for vulnerability indicators."""

    def analyze(self, result: FuzzResult, vuln_config: dict) -> FuzzResult:
        """Run all detection checks on a fuzz result."""
        # Pattern matching
        for pattern, confidence, desc in vuln_config.get("matchers", []):
            match = pattern.search(result.response_body)
            if match:
                result.hits.append({
                    "type": "pattern_match",
                    "confidence": confidence,
                    "description": desc,
                    "evidence": result.response_body[max(0, match.start()-30):match.end()+30][:200],
                })

        # Time-based detection
        threshold = vuln_config.get("time_threshold_ms")
        if threshold and result.response_time_ms > threshold:
            time_diff = result.response_time_ms - result.baseline_time_ms
            if time_diff > threshold * 0.8:
                result.hits.append({
                    "type": "time_based",
                    "confidence": "medium",
                    "description": f"Response {result.response_time_ms:.0f}ms vs baseline {result.baseline_time_ms:.0f}ms (diff: {time_diff:.0f}ms)",
                    "evidence": f"Threshold: {threshold}ms",
                })

        # Status code change (e.g., 200 -> 500 = error triggered)
        if result.response_status != result.baseline_status:
            if result.response_status >= 500:
                result.hits.append({
                    "type": "status_change",
                    "confidence": "medium",
                    "description": f"Server error triggered: {result.baseline_status} -> {result.response_status}",
                    "evidence": f"Payload: {result.payload[:100]}",
                })
            elif result.response_status == 403 and result.baseline_status == 200:
                result.hits.append({
                    "type": "status_change",
                    "confidence": "low",
                    "description": f"WAF/filter triggered: {result.baseline_status} -> {result.response_status}",
                    "evidence": f"Payload may have been detected",
                })

        # Significant length change
        if result.baseline_length > 0:
            length_ratio = result.response_length / result.baseline_length
            if length_ratio > 2.0 or length_ratio < 0.3:
                result.hits.append({
                    "type": "length_anomaly",
                    "confidence": "low",
                    "description": f"Response length changed significantly: {result.baseline_length} -> {result.response_length} ({length_ratio:.1f}x)",
                    "evidence": "",
                })

        # Redirect check (open redirect)
        if vuln_config.get("check_redirect"):
            location = result.response_headers.get("location", "")
            if "evil.com" in location:
                result.hits.append({
                    "type": "open_redirect",
                    "confidence": "high",
                    "description": f"Redirect to attacker-controlled domain",
                    "evidence": f"Location: {location[:200]}",
                })

        # Header injection check
        if vuln_config.get("check_headers"):
            for hname, hval in result.response_headers.items():
                if "x-injected" in hname.lower() or "wbprb" in hval.lower():
                    result.hits.append({
                        "type": "header_injection",
                        "confidence": "high",
                        "description": f"Injected header appeared in response",
                        "evidence": f"{hname}: {hval}",
                    })

        # Set overall confidence
        if result.hits:
            confidences = [h["confidence"] for h in result.hits]
            if "high" in confidences:
                result.confidence = "high"
            elif "medium" in confidences:
                result.confidence = "medium"
            else:
                result.confidence = "low"

        return result


class Fuzzer:
    """Send payloads and collect responses."""

    def __init__(self, store: Store, timeout: float = 10.0, verify_ssl: bool = False,
                 delay_ms: int = 0, user_agent: str = None):
        self.store = store
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay_ms = delay_ms
        self.detector = Detector()
        self.headers = {
            "User-Agent": user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "*/*",
        }

    def _get_baseline(self, url: str, method: str = "GET",
                      headers: dict = None, body: bytes = None) -> tuple[int, int, float, str, dict]:
        """Fetch baseline response for comparison."""
        with httpx.Client(verify=self.verify_ssl, timeout=self.timeout,
                         follow_redirects=False) as client:
            start = time.time()
            resp = client.request(method, url, headers=headers or self.headers, content=body)
            elapsed = (time.time() - start) * 1000
            return (resp.status_code, len(resp.content), elapsed,
                    resp.text[:50000], dict(resp.headers))

    def _send_fuzz(self, url: str, method: str = "GET",
                   headers: dict = None, body: bytes = None) -> tuple[int, int, float, str, dict]:
        """Send a fuzzed request."""
        with httpx.Client(verify=self.verify_ssl, timeout=self.timeout,
                         follow_redirects=False) as client:
            start = time.time()
            try:
                resp = client.request(method, url, headers=headers or self.headers, content=body)
                elapsed = (time.time() - start) * 1000
                return (resp.status_code, len(resp.content), elapsed,
                        resp.text[:50000], dict(resp.headers))
            except httpx.TimeoutException:
                elapsed = (time.time() - start) * 1000
                return (0, 0, elapsed, "", {})
            except Exception as e:
                return (0, 0, 0, str(e), {})

    def fuzz_param_in_url(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into a URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def fuzz_path_segment(self, url: str, payload: str) -> str:
        """Inject payload as a path segment (for LFI/path traversal)."""
        parsed = urlparse(url)
        # Replace the last path segment
        parts = parsed.path.rsplit("/", 1)
        new_path = parts[0] + "/" + payload if len(parts) > 1 else "/" + payload
        return f"{parsed.scheme}://{parsed.netloc}{new_path}"

    def fuzz_endpoint(self, url: str, vuln_config: dict,
                      param_name: str = None, param_location: str = "query",
                      on_result: callable = None) -> list[FuzzResult]:
        """Fuzz a single endpoint with all payloads from a vuln class."""
        results = []

        # Get baseline
        try:
            bl_status, bl_length, bl_time, bl_body, bl_headers = self._get_baseline(url)
        except Exception as e:
            return results

        for payload in vuln_config["payloads"]:
            if param_name and param_location == "query":
                fuzzed_url = self.fuzz_param_in_url(url, param_name, payload)
            elif param_location == "path":
                fuzzed_url = self.fuzz_path_segment(url, payload)
            else:
                # Append as query param
                sep = "&" if "?" in url else "?"
                fuzzed_url = f"{url}{sep}{param_name}={payload}" if param_name else url

            result = FuzzResult(
                param=param_name or "path",
                location=param_location,
                payload=payload,
                vuln_class=vuln_config["short"],
                original_url=url,
            )
            result.baseline_status = bl_status
            result.baseline_length = bl_length
            result.baseline_time_ms = bl_time

            # Send fuzzed request
            status, length, elapsed, body, headers = self._send_fuzz(fuzzed_url)
            result.response_status = status
            result.response_length = length
            result.response_time_ms = elapsed
            result.response_body = body
            result.response_headers = headers

            # Analyze
            result = self.detector.analyze(result, vuln_config)

            if result.hits:
                # Save to DB
                parsed = urlparse(fuzzed_url)
                req_id = self.store.insert_request(
                    method="GET", url=fuzzed_url, scheme=parsed.scheme,
                    host=parsed.hostname or "", port=parsed.port or 443,
                    path=parsed.path, query=parsed.query,
                    request_headers=json.dumps(self.headers),
                    request_body=b"", request_content_type="",
                    response_status=status,
                    response_reason="",
                    response_headers=json.dumps(headers),
                    response_body=body.encode()[:100000],
                    response_content_type=headers.get("content-type", ""),
                    response_length=length,
                    duration_ms=round(elapsed, 2),
                    source="fuzzer",
                    tags=json.dumps(["fuzz", vuln_config["short"], result.confidence]),
                )
                result.request_id = req_id

                # Save finding
                for hit in result.hits:
                    self.store.insert_finding(
                        request_id=req_id,
                        category=f"fuzz_{vuln_config['short']}",
                        severity=hit["confidence"],
                        title=f"[{vuln_config['name']}] {hit['description']}",
                        detail=f"Param: {param_name}, Payload: {payload[:100]}, URL: {fuzzed_url[:200]}",
                        evidence=hit.get("evidence", ""),
                    )

            if on_result:
                on_result(result)

            results.append(result)

            if self.delay_ms > 0:
                time.sleep(self.delay_ms / 1000)

        return results

    def fuzz_graphql(self, url: str, vuln_config: dict,
                     on_result: callable = None) -> list[FuzzResult]:
        """Send GraphQL introspection queries."""
        results = []

        for payload in vuln_config["payloads"]:
            result = FuzzResult(
                param="query", location="body",
                payload=payload[:80], vuln_class="graphql",
                original_url=url,
            )

            headers = {**self.headers, "Content-Type": "application/json"}
            try:
                with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                    start = time.time()
                    resp = client.post(url, headers=headers, content=payload.encode())
                    elapsed = (time.time() - start) * 1000

                    result.response_status = resp.status_code
                    result.response_length = len(resp.content)
                    result.response_time_ms = elapsed
                    result.response_body = resp.text[:50000]
                    result.response_headers = dict(resp.headers)
            except Exception as e:
                result.error = str(e)
                results.append(result)
                continue

            result = self.detector.analyze(result, vuln_config)

            if result.hits:
                parsed = urlparse(url)
                req_id = self.store.insert_request(
                    method="POST", url=url, scheme=parsed.scheme,
                    host=parsed.hostname or "", port=parsed.port or 443,
                    path=parsed.path, query="",
                    request_headers=json.dumps(headers),
                    request_body=payload.encode(), request_content_type="application/json",
                    response_status=result.response_status,
                    response_reason="",
                    response_headers=json.dumps(result.response_headers),
                    response_body=result.response_body.encode()[:100000],
                    response_content_type=result.response_headers.get("content-type", ""),
                    response_length=result.response_length,
                    duration_ms=round(elapsed, 2),
                    source="fuzzer",
                    tags=json.dumps(["fuzz", "graphql", result.confidence]),
                )
                result.request_id = req_id

                for hit in result.hits:
                    self.store.insert_finding(
                        request_id=req_id,
                        category="fuzz_graphql",
                        severity=hit["confidence"],
                        title=f"[GraphQL] {hit['description']}",
                        detail=f"Introspection query returned schema data at {url}",
                        evidence=hit.get("evidence", ""),
                    )

            if on_result:
                on_result(result)
            results.append(result)

        return results
