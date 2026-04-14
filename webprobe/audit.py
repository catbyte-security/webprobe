"""AI audit orchestrator - automated dynamic security testing.

Reads captured traffic, identifies attack surface, generates test plans,
executes fuzzing, analyzes results, and iterates on findings.
"""

import json
from typing import Optional
from urllib.parse import urlparse, parse_qs

from .store import Store
from .analyze import Analyzer
from .js_analyze import JSAnalyzer
from .detect import Fuzzer, FuzzResult
from .payloads import (
    ALL_CLASSES, FAST_CLASSES, SQLI, XSS, SSRF, LFI, SSTI,
    OPEN_REDIRECT, GRAPHQL_INTROSPECTION, HEADER_INJECTION,
    get_params_for_fuzzing,
)


class AuditPlan:
    """A plan of what to test, generated from recon data."""

    def __init__(self):
        self.targets: list[dict] = []
        self.graphql_endpoints: list[str] = []
        self.api_endpoints: list[dict] = []
        self.param_targets: list[dict] = []
        self.path_targets: list[dict] = []

    def to_dict(self) -> dict:
        return {
            "total_targets": len(self.targets),
            "graphql_endpoints": self.graphql_endpoints,
            "api_endpoints_to_fuzz": len(self.api_endpoints),
            "param_targets": len(self.param_targets),
            "path_traversal_targets": len(self.path_targets),
            "targets": self.targets[:50],
        }


class Auditor:
    """Orchestrates the full audit: plan -> fuzz -> detect -> report."""

    def __init__(self, store: Store, timeout: float = 10.0, delay_ms: int = 100,
                 verify_ssl: bool = False, vuln_classes: list = None,
                 on_finding: callable = None, on_progress: callable = None):
        self.store = store
        self.fuzzer = Fuzzer(store, timeout=timeout, verify_ssl=verify_ssl, delay_ms=delay_ms)
        self.vuln_classes = vuln_classes or ALL_CLASSES
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.results: list[FuzzResult] = []

    def _log(self, msg: str):
        if self.on_progress:
            self.on_progress(msg)

    def plan(self) -> AuditPlan:
        """Analyze captured traffic and build an audit plan."""
        plan = AuditPlan()

        # Get unique endpoints with params
        all_requests = self.store.query_requests(limit=5000)
        params = self.store.get_unique_params()
        endpoints = self.store.get_endpoints()

        # Detect SPA catch-all to exclude fake endpoints
        fingerprints = self.store.get_response_fingerprints()
        spa_paths = set()
        for g in fingerprints:
            if g["is_spa_catchall"]:
                for r in g["requests"]:
                    spa_paths.add(r["path"])

        # Find parameterized endpoints (highest priority for fuzzing)
        seen_param_combos = set()
        for req in all_requests:
            path = req.get("path", "")
            host = req.get("host", "")
            status = req.get("response_status") or 0
            query = req.get("query", "")
            url = req.get("url", "")

            # Skip SPA shell responses, non-200s, and static assets
            if path in spa_paths:
                continue
            if status < 200 or status >= 400:
                continue
            if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ico")):
                continue

            # Endpoints with query params
            if query:
                parsed_params = parse_qs(query, keep_blank_values=True)
                for pname in parsed_params:
                    combo_key = f"{host}{path}:{pname}"
                    if combo_key not in seen_param_combos:
                        seen_param_combos.add(combo_key)
                        plan.param_targets.append({
                            "url": url.split("?")[0] + "?" + query,
                            "host": host,
                            "path": path,
                            "param": pname,
                            "location": "query",
                            "original_value": parsed_params[pname][0],
                        })

            # JSON API endpoints (test for injection in path segments)
            ct = req.get("response_content_type", "")
            if "json" in ct and path and not query:
                plan.api_endpoints.append({
                    "url": url,
                    "host": host,
                    "path": path,
                    "content_type": ct,
                })

            # Path-based params (e.g., /api/missions/123)
            parts = path.strip("/").split("/")
            for i, part in enumerate(parts):
                if part.isdigit() or (len(part) > 20 and all(c in "0123456789abcdef-" for c in part)):
                    plan.path_targets.append({
                        "url": url,
                        "host": host,
                        "path": path,
                        "param_index": i,
                        "original_value": part,
                    })

        # Find GraphQL endpoints
        for ep in endpoints:
            path = ep.get("path", "")
            if "graphql" in path.lower():
                host = ep.get("host", "")
                # Only if it's not a SPA catch-all
                if path not in spa_paths:
                    plan.graphql_endpoints.append(f"https://{host}{path}")

        # Check JS-discovered endpoints too
        js_results = JSAnalyzer(self.store).analyze_all()
        for route in js_results.get("api_endpoints", []):
            if route.startswith("/"):
                # Try to match to a known host
                hosts = self.store.get_unique_hosts()
                for h in hosts:
                    if "api" in h or "content" in h:
                        plan.api_endpoints.append({
                            "url": f"https://{h}{route}",
                            "host": h,
                            "path": route,
                            "content_type": "unknown",
                        })
                        break

        # Build target list
        for pt in plan.param_targets:
            plan.targets.append({
                "type": "param_fuzz",
                "url": pt["url"],
                "param": pt["param"],
                "vuln_classes": [c["short"] for c in self.vuln_classes
                                if c["short"] not in ("graphql", "redirect")],
            })

        for pt in plan.path_targets:
            plan.targets.append({
                "type": "path_fuzz",
                "url": pt["url"],
                "param": f"path_segment[{pt['param_index']}]",
                "vuln_classes": ["lfi", "sqli", "idor"],
            })

        for ep in plan.api_endpoints[:30]:
            plan.targets.append({
                "type": "api_fuzz",
                "url": ep["url"],
                "param": "endpoint",
                "vuln_classes": ["sqli", "xss", "ssti"],
            })

        for gql in plan.graphql_endpoints:
            plan.targets.append({
                "type": "graphql",
                "url": gql,
                "param": "query",
                "vuln_classes": ["graphql"],
            })

        return plan

    def run(self, plan: AuditPlan = None, max_requests: int = 500) -> dict:
        """Execute the full audit."""
        if plan is None:
            plan = self.plan()

        self._log(f"Audit plan: {len(plan.targets)} targets")
        total_fuzz_requests = 0
        all_hits: list[dict] = []

        # Phase 1: Fuzz parameters
        self._log("Phase 1: Parameter fuzzing")
        for target in plan.param_targets:
            if total_fuzz_requests >= max_requests:
                break
            url = target["url"]
            param = target["param"]

            for vuln_class in self.vuln_classes:
                if vuln_class["short"] in ("graphql", "redirect"):
                    continue
                if total_fuzz_requests >= max_requests:
                    break

                self._log(f"  [{vuln_class['short']}] {param}@ {url[:80]}")

                def on_result(r: FuzzResult):
                    if r.hits:
                        if self.on_finding:
                            self.on_finding(r)

                results = self.fuzzer.fuzz_endpoint(
                    url, vuln_class, param_name=param,
                    param_location="query", on_result=on_result,
                )
                total_fuzz_requests += len(results)
                for r in results:
                    if r.hits:
                        all_hits.append(r.to_dict())
                self.results.extend(results)

        # Phase 2: API endpoint fuzzing (append params)
        self._log("Phase 2: API endpoint fuzzing")
        for ep in plan.api_endpoints[:20]:
            if total_fuzz_requests >= max_requests:
                break
            url = ep["url"]

            # Try common injection params
            for test_param in ("id", "search", "q", "filter", "sort"):
                for vuln_class in [SQLI, XSS, SSTI]:
                    if total_fuzz_requests >= max_requests:
                        break
                    # Only try first 3 payloads per class for APIs
                    limited_class = {**vuln_class, "payloads": vuln_class["payloads"][:3]}
                    results = self.fuzzer.fuzz_endpoint(
                        url, limited_class, param_name=test_param,
                        param_location="query",
                    )
                    total_fuzz_requests += len(results)
                    for r in results:
                        if r.hits:
                            all_hits.append(r.to_dict())
                    self.results.extend(results)

        # Phase 3: Path traversal on parameterized paths
        self._log("Phase 3: Path traversal testing")
        for pt in plan.path_targets[:10]:
            if total_fuzz_requests >= max_requests:
                break
            url = pt["url"]
            results = self.fuzzer.fuzz_endpoint(
                url, LFI, param_name=None, param_location="path",
            )
            total_fuzz_requests += len(results)
            for r in results:
                if r.hits:
                    all_hits.append(r.to_dict())
            self.results.extend(results)

        # Phase 4: GraphQL introspection
        self._log("Phase 4: GraphQL introspection")
        for gql_url in plan.graphql_endpoints:
            if total_fuzz_requests >= max_requests:
                break
            results = self.fuzzer.fuzz_graphql(gql_url, GRAPHQL_INTROSPECTION)
            total_fuzz_requests += len(results)
            for r in results:
                if r.hits:
                    all_hits.append(r.to_dict())
            self.results.extend(results)

        # Build summary
        summary = {
            "total_requests_sent": total_fuzz_requests,
            "targets_tested": len(plan.targets),
            "total_hits": len(all_hits),
            "by_confidence": {
                "high": len([h for h in all_hits if h["confidence"] == "high"]),
                "medium": len([h for h in all_hits if h["confidence"] == "medium"]),
                "low": len([h for h in all_hits if h["confidence"] == "low"]),
            },
            "by_vuln_class": {},
            "findings": sorted(all_hits, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["confidence"], 3)),
        }

        for h in all_hits:
            vc = h["vuln_class"]
            summary["by_vuln_class"][vc] = summary["by_vuln_class"].get(vc, 0) + 1

        self._log(f"Audit complete: {total_fuzz_requests} requests, {len(all_hits)} hits")
        return summary
