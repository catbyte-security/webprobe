"""CLI interface - all commands output JSON for AI consumption."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

from .store import Store
from .analyze import Analyzer
from .crawler import run_crawl
from .proxy import start_proxy
from .replay import replay_request
from .js_analyze import JSAnalyzer
from .audit import Auditor
from .cloud import CloudTester
from .oidc import OIDCTester
from .payloads import ALL_CLASSES, FAST_CLASSES, get_class

console = Console(stderr=True)
DB_ENV = "WEBPROBE_DB"
DEFAULT_DB = "webprobe.db"


def get_db_path(ctx):
    return ctx.obj.get("db", os.environ.get(DB_ENV, DEFAULT_DB))


def output(data, as_json=True):
    """Print structured output to stdout."""
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        click.echo(data)


@click.group()
@click.option("--db", default=None, help="Path to webprobe.db (default: ./webprobe.db)")
@click.option("--json-output", "json_out", is_flag=True, default=False, help="Force JSON output")
@click.pass_context
def cli(ctx, db, json_out):
    """webprobe - Black-box web recon & traffic capture for AI-driven bug bounty hunting.

    Intercept, crawl, analyze, and replay HTTP traffic. All output is JSON for AI agents.
    """
    ctx.ensure_object(dict)
    ctx.obj["db"] = db or os.environ.get(DB_ENV, DEFAULT_DB)
    ctx.obj["json"] = json_out


# ═══════════════════════════════════════════════════════════════
# PROXY
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--port", "-p", default=8080, help="Proxy listen port")
@click.option("--host", "-H", default="127.0.0.1", help="Proxy listen host")
@click.option("--upstream", default=None, help="Upstream proxy (e.g., http://127.0.0.1:8081)")
@click.option("--ssl-insecure", is_flag=True, help="Don't verify upstream SSL certs")
@click.option("--transparent", is_flag=True, help="Transparent proxy mode")
@click.option("--quiet", "-q", is_flag=True, help="Suppress mitmproxy output")
@click.pass_context
def proxy(ctx, port, host, upstream, ssl_insecure, transparent, quiet):
    """Start the intercepting proxy (wraps mitmdump).

    Configure your browser/tool to use http://127.0.0.1:8080 as HTTP proxy.
    All traffic is captured to the database for analysis.

    Install mitmproxy CA cert: ~/.mitmproxy/mitmproxy-ca-cert.pem
    """
    db_path = os.path.abspath(get_db_path(ctx))
    store = Store(db_path)

    console.print(Panel.fit(
        f"[bold green]webprobe proxy[/bold green]\n"
        f"Listening: [cyan]{host}:{port}[/cyan]\n"
        f"Database:  [cyan]{db_path}[/cyan]\n"
        f"CA cert:   [cyan]~/.mitmproxy/mitmproxy-ca-cert.pem[/cyan]\n"
        f"\nSet HTTP proxy to [bold]http://{host}:{port}[/bold]\n"
        f"Press Ctrl+C to stop.",
        title="Intercepting Proxy",
    ))

    scope = store.get_scope()
    if scope:
        console.print(f"Scope: {', '.join(s['pattern'] for s in scope)}")
    store.close()

    cmd, env = start_proxy(
        db_path=db_path,
        listen_port=port,
        listen_host=host,
        upstream_proxy=upstream,
        ssl_insecure=ssl_insecure,
        transparent=transparent,
        quiet=quiet,
    )

    try:
        proc = subprocess.Popen(cmd, env=env)
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
        console.print("\n[yellow]Proxy stopped.[/yellow]")


# ═══════════════════════════════════════════════════════════════
# CRAWL
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("url")
@click.option("--depth", "-d", default=3, help="Max crawl depth")
@click.option("--max-pages", "-m", default=500, help="Max pages to crawl")
@click.option("--concurrency", "-c", default=15, help="Concurrent requests")
@click.option("--timeout", "-t", default=10.0, help="Request timeout (seconds)")
@click.option("--no-probe", is_flag=True, help="Skip common path probing")
@click.option("--no-js", is_flag=True, help="Skip JS endpoint extraction")
@click.option("--header", "-H", multiple=True, help="Extra header (Name: Value)")
@click.option("--cookie", multiple=True, help="Cookie (name=value)")
@click.option("--user-agent", default=None, help="Custom User-Agent")
@click.pass_context
def crawl(ctx, url, depth, max_pages, concurrency, timeout, no_probe, no_js, header, cookie, user_agent):
    """Crawl a target URL to discover endpoints, forms, and API paths.

    Extracts links from HTML, parses JavaScript for API endpoints,
    probes common paths (robots.txt, sitemap.xml, .env, etc.).
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    extra_headers = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    cookies = {}
    for c in cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    kwargs = {
        "max_depth": depth,
        "max_pages": max_pages,
        "concurrency": concurrency,
        "timeout": timeout,
        "probe_common": not no_probe,
        "extract_js": not no_js,
        "headers": extra_headers,
        "cookies": cookies,
    }
    if user_agent:
        kwargs["user_agent"] = user_agent

    def on_request(method, url, status, size):
        console.print(f"  [dim]{method}[/dim] {url} [{'green' if 200 <= status < 300 else 'yellow' if 300 <= status < 400 else 'red'}]{status}[/] ({size}B)")

    kwargs["on_request"] = on_request

    console.print(f"[bold]Crawling[/bold] {url} (depth={depth}, max={max_pages})")
    start = time.time()

    try:
        result = run_crawl(store, url, **kwargs)
    except KeyboardInterrupt:
        console.print("\n[yellow]Crawl interrupted.[/yellow]")
        store.close()
        return
    except Exception as e:
        console.print(f"[red]Crawl error:[/red] {e}")
        store.close()
        return

    elapsed = round(time.time() - start, 1)
    result["elapsed_seconds"] = elapsed
    store.close()

    console.print(f"\n[bold green]Crawl complete[/bold green] in {elapsed}s")
    output(result)


# ═══════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════

@cli.group()
def scope():
    """Manage target scope (domains/hosts to include/exclude)."""
    pass


@scope.command("add")
@click.argument("pattern")
@click.option("--exclude", is_flag=True, help="Add as exclusion pattern")
@click.pass_context
def scope_add(ctx, pattern, exclude):
    """Add a domain/host pattern to scope."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    scope_type = "exclude" if exclude else "include"
    store.add_scope(pattern, scope_type)
    store.close()
    output({"action": "added", "pattern": pattern, "type": scope_type})


@scope.command("rm")
@click.argument("pattern")
@click.pass_context
def scope_rm(ctx, pattern):
    """Remove a pattern from scope."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    store.remove_scope(pattern)
    store.close()
    output({"action": "removed", "pattern": pattern})


@scope.command("list")
@click.pass_context
def scope_list(ctx):
    """List current scope patterns."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    result = store.get_scope()
    store.close()
    output(result)


# ═══════════════════════════════════════════════════════════════
# REQUESTS
# ═══════════════════════════════════════════════════════════════

@cli.command("requests")
@click.option("--method", "-m", default=None, help="Filter by HTTP method")
@click.option("--host", "-H", default=None, help="Filter by host (substring match)")
@click.option("--path", "-p", default=None, help="Filter by path (substring match)")
@click.option("--status", "-s", default=None, type=int, help="Filter by exact status code")
@click.option("--status-range", default=None, help="Status range (e.g., 400-499)")
@click.option("--source", default=None, type=click.Choice(["proxy", "crawler", "replay"]))
@click.option("--content-type", "-ct", default=None, help="Filter by response content type")
@click.option("--has-params", is_flag=True, default=False, help="Only requests with parameters")
@click.option("--limit", "-n", default=100, help="Max results")
@click.option("--offset", default=0, help="Offset for pagination")
@click.option("--full", is_flag=True, help="Include request/response bodies")
@click.option("--table", "as_table", is_flag=True, help="Pretty table output (stderr)")
@click.pass_context
def list_requests(ctx, method, host, path, status, status_range, source, content_type, has_params, limit, offset, full, as_table):
    """Query captured HTTP requests with filters.

    All filters are AND-combined. Output is JSON array for AI parsing.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    sr = None
    if status_range:
        parts = status_range.split("-")
        sr = (int(parts[0]), int(parts[1]))

    results = store.query_requests(
        method=method,
        host=host,
        path_contains=path,
        status=status,
        status_range=sr,
        source=source,
        content_type=content_type,
        has_params=has_params if has_params else None,
        limit=limit,
        offset=offset,
    )

    formatted = [store.request_to_dict(r, include_body=full) for r in results]

    if as_table:
        table = Table(title=f"Requests ({len(formatted)})")
        table.add_column("ID", style="dim")
        table.add_column("Method", style="bold")
        table.add_column("URL", max_width=80)
        table.add_column("Status")
        table.add_column("Size")
        table.add_column("Time")
        table.add_column("Src", style="dim")
        for r in formatted:
            status_style = "green" if 200 <= (r["status"] or 0) < 300 else "yellow" if 300 <= (r["status"] or 0) < 400 else "red"
            table.add_row(
                str(r["id"]),
                r["method"],
                r["url"][:80],
                f"[{status_style}]{r['status']}[/]",
                str(r["response_length"] or 0),
                f"{r['duration_ms'] or 0:.0f}ms",
                r["source"] or "",
            )
        console.print(table)

    store.close()
    output(formatted)


@cli.command("request")
@click.argument("request_id", type=int)
@click.pass_context
def show_request(ctx, request_id):
    """Show full details of a single request (headers + body)."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    req = store.get_request(request_id)
    if not req:
        output({"error": f"Request {request_id} not found"})
        store.close()
        return
    formatted = store.request_to_dict(req, include_body=True)
    store.close()
    output(formatted)


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@cli.command("endpoints")
@click.option("--host", "-H", default=None, help="Filter by host")
@click.pass_context
def list_endpoints(ctx, host):
    """List unique endpoints (method + path) with hit counts."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    endpoints = store.get_endpoints(host)
    store.close()
    output(endpoints)


# ═══════════════════════════════════════════════════════════════
# PARAMS
# ═══════════════════════════════════════════════════════════════

@cli.command("params")
@click.pass_context
def list_params(ctx):
    """List all discovered parameters across requests."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    params = store.get_unique_params()
    store.close()
    output(params)


# ═══════════════════════════════════════════════════════════════
# ANALYZE
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--request-id", "-r", type=int, default=None, help="Analyze single request")
@click.pass_context
def analyze(ctx, request_id):
    """Run passive security analysis on captured traffic.

    Checks: security headers, cookies, CORS, info disclosure,
    technology fingerprinting, interesting patterns.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)
    analyzer = Analyzer(store)

    if request_id:
        findings = analyzer.analyze_request(request_id)
        store.close()
        output(findings)
    else:
        console.print("[bold]Running passive analysis...[/bold]")
        summary = analyzer.analyze_all()
        console.print(f"[green]Analysis complete.[/green] {summary['total_requests_analyzed']} requests analyzed.")
        store.close()
        output(summary)


# ═══════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════

@cli.command("findings")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--category", "-c", default=None, help="Filter by category")
@click.option("--limit", "-n", default=200, help="Max results")
@click.option("--table", "as_table", is_flag=True, help="Pretty table output")
@click.pass_context
def list_findings(ctx, severity, category, limit, as_table):
    """List security findings from analysis."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    findings = store.get_findings(category=category, severity=severity, limit=limit)

    if as_table:
        table = Table(title=f"Findings ({len(findings)})")
        table.add_column("ID", style="dim")
        table.add_column("Sev")
        table.add_column("Category", style="dim")
        table.add_column("Title", max_width=60)
        table.add_column("ReqID", style="dim")
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        for f in findings:
            table.add_row(
                str(f["id"]),
                f"[{sev_colors.get(f['severity'], 'white')}]{f['severity']}[/]",
                f["category"],
                f["title"][:60],
                str(f["request_id"]),
            )
        console.print(table)

    store.close()
    output(findings)


# ═══════════════════════════════════════════════════════════════
# REPLAY
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("request_id", type=int)
@click.option("--method", "-m", default=None, help="Override HTTP method")
@click.option("--url", default=None, help="Override URL")
@click.option("--header", "-H", multiple=True, help="Override header (Name: Value)")
@click.option("--param", "-p", multiple=True, help="Override query param (name=value)")
@click.option("--body", "-b", default=None, help="Override request body")
@click.option("--follow", is_flag=True, help="Follow redirects")
@click.pass_context
def replay(ctx, request_id, method, url, header, param, body, follow):
    """Replay a captured request with optional modifications.

    Useful for testing parameter manipulation, auth bypass, etc.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    mod_headers = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            mod_headers[k.strip()] = v.strip()

    mod_params = {}
    for p in param:
        if "=" in p:
            k, v = p.split("=", 1)
            mod_params[k.strip()] = v.strip()

    result = replay_request(
        store, request_id,
        modify_headers=mod_headers or None,
        modify_params=mod_params or None,
        modify_body=body,
        modify_method=method,
        modify_url=url,
        follow_redirects=follow,
    )
    store.close()
    output(result)


# ═══════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--include-requests", is_flag=True, help="Include all request data in report")
@click.option("--out", "-o", default=None, help="Write report to file")
@click.pass_context
def report(ctx, include_requests, out):
    """Generate comprehensive JSON report for AI analysis.

    Includes: findings summary, endpoints, parameters, technologies,
    attack surface mapping, and optionally all request data.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    # Run analysis first
    analyzer = Analyzer(store)
    console.print("[bold]Running analysis and generating report...[/bold]")
    analyzer.analyze_all()
    report_data = analyzer.generate_report(include_requests=include_requests)
    store.close()

    report_json = json.dumps(report_data, indent=2, default=str)

    if out:
        Path(out).write_text(report_json)
        console.print(f"[green]Report written to {out}[/green]")
    else:
        click.echo(report_json)


# ═══════════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.pass_context
def stats(ctx):
    """Show traffic statistics summary."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    result = store.get_stats()
    store.close()
    output(result)


# ═══════════════════════════════════════════════════════════════
# HOSTS
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.pass_context
def hosts(ctx):
    """List all unique hosts seen in traffic."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    result = store.get_unique_hosts()
    store.close()
    output(result)


# ═══════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════

@cli.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "curl", "httpie"]), default="json")
@click.option("--request-id", "-r", type=int, default=None, help="Export single request")
@click.option("--host", "-H", default=None, help="Filter by host")
@click.pass_context
def export_requests(ctx, fmt, request_id, host):
    """Export requests as JSON, curl commands, or httpie commands."""
    db_path = get_db_path(ctx)
    store = Store(db_path)

    if request_id:
        reqs = [store.get_request(request_id)]
        reqs = [r for r in reqs if r]
    else:
        reqs = store.query_requests(host=host, limit=500)

    if fmt == "json":
        formatted = [store.request_to_dict(r, include_body=True) for r in reqs]
        output(formatted)

    elif fmt == "curl":
        cmds = []
        for req in reqs:
            headers = json.loads(req.get("request_headers") or "{}")
            cmd = f"curl -X {req['method']}"
            for k, v in headers.items():
                if k.lower() not in ("host", "content-length", "connection"):
                    cmd += f" -H '{k}: {v}'"
            body = req.get("request_body")
            if body:
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="replace")
                if body:
                    cmd += f" -d '{body}'"
            cmd += f" '{req['url']}'"
            cmds.append({"id": req["id"], "curl": cmd})
        output(cmds)

    elif fmt == "httpie":
        cmds = []
        for req in reqs:
            headers = json.loads(req.get("request_headers") or "{}")
            method = req["method"].lower()
            cmd = f"http {method} '{req['url']}'"
            for k, v in headers.items():
                if k.lower() not in ("host", "content-length", "connection", "user-agent", "accept-encoding"):
                    cmd += f" '{k}:{v}'"
            cmds.append({"id": req["id"], "httpie": cmd})
        output(cmds)

    store.close()


# ═══════════════════════════════════════════════════════════════
# DIFF
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("id1", type=int)
@click.argument("id2", type=int)
@click.pass_context
def diff(ctx, id1, id2):
    """Compare two requests/responses side by side (JSON diff)."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    r1 = store.get_request(id1)
    r2 = store.get_request(id2)
    if not r1 or not r2:
        output({"error": "One or both request IDs not found"})
        store.close()
        return

    d1 = store.request_to_dict(r1, include_body=True)
    d2 = store.request_to_dict(r2, include_body=True)

    differences = {}
    all_keys = set(d1.keys()) | set(d2.keys())
    for k in all_keys:
        v1 = d1.get(k)
        v2 = d2.get(k)
        if v1 != v2:
            differences[k] = {"request_1": v1, "request_2": v2}

    store.close()
    output({
        "request_1_id": id1,
        "request_2_id": id2,
        "differences": differences,
        "identical_fields": [k for k in all_keys if d1.get(k) == d2.get(k)],
    })


# ═══════════════════════════════════════════════════════════════
# JS-ANALYZE (deep JavaScript bundle analysis)
# ═══════════════════════════════════════════════════════════════

@cli.command("js-analyze")
@click.option("--secrets-only", is_flag=True, help="Only show secrets/tokens")
@click.option("--routes-only", is_flag=True, help="Only show routes and endpoints")
@click.pass_context
def js_analyze(ctx, secrets_only, routes_only):
    """Deep analysis of captured JavaScript bundles.

    Extracts: API endpoints, framework routes, GraphQL operations,
    secrets/tokens, internal hostnames, WebSocket URLs, fetch calls.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)
    analyzer = JSAnalyzer(store)

    console.print("[bold]Analyzing JavaScript bundles...[/bold]")
    results = analyzer.analyze_all()
    store.close()

    console.print(f"[green]{results['js_files_analyzed']} JS files analyzed[/green]")

    if secrets_only:
        output({"secrets": results["secrets"], "interesting_strings": results["interesting_strings"]})
    elif routes_only:
        output({
            "api_endpoints": results["api_endpoints"],
            "fetch_calls": results["fetch_calls"],
            "framework_routes": results["framework_routes"],
        })
    else:
        output(results)


# ═══════════════════════════════════════════════════════════════
# FINGERPRINT (response dedup & SPA detection)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--host", "-H", default=None, help="Filter by host")
@click.pass_context
def fingerprint(ctx, host):
    """Fingerprint responses by body hash to detect SPA catch-all patterns.

    Groups requests returning identical response bodies. If many different
    paths return the same HTML, it's a SPA serving a shell for client-side routing.
    These are NOT real server endpoints (e.g., /admin, /debug returning 200).
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)
    groups = store.get_response_fingerprints(host)
    store.close()

    for g in groups:
        if g["is_spa_catchall"]:
            console.print(f"[yellow]SPA catch-all detected:[/yellow] {g['count']} paths return same {g['response_length']}B body")
            console.print(f"  Paths: {', '.join(g['sample_paths'][:8])}...")

    output([{
        "body_hash": g["body_hash"],
        "count": g["count"],
        "is_spa_catchall": g["is_spa_catchall"],
        "response_length": g["response_length"],
        "status_codes": g["status_codes"],
        "sample_paths": g["sample_paths"][:15],
    } for g in groups])


# ═══════════════════════════════════════════════════════════════
# SUBDOMAINS (extract from all captured data)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.pass_context
def subdomains(ctx):
    """Extract all subdomains from captured traffic, JS, and headers."""
    db_path = get_db_path(ctx)
    store = Store(db_path)
    result = store.extract_subdomains()
    store.close()

    console.print(f"[bold]{len(result)} subdomains found[/bold]")
    output(result)


# ═══════════════════════════════════════════════════════════════
# PROTECTED (403 vs 404 anomaly detection)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--host", "-H", default=None, help="Filter by host")
@click.pass_context
def protected(ctx, host):
    """Find paths that return 403 (protected) while most unknowns return 404.

    These are real paths that exist on the server but are access-controlled.
    Worth investigating for auth bypass, path traversal, or misconfiguration.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)
    anomalies = store.get_status_anomalies(host)
    store.close()

    if anomalies:
        console.print(f"[yellow]{len(anomalies)} protected paths found[/yellow]")
    else:
        console.print("[dim]No 403/404 anomalies detected[/dim]")

    output(anomalies)


# ═══════════════════════════════════════════════════════════════
# AUDIT (AI-driven dynamic testing)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.option("--max-requests", "-n", default=500, help="Max fuzz requests to send")
@click.option("--delay", "-d", default=100, help="Delay between requests (ms)")
@click.option("--timeout", "-t", default=10.0, help="Request timeout (seconds)")
@click.option("--fast", is_flag=True, help="Fast mode: only SQLi, XSS, LFI, SSTI")
@click.option("--vuln", "-v", multiple=True, help="Specific vuln class (sqli, xss, ssrf, lfi, ssti, redirect, graphql, crlf)")
@click.option("--plan-only", is_flag=True, help="Show audit plan without executing")
@click.pass_context
def audit(ctx, max_requests, delay, timeout, fast, vuln, plan_only):
    """AI-driven dynamic security audit.

    Automatically identifies attack surface from captured traffic,
    generates a test plan, fuzzes parameters with payloads for SQLi/XSS/SSRF/LFI/SSTI,
    tests GraphQL introspection, and reports confirmed findings.

    \b
    Workflow:
      1. Reads captured traffic and JS analysis
      2. Identifies parameterized endpoints, API routes, GraphQL
      3. Generates payloads for each vuln class
      4. Sends fuzzed requests and analyzes responses
      5. Reports hits with confidence scoring
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    # Select vuln classes
    if vuln:
        classes = [get_class(v) for v in vuln]
        classes = [c for c in classes if c]
    elif fast:
        classes = FAST_CLASSES
    else:
        classes = ALL_CLASSES

    def on_finding(result):
        sev_color = {"high": "red bold", "medium": "yellow", "low": "cyan"}.get(result.confidence, "dim")
        console.print(f"  [{sev_color}][{result.confidence.upper()}][/] {result.vuln_class}: {result.hits[0]['description']}")
        console.print(f"    param={result.param} payload={result.payload[:60]}")

    def on_progress(msg):
        console.print(f"[dim]{msg}[/dim]")

    auditor = Auditor(
        store, timeout=timeout, delay_ms=delay,
        vuln_classes=classes, on_finding=on_finding, on_progress=on_progress,
    )

    plan = auditor.plan()

    if plan_only:
        store.close()
        output(plan.to_dict())
        return

    console.print(Panel.fit(
        f"[bold]Audit Plan[/bold]\n"
        f"Targets: [cyan]{len(plan.targets)}[/cyan]\n"
        f"Param targets: [cyan]{len(plan.param_targets)}[/cyan]\n"
        f"API endpoints: [cyan]{len(plan.api_endpoints)}[/cyan]\n"
        f"Path targets: [cyan]{len(plan.path_targets)}[/cyan]\n"
        f"GraphQL: [cyan]{len(plan.graphql_endpoints)}[/cyan]\n"
        f"Max requests: [cyan]{max_requests}[/cyan]\n"
        f"Vuln classes: [cyan]{', '.join(c['short'] for c in classes)}[/cyan]",
        title="Dynamic Audit",
    ))

    summary = auditor.run(plan, max_requests=max_requests)
    store.close()

    console.print(f"\n[bold green]Audit complete.[/bold green] {summary['total_requests_sent']} requests, {summary['total_hits']} hits")
    output(summary)


# ═══════════════════════════════════════════════════════════════
# FUZZ (targeted single-endpoint fuzzing)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("url")
@click.option("--param", "-p", default=None, help="Parameter name to fuzz")
@click.option("--vuln", "-v", default="sqli", help="Vuln class (sqli, xss, ssrf, lfi, ssti, crlf)")
@click.option("--delay", "-d", default=50, help="Delay between requests (ms)")
@click.pass_context
def fuzz(ctx, url, param, vuln, delay):
    """Fuzz a specific URL/parameter with a vuln class.

    \b
    Examples:
      webprobe fuzz "https://target.com/api?id=1" -p id -v sqli
      webprobe fuzz "https://target.com/search?q=test" -p q -v xss
      webprobe fuzz "https://target.com/api/users/1" -v lfi
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    vuln_config = get_class(vuln)
    if not vuln_config:
        console.print(f"[red]Unknown vuln class: {vuln}[/red]")
        store.close()
        return

    from .detect import Fuzzer
    fuzzer = Fuzzer(store, delay_ms=delay)

    def on_result(r):
        status_color = "green" if not r.hits else "red bold"
        hit_str = f" -> [{r.confidence.upper()}] {r.hits[0]['description']}" if r.hits else ""
        console.print(f"  [{status_color}]{r.response_status}[/] {r.payload[:50]} ({r.response_length}B, {r.response_time_ms:.0f}ms){hit_str}")

    console.print(f"[bold]Fuzzing[/bold] {url} param={param} class={vuln_config['name']}")
    results = fuzzer.fuzz_endpoint(url, vuln_config, param_name=param, on_result=on_result)
    store.close()

    hits = [r.to_dict() for r in results if r.hits]
    output({
        "total_payloads": len(results),
        "hits": len(hits),
        "findings": hits,
    })


# ═══════════════════════════════════════════════════════════════
# INTROSPECT (GraphQL schema discovery)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("url")
@click.pass_context
def introspect(ctx, url):
    """Run GraphQL introspection on a URL.

    Sends __schema queries to discover types, fields, queries, and mutations.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    from .detect import Fuzzer
    from .payloads import GRAPHQL_INTROSPECTION
    fuzzer = Fuzzer(store)

    def on_result(r):
        if r.hits:
            console.print(f"[green bold]Introspection ENABLED[/green bold] - schema returned")
        else:
            console.print(f"[dim]{r.response_status} ({r.response_length}B)[/dim]")

    console.print(f"[bold]GraphQL introspection:[/bold] {url}")
    results = fuzzer.fuzz_graphql(url, GRAPHQL_INTROSPECTION, on_result=on_result)
    store.close()

    hits = [r.to_dict() for r in results if r.hits]
    if hits:
        # Also output the raw schema response
        for r in results:
            if r.hits and r.response_body:
                try:
                    schema = json.loads(r.response_body)
                    output({"introspection_enabled": True, "schema": schema})
                    return
                except json.JSONDecodeError:
                    pass
    output({"introspection_enabled": bool(hits), "hits": hits})


# ═══════════════════════════════════════════════════════════════
# OIDC (OAuth/OpenID Connect testing)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("url")
@click.option("--client-id", default=None, help="OAuth client_id to use in tests")
@click.option("--timeout", "-t", default=10.0, help="Request timeout (seconds)")
@click.option("--phase", type=click.Choice(["discover", "grants", "userinfo", "redirect", "all"]),
              default="all", help="Run specific test phase only")
@click.pass_context
def oidc(ctx, url, client_id, timeout, phase):
    """Test OAuth/OIDC endpoints for misconfigurations.

    Probes well-known discovery endpoints, enumerates supported grant types
    via error message parsing, tests userinfo with fake tokens, and checks
    redirect_uri manipulation on the authorize endpoint.

    \b
    Phases:
      discover  - Probe .well-known endpoints
      grants    - Enumerate supported grant types
      userinfo  - Test /userinfo with fake bearer tokens
      redirect  - Test redirect_uri manipulation
      all       - Run all phases (default)

    \b
    Examples:
      webprobe oidc https://auth.target.com
      webprobe oidc https://target.com --client-id known_client_id
      webprobe oidc https://target.com --phase discover
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    tester = OIDCTester(store, url, timeout=timeout)

    if phase == "discover":
        console.print(f"[bold]OIDC Discovery:[/bold] {url}")
        result = tester.discover()
        found = len(result["endpoints_found"])
        console.print(f"[green]{found} endpoints found[/green]")
        store.close()
        output(result)

    elif phase == "grants":
        console.print(f"[bold]Grant Enumeration:[/bold] {url}")
        # Run discovery first to find token endpoint
        tester.discover()
        result = tester.enumerate_grants(client_id=client_id)
        console.print(f"Supported: [green]{', '.join(result['supported']) or 'none'}[/green]")
        console.print(f"Needs creds: [yellow]{', '.join(result['needs_credentials']) or 'none'}[/yellow]")
        console.print(f"Unsupported: [dim]{', '.join(result['unsupported']) or 'none'}[/dim]")
        store.close()
        output(result)

    elif phase == "userinfo":
        console.print(f"[bold]Userinfo Testing:[/bold] {url}")
        tester.discover()
        result = tester.test_userinfo()
        if result["findings"]:
            for f in result["findings"]:
                console.print(f"  [red bold][FINDING][/red bold] {f}")
        else:
            console.print("[dim]No userinfo issues found[/dim]")
        store.close()
        output(result)

    elif phase == "redirect":
        console.print(f"[bold]Redirect URI Testing:[/bold] {url}")
        tester.discover()
        result = tester.test_redirect_uri(client_id=client_id)
        vulns = [r for r in result if r.get("vulnerable")]
        if vulns:
            for v in vulns:
                console.print(f"  [red bold][VULN][/red bold] {v['redirect_uri']} -> {v.get('vuln_type', 'unknown')}")
        else:
            console.print("[dim]No redirect_uri manipulation found[/dim]")
        store.close()
        output(result)

    else:  # all
        console.print(Panel.fit(
            f"[bold green]OIDC Security Audit[/bold green]\n"
            f"Target: [cyan]{url}[/cyan]\n"
            f"Client ID: [cyan]{client_id or 'test_client'}[/cyan]\n"
            f"Phases: discovery, grants, userinfo, redirect_uri",
            title="OAuth/OIDC Tester",
        ))

        result = tester.run_all(client_id=client_id)

        # Print summary
        total = result["summary"]["total_findings"]
        by_sev = result["summary"]["findings_by_severity"]
        console.print(f"\n[bold green]OIDC audit complete.[/bold green] "
                      f"{result['summary']['total_requests']} requests, {total} findings")
        if by_sev.get("critical"):
            console.print(f"  [red bold]Critical: {by_sev['critical']}[/red bold]")
        if by_sev.get("high"):
            console.print(f"  [red]High: {by_sev['high']}[/red]")
        if by_sev.get("medium"):
            console.print(f"  [yellow]Medium: {by_sev['medium']}[/yellow]")

        for kf in result["summary"]["key_findings"]:
            console.print(f"  [{('red bold' if kf['severity'] == 'critical' else 'red')}]"
                          f"[{kf['severity'].upper()}][/] {kf['title']}")

        store.close()
        output(result)


# ═══════════════════════════════════════════════════════════════
# CLOUD (cloud storage security testing)
# ═══════════════════════════════════════════════════════════════

@cli.command()
@click.argument("url")
@click.option("--timeout", "-t", default=10, help="Request timeout (seconds)")
@click.option("--skip-upload", is_flag=True, help="Skip write/upload tests")
@click.option("--skip-js", is_flag=True, help="Skip JS SAS token scan")
@click.pass_context
def cloud(ctx, url, timeout, skip_upload, skip_js):
    """Enumerate cloud storage (Azure Blob, S3, GCS) for misconfigurations.

    \b
    Auto-detects cloud provider from URL and runs:
      - Container/bucket listing test
      - Container existence oracle (Azure BlobNotFound vs ContainerNotFound)
      - Unauthenticated upload test
      - Tenant ID extraction (Azure 401 headers)
      - Metadata access check
      - SAS token / presigned URL scan in captured JS

    \b
    Examples:
      webprobe cloud "https://account.blob.core.windows.net"
      webprobe cloud "https://account.blob.core.usgovcloudapi.net"
      webprobe cloud "https://mybucket.s3.amazonaws.com"
      webprobe cloud "https://storage.googleapis.com/mybucket"
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)
    tester = CloudTester(store, timeout=timeout)

    provider = tester.detect_provider(url)
    console.print(Panel.fit(
        f"[bold green]Cloud Storage Audit[/bold green]\n"
        f"URL: [cyan]{url}[/cyan]\n"
        f"Provider: [cyan]{provider}[/cyan]\n"
        f"Timeout: [cyan]{timeout}s[/cyan]",
        title="Cloud Tester",
    ))

    try:
        if provider == "azure":
            console.print("[bold]Running Azure Blob Storage audit...[/bold]")
            result = tester.test_azure(url)
        elif provider == "aws":
            console.print("[bold]Running S3 bucket audit...[/bold]")
            result = tester.test_s3(url)
        elif provider == "gcp":
            console.print("[bold]Running GCS bucket audit...[/bold]")
            result = tester.test_gcs(url)
        else:
            console.print(f"[yellow]Unknown provider for URL. Running auto-detect...[/yellow]")
            result = tester.run_all(url)

        # JS SAS token scan
        sas_tokens = []
        if not skip_js:
            console.print("[dim]Scanning captured JS for cloud credentials...[/dim]")
            sas_tokens = tester.scan_js_for_sas_tokens()
            result["sas_tokens_in_js"] = sas_tokens

        # Print summary
        findings = result.get("findings", [])
        if findings:
            console.print(f"\n[bold]{len(findings)} findings:[/bold]")
            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
            for f in findings:
                console.print(f"  [{sev_colors.get(f['severity'], 'white')}][{f['severity'].upper()}][/] {f['title']}")
        else:
            console.print("\n[dim]No findings.[/dim]")

        if sas_tokens:
            console.print(f"[red]{len(sas_tokens)} cloud credentials found in JS[/red]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Cloud audit interrupted.[/yellow]")
    finally:
        tester.close()
        store.close()

    output(result)


# ═══════════════════════════════════════════════════════════════
# CDN (CDN/WAF fingerprinting)
# ═══════════════════════════════════════════════════════════════

@cli.command("cdn")
@click.argument("url")
@click.pass_context
def cdn_fingerprint(ctx, url):
    """Fingerprint CDN/WAF behavior for a URL.

    Tests: query param handling, method filtering, cache behavior,
    path whitelisting, CDN provider identification.

    \b
    Critical for attack planning: if CDN strips query params,
    filter injection attacks are useless regardless of backend vulns.
    """
    db_path = get_db_path(ctx)
    store = Store(db_path)

    from .cdn import CDNFingerprinter
    fp = CDNFingerprinter(store)

    console.print(f"[bold]CDN/WAF fingerprinting:[/bold] {url}")
    result = fp.fingerprint(url)
    store.close()

    if result.get("cdn_provider"):
        console.print(f"  CDN: [cyan]{result['cdn_provider']}[/cyan]")
    if result.get("waf_detected"):
        console.print(f"  WAF: [yellow]{', '.join(result['waf_detected'])}[/yellow]")
    if result.get("query_params_stripped"):
        console.print(f"  [red bold]Query params stripped by CDN - injection attacks will not reach backend[/red bold]")
    if result.get("methods_blocked"):
        console.print(f"  Blocked methods: [yellow]{', '.join(result['methods_blocked'])}[/yellow]")

    output(result)


# ═══════════════════════════════════════════════════════════════
# CORS-VERIFY (confirm CORS misconfigs)
# ═══════════════════════════════════════════════════════════════

@cli.command("cors-verify")
@click.argument("url")
@click.pass_context
def cors_verify(ctx, url):
    """Verify CORS misconfiguration by sending requests with arbitrary Origin.

    Tests if the server reflects any Origin in Access-Control-Allow-Origin,
    and whether credentials are allowed.
    """
    import httpx as _httpx
    db_path = get_db_path(ctx)
    store = Store(db_path)

    test_origins = [
        "https://evil.com",
        "https://attacker.spacex.com.evil.com",
        "null",
    ]

    results = []
    for origin in test_origins:
        try:
            with _httpx.Client(verify=False, timeout=10) as client:
                resp = client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                reflected = acao == origin
                vuln = reflected and acac.lower() == "true"
                result = {
                    "origin_sent": origin,
                    "acao": acao,
                    "acac": acac,
                    "reflected": reflected,
                    "credentials_allowed": acac.lower() == "true",
                    "vulnerable": vuln,
                }
                results.append(result)

                marker = "[red bold]VULNERABLE" if vuln else "[yellow]reflected" if reflected else "[green]safe"
                console.print(f"  Origin: {origin} -> ACAO: {acao} ACAC: {acac} [{marker}[/]")

                if reflected:
                    from urllib.parse import urlparse
                    p = urlparse(url)
                    rid = store.insert_request(
                        method="GET", url=url, scheme=p.scheme,
                        host=p.hostname or "", port=p.port or 443,
                        path=p.path, query=p.query or "",
                        request_headers=json.dumps({"Origin": origin}),
                        request_body=b"", request_content_type="",
                        response_status=resp.status_code, response_reason="",
                        response_headers=json.dumps(dict(resp.headers)),
                        response_body=b"", response_content_type="",
                        response_length=len(resp.content),
                        duration_ms=0, source="cors_verify",
                        tags=json.dumps(["cors", "verify"]),
                    )
                    sev = "high" if vuln else "medium"
                    store.insert_finding(
                        request_id=rid, category="cors",
                        severity=sev,
                        title=f"CORS reflects arbitrary origin: {origin}",
                        detail=f"Server reflects Origin header. Credentials: {acac}",
                        evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                    )
        except Exception as e:
            results.append({"origin_sent": origin, "error": str(e)})

    store.close()
    output(results)


if __name__ == "__main__":
    cli()
