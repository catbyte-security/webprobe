# webprobe — Black-Box Web Security Recon for Bug Bounty

A web security analysis toolkit built for AI-driven bug bounty workflows. Intercept, crawl, analyze, and replay HTTP traffic — all output is JSON for piping into AI agents or automation scripts.

Identifies SSRF, XXE, OIDC misconfigurations, cloud metadata exposure, JavaScript vulnerabilities, and common web security issues through passive traffic analysis and active probing.

## Features

- **Intercepting proxy** — Capture all HTTP/S traffic via mitmdump, stored in SQLite for analysis
- **Crawler** — Spider targets to discover endpoints, forms, and API routes
- **Passive analysis** — Scan captured traffic for security headers, CSP issues, CORS misconfigs, sensitive data exposure, technology fingerprinting
- **SSRF/XXE detection** — Test for server-side request forgery and XML external entity injection
- **Cloud metadata** — Detect exposed cloud provider metadata endpoints (AWS, GCP, Azure)
- **OIDC testing** — Probe OpenID Connect configurations for misconfigurations
- **JavaScript analysis** — Extract secrets, API keys, endpoints, and interesting patterns from JS files
- **CDN analysis** — Identify CDN providers and potential origin IP leaks
- **Request replay** — Replay captured requests with modifications for manual testing
- **Payload library** — Built-in payload classes for SSRF, XSS, SQLi, path traversal, and more

## Install

```bash
git clone https://github.com/catbyte-security/webprobe.git
cd webprobe
pip install -e .
```

**Requirements:** Python 3.10+, mitmproxy (for proxy mode)

## Quick Start

```bash
# Start intercepting proxy
webprobe proxy --port 8080

# Crawl a target
webprobe crawl https://target.example.com --depth 3

# Analyze captured traffic
webprobe analyze --db webprobe.db

# Run full audit
webprobe audit https://target.example.com

# Test for SSRF
webprobe ssrf https://target.example.com/api/fetch?url=

# Check cloud metadata exposure
webprobe cloud https://target.example.com

# OIDC configuration analysis
webprobe oidc https://target.example.com

# Analyze JavaScript files for secrets
webprobe js https://target.example.com/app.js

# Replay a captured request with modifications
webprobe replay --id 42 --header "Authorization: Bearer token"
```

## Output

All commands output JSON to stdout, making it easy to pipe into other tools or AI agents:

```bash
# Pipe into jq
webprobe analyze --db webprobe.db | jq '.findings[] | select(.severity == "high")'

# Save results
webprobe audit https://target.example.com > results.json
```

## Architecture

```
webprobe/
  cli.py          # Click CLI interface
  store.py        # SQLite storage layer for captured traffic
  analyze.py      # Passive analysis engine (headers, CSP, CORS, tech fingerprinting)
  audit.py        # Active security auditing
  crawler.py      # Web spider
  proxy.py        # mitmproxy integration
  proxy_addon.py  # mitmdump addon for traffic capture
  cloud.py        # Cloud metadata exposure testing
  oidc.py         # OpenID Connect testing
  js_analyze.py   # JavaScript static analysis
  detect.py       # Vulnerability detection engine
  cdn.py          # CDN identification
  payloads.py     # Payload library (SSRF, XSS, SQLi, traversal)
  replay.py       # Request replay engine
```

## License

MIT
