"""Replay captured requests with optional modifications."""

import json
import time
from urllib.parse import urlparse

import httpx

from .store import Store


def replay_request(
    store: Store,
    request_id: int,
    modify_headers: dict = None,
    modify_params: dict = None,
    modify_body: str = None,
    modify_method: str = None,
    modify_url: str = None,
    follow_redirects: bool = False,
    verify_ssl: bool = False,
    timeout: float = 15.0,
) -> dict:
    """Replay a captured request and store the result."""
    req = store.get_request(request_id)
    if not req:
        return {"error": f"Request {request_id} not found"}

    method = modify_method or req["method"]
    url = modify_url or req["url"]
    headers = json.loads(req.get("request_headers") or "{}")
    body = req.get("request_body")

    # Apply header modifications
    if modify_headers:
        for k, v in modify_headers.items():
            if v is None:
                headers.pop(k, None)
            else:
                headers[k] = v

    # Remove hop-by-hop headers
    for h in ("host", "content-length", "transfer-encoding", "connection"):
        headers.pop(h, None)
        headers.pop(h.title(), None)

    # Apply param modifications (query string)
    if modify_params:
        parsed = urlparse(url)
        from urllib.parse import parse_qs, urlencode
        params = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in modify_params.items():
            params[k] = [v]
        new_query = urlencode(params, doseq=True)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    # Apply body modification
    if modify_body is not None:
        if isinstance(modify_body, str):
            body = modify_body.encode()
        else:
            body = modify_body

    start = time.time()
    try:
        with httpx.Client(verify=verify_ssl, timeout=timeout, follow_redirects=follow_redirects) as client:
            resp = client.request(
                method=method,
                url=url,
                headers=headers,
                content=body if body else None,
            )
    except Exception as e:
        return {"error": str(e), "original_request_id": request_id}

    duration = (time.time() - start) * 1000
    parsed = urlparse(str(resp.url))

    resp_body = resp.content
    if len(resp_body) > 512 * 1024:
        resp_body = resp_body[:512 * 1024]

    new_id = store.insert_request(
        method=method,
        url=str(resp.url),
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        path=parsed.path,
        query=parsed.query,
        request_headers=json.dumps(dict(resp.request.headers)),
        request_body=body or b"",
        request_content_type=headers.get("content-type", ""),
        response_status=resp.status_code,
        response_reason=resp.reason_phrase,
        response_headers=json.dumps(dict(resp.headers)),
        response_body=resp_body,
        response_content_type=resp.headers.get("content-type", ""),
        response_length=len(resp.content),
        duration_ms=round(duration, 2),
        source="replay",
        tags=json.dumps(["replay", f"from:{request_id}"]),
    )

    return {
        "replay_id": new_id,
        "original_id": request_id,
        "method": method,
        "url": str(resp.url),
        "status": resp.status_code,
        "response_length": len(resp.content),
        "duration_ms": round(duration, 2),
        "response_headers": dict(resp.headers),
        "response_body_preview": resp.text[:2000] if resp.text else "",
    }
