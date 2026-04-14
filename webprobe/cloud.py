"""Cloud storage security testing - Azure Blob, AWS S3, GCP GCS misconfigurations."""

import json
import re
import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from .store import Store


COMMON_CONTAINERS = [
    "cms-assets", "uploads", "media", "images", "static", "assets",
    "public", "backup", "backups", "logs", "data", "content", "dev",
    "staging", "test", "private", "temp", "config", "documents", "exports",
]

AZURE_API_VERSIONS = [
    "2023-11-03",
    "2023-01-03",
    "2022-11-02",
    "2021-12-02",
    "2021-08-06",
    "2020-10-02",
    "2019-07-07",
]

# SAS token patterns
SAS_TOKEN_RE = re.compile(
    r'[?&]sv=\d{4}-\d{2}-\d{2}[^"\'`\s<>}{)(\]]*sig=[^"\'`\s<>}{)(\]]+',
    re.IGNORECASE,
)
AWS_PRESIGNED_RE = re.compile(
    r'X-Amz-Signature=[0-9a-f]{64}',
    re.IGNORECASE,
)
GCS_SIGNED_RE = re.compile(
    r'Expires=\d+&[^"\'`\s]*Signature=[^"\'`\s<>}{)(\]]+',
    re.IGNORECASE,
)


class CloudTester:
    """Automated cloud storage security testing for Azure Blob, S3, and GCS."""

    def __init__(self, store: Store, timeout: int = 10, verify_ssl: bool = False):
        self.store = store
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client = httpx.Client(
            verify=verify_ssl,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "webprobe/0.1"},
        )

    def close(self):
        self._client.close()

    # ── Provider Detection ───────────────────────────────────

    def detect_provider(self, url: str) -> str:
        """Detect cloud provider from URL pattern: azure, aws, gcp, or unknown."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""

        # Azure: *.blob.core.windows.net, *.blob.core.usgovcloudapi.net, *.azureedge.net
        if re.search(r'\.blob\.core\.(windows\.net|usgovcloudapi\.net|chinacloudapi\.cn)', host):
            return "azure"
        if host.endswith(".azureedge.net"):
            return "azure"

        # AWS S3: *.s3.amazonaws.com, s3.*.amazonaws.com, *.s3-*.amazonaws.com
        if re.search(r'\.s3[.-].*\.amazonaws\.com$', host):
            return "aws"
        if re.search(r'^s3[.-].*\.amazonaws\.com$', host):
            return "aws"
        if host.endswith(".s3.amazonaws.com"):
            return "aws"

        # GCP: storage.googleapis.com, *.storage.googleapis.com
        if host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
            return "gcp"

        return "unknown"

    # ── HTTP Helpers ─────────────────────────────────────────

    def _request(self, method: str, url: str, headers: dict = None,
                 content: bytes = None, source_tag: str = "cloud") -> dict:
        """Make a request and store it in the database. Returns result dict."""
        req_headers = dict(self._client.headers)
        if headers:
            req_headers.update(headers)

        start = time.time()
        try:
            resp = self._client.request(
                method=method,
                url=url,
                headers=headers or {},
                content=content,
            )
        except httpx.TimeoutException:
            return {"error": "timeout", "url": url, "method": method}
        except Exception as e:
            return {"error": str(e), "url": url, "method": method}

        duration = (time.time() - start) * 1000
        parsed = urlparse(str(resp.url))

        resp_body = resp.content
        if len(resp_body) > 512 * 1024:
            resp_body = resp_body[:512 * 1024]

        req_id = self.store.insert_request(
            method=method,
            url=url,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.path,
            query=parsed.query,
            request_headers=json.dumps(req_headers),
            request_body=content or b"",
            request_content_type=req_headers.get("content-type", ""),
            response_status=resp.status_code,
            response_reason=resp.reason_phrase,
            response_headers=json.dumps(dict(resp.headers)),
            response_body=resp_body,
            response_content_type=resp.headers.get("content-type", ""),
            response_length=len(resp.content),
            duration_ms=round(duration, 2),
            source="cloud",
            tags=json.dumps(["cloud", source_tag]),
        )

        return {
            "request_id": req_id,
            "method": method,
            "url": url,
            "status": resp.status_code,
            "reason": resp.reason_phrase,
            "response_length": len(resp.content),
            "duration_ms": round(duration, 2),
            "response_headers": dict(resp.headers),
            "response_body": resp.text[:4000] if resp.text else "",
        }

    # ── Azure Blob Storage ───────────────────────────────────

    def test_azure(self, storage_url: str) -> dict:
        """Full Azure blob storage security audit."""
        parsed = urlparse(storage_url)
        base = f"{parsed.scheme}://{parsed.hostname}"
        results = {
            "provider": "azure",
            "storage_url": storage_url,
            "base_url": base,
            "container_listing": None,
            "container_enumeration": [],
            "upload_test": None,
            "tenant_id": None,
            "metadata_access": [],
            "findings": [],
        }

        # 1. Container listing (comp=list with various API versions)
        results["container_listing"] = self._azure_container_list(base)

        # 2. Container enumeration via error code oracle
        results["container_enumeration"] = self._azure_enumerate_containers(base)

        # 3. Upload test on discovered containers
        results["upload_test"] = self._azure_upload_test(base, results["container_enumeration"])

        # 4. Tenant ID extraction from 401 responses
        results["tenant_id"] = self._azure_extract_tenant(base)

        # 5. Metadata access on discovered containers
        results["metadata_access"] = self._azure_metadata_check(base, results["container_enumeration"])

        # Generate findings
        self._azure_generate_findings(results)

        return results

    def _azure_container_list(self, base_url: str) -> dict:
        """Test account-level container listing."""
        listing_result = {
            "accessible": False,
            "api_versions_tested": [],
            "containers_found": [],
        }

        for api_ver in AZURE_API_VERSIONS:
            url = f"{base_url}/?comp=list&restype=container&maxresults=100"
            resp = self._request(
                "GET", url,
                headers={"x-ms-version": api_ver},
                source_tag="azure-container-list",
            )
            listing_result["api_versions_tested"].append({
                "version": api_ver,
                "status": resp.get("status"),
                "error": resp.get("error"),
            })

            if resp.get("status") == 200:
                listing_result["accessible"] = True
                body = resp.get("response_body", "")
                # Parse container names from XML response
                containers = re.findall(r'<Name>([^<]+)</Name>', body)
                listing_result["containers_found"] = containers
                break  # Found a working version

        return listing_result

    def _azure_enumerate_containers(self, base_url: str) -> list:
        """Enumerate containers using error code differences.

        BlobNotFound = container exists but blob doesn't
        ContainerNotFound / ResourceNotFound = container doesn't exist
        """
        found = []
        for name in COMMON_CONTAINERS:
            # Request a nonexistent blob to differentiate container existence
            url = f"{base_url}/{name}/webprobe-test-{uuid.uuid4().hex[:8]}.txt"
            resp = self._request(
                "GET", url,
                headers={"x-ms-version": "2023-11-03"},
                source_tag="azure-enum",
            )

            if resp.get("error"):
                found.append({
                    "container": name,
                    "status": "error",
                    "detail": resp["error"],
                })
                continue

            status = resp.get("status", 0)
            body = resp.get("response_body", "")

            entry = {
                "container": name,
                "status": status,
                "exists": False,
                "public_access": False,
            }

            if status == 404:
                # Check error code in XML body
                error_code = ""
                m = re.search(r'<Code>([^<]+)</Code>', body)
                if m:
                    error_code = m.group(1)
                entry["error_code"] = error_code

                if error_code == "BlobNotFound":
                    # Container exists, blob doesn't
                    entry["exists"] = True
                elif error_code in ("ContainerNotFound", "ResourceNotFound"):
                    entry["exists"] = False
                else:
                    entry["exists"] = None  # Ambiguous

            elif status == 200:
                entry["exists"] = True
                entry["public_access"] = True

            elif status == 403:
                # Container exists but not publicly accessible
                entry["exists"] = True

            found.append(entry)

        return found

    def _azure_upload_test(self, base_url: str, enumeration: list) -> dict:
        """Test if PUT uploads work without auth on discovered containers."""
        upload_result = {
            "tested": False,
            "writable_containers": [],
        }

        # Get existing containers
        existing = [e["container"] for e in enumeration
                    if e.get("exists") is True]

        if not existing:
            # Try public and uploads anyway
            existing = ["public", "uploads"]

        for container in existing:
            test_blob = f"webprobe-write-test-{uuid.uuid4().hex[:8]}.txt"
            url = f"{base_url}/{container}/{test_blob}"
            resp = self._request(
                "PUT", url,
                headers={
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-version": "2023-11-03",
                    "Content-Type": "text/plain",
                },
                content=b"webprobe upload test",
                source_tag="azure-upload-test",
            )
            upload_result["tested"] = True

            if resp.get("status") == 201:
                upload_result["writable_containers"].append({
                    "container": container,
                    "blob": test_blob,
                    "url": url,
                    "status": resp["status"],
                })

        return upload_result

    def _azure_extract_tenant(self, base_url: str) -> dict:
        """Extract tenant ID from 401 www-authenticate header."""
        tenant_result = {
            "found": False,
            "tenant_id": None,
            "auth_resource": None,
        }

        url = f"{base_url}/?comp=list&restype=container"
        resp = self._request(
            "GET", url,
            headers={"x-ms-version": "2023-11-03"},
            source_tag="azure-tenant-extract",
        )

        if resp.get("error"):
            return tenant_result

        headers = resp.get("response_headers", {})
        www_auth = headers.get("www-authenticate", "")
        if not www_auth:
            # Also check lowercase variants
            for k, v in headers.items():
                if k.lower() == "www-authenticate":
                    www_auth = v
                    break

        if www_auth:
            # Extract tenant ID from Bearer authorization_uri
            m = re.search(
                r'authorization_uri="https://login\.microsoftonline\.com/([0-9a-f-]+)',
                www_auth,
            )
            if m:
                tenant_result["found"] = True
                tenant_result["tenant_id"] = m.group(1)

            # Also try the resource_id
            m2 = re.search(r'resource_id="([^"]+)"', www_auth)
            if m2:
                tenant_result["auth_resource"] = m2.group(1)

        tenant_result["www_authenticate"] = www_auth
        return tenant_result

    def _azure_metadata_check(self, base_url: str, enumeration: list) -> list:
        """Check blob metadata access on discovered containers."""
        results = []
        existing = [e["container"] for e in enumeration
                    if e.get("exists") is True]

        for container in existing:
            url = f"{base_url}/{container}?restype=container&comp=metadata"
            resp = self._request(
                "GET", url,
                headers={"x-ms-version": "2023-11-03"},
                source_tag="azure-metadata",
            )

            entry = {
                "container": container,
                "status": resp.get("status"),
                "accessible": resp.get("status") == 200,
                "metadata": {},
            }

            if resp.get("status") == 200:
                # Extract x-ms-meta-* headers
                for k, v in resp.get("response_headers", {}).items():
                    if k.lower().startswith("x-ms-meta-"):
                        entry["metadata"][k] = v

            results.append(entry)

        return results

    def _azure_generate_findings(self, results: dict):
        """Generate security findings from Azure test results."""
        findings = results["findings"]

        # Container listing open
        if results["container_listing"]["accessible"]:
            count = len(results["container_listing"]["containers_found"])
            findings.append({
                "severity": "high",
                "title": "Azure container listing publicly accessible",
                "detail": f"Account-level container listing is open. {count} containers exposed.",
                "evidence": ", ".join(results["container_listing"]["containers_found"][:20]),
            })

        # Public containers
        for entry in results["container_enumeration"]:
            if entry.get("public_access"):
                findings.append({
                    "severity": "high",
                    "title": f"Azure container '{entry['container']}' has public read access",
                    "detail": "Container contents are readable without authentication.",
                    "evidence": f"GET /{entry['container']}/... returned 200",
                })
            elif entry.get("exists") is True and not entry.get("public_access"):
                findings.append({
                    "severity": "info",
                    "title": f"Azure container '{entry['container']}' exists (not public)",
                    "detail": "Container exists but requires authentication. Error oracle confirmed.",
                    "evidence": f"BlobNotFound vs ContainerNotFound differentiation",
                })

        # Writable containers
        if results["upload_test"].get("writable_containers"):
            for wc in results["upload_test"]["writable_containers"]:
                findings.append({
                    "severity": "critical",
                    "title": f"Azure container '{wc['container']}' allows unauthenticated writes",
                    "detail": "PUT upload succeeded without credentials. Attacker can upload arbitrary content.",
                    "evidence": f"PUT {wc['url']} -> 201 Created",
                })

        # Tenant ID leaked
        if results["tenant_id"].get("found"):
            findings.append({
                "severity": "low",
                "title": "Azure tenant ID disclosed",
                "detail": f"Tenant ID: {results['tenant_id']['tenant_id']}",
                "evidence": results["tenant_id"].get("www_authenticate", ""),
            })

        # Metadata accessible
        for entry in results["metadata_access"]:
            if entry.get("accessible"):
                findings.append({
                    "severity": "medium",
                    "title": f"Azure container '{entry['container']}' metadata accessible",
                    "detail": "Container metadata is readable without authentication.",
                    "evidence": json.dumps(entry.get("metadata", {})),
                })

        # Store findings in DB
        for f in findings:
            self.store.insert_finding(
                request_id=0,
                category="cloud-azure",
                severity=f["severity"],
                title=f["title"],
                detail=f["detail"],
                evidence=f.get("evidence", ""),
            )

    # ── AWS S3 ───────────────────────────────────────────────

    def test_s3(self, bucket_url: str) -> dict:
        """Full S3 bucket security audit."""
        parsed = urlparse(bucket_url)
        host = parsed.hostname or ""

        # Determine bucket name and base URL
        bucket_name = ""
        if host.endswith(".s3.amazonaws.com"):
            bucket_name = host.replace(".s3.amazonaws.com", "")
            base = f"{parsed.scheme}://{host}"
        elif ".s3-" in host or ".s3." in host:
            bucket_name = host.split(".s3")[0]
            base = f"{parsed.scheme}://{host}"
        else:
            base = f"{parsed.scheme}://{host}"
            bucket_name = host.split(".")[0]

        results = {
            "provider": "aws",
            "bucket_url": bucket_url,
            "bucket_name": bucket_name,
            "base_url": base,
            "listing": None,
            "acl": None,
            "upload_test": None,
            "findings": [],
        }

        # 1. Bucket listing (GET /)
        results["listing"] = self._s3_list_bucket(base)

        # 2. ACL check (GET /?acl)
        results["acl"] = self._s3_check_acl(base)

        # 3. Upload test (PUT)
        results["upload_test"] = self._s3_upload_test(base)

        # Generate findings
        self._s3_generate_findings(results)

        return results

    def _s3_list_bucket(self, base_url: str) -> dict:
        """Test bucket listing."""
        result = {"accessible": False, "objects": []}

        url = f"{base_url}/?list-type=2&max-keys=50"
        resp = self._request("GET", url, source_tag="s3-list")

        if resp.get("status") == 200:
            body = resp.get("response_body", "")
            if "<Contents>" in body or "<ListBucketResult" in body:
                result["accessible"] = True
                keys = re.findall(r'<Key>([^<]+)</Key>', body)
                result["objects"] = keys[:50]

        result["status"] = resp.get("status")
        return result

    def _s3_check_acl(self, base_url: str) -> dict:
        """Check bucket ACL."""
        result = {"accessible": False, "grants": []}

        url = f"{base_url}/?acl"
        resp = self._request("GET", url, source_tag="s3-acl")

        if resp.get("status") == 200:
            body = resp.get("response_body", "")
            result["accessible"] = True

            # Parse grants from XML
            grants = re.findall(
                r'<Grant>.*?<URI>([^<]*)</URI>.*?<Permission>([^<]+)</Permission>.*?</Grant>',
                body,
                re.DOTALL,
            )
            for uri, perm in grants:
                result["grants"].append({"grantee": uri, "permission": perm})

            # Check for AllUsers or AuthenticatedUsers
            if "AllUsers" in body:
                result["public_access"] = True
            if "AuthenticatedUsers" in body:
                result["authenticated_access"] = True

        result["status"] = resp.get("status")
        return result

    def _s3_upload_test(self, base_url: str) -> dict:
        """Test upload to bucket."""
        result = {"writable": False}

        test_key = f"webprobe-write-test-{uuid.uuid4().hex[:8]}.txt"
        url = f"{base_url}/{test_key}"
        resp = self._request(
            "PUT", url,
            headers={"Content-Type": "text/plain"},
            content=b"webprobe upload test",
            source_tag="s3-upload-test",
        )

        if resp.get("status") == 200:
            result["writable"] = True
            result["key"] = test_key

        result["status"] = resp.get("status")
        return result

    def _s3_generate_findings(self, results: dict):
        """Generate findings from S3 audit."""
        findings = results["findings"]

        if results["listing"]["accessible"]:
            count = len(results["listing"]["objects"])
            findings.append({
                "severity": "high",
                "title": f"S3 bucket listing accessible ({results['bucket_name']})",
                "detail": f"Bucket listing is open. {count} objects visible.",
                "evidence": ", ".join(results["listing"]["objects"][:10]),
            })

        if results["acl"]["accessible"]:
            grants_desc = "; ".join(
                f"{g['grantee']} -> {g['permission']}"
                for g in results["acl"]["grants"]
            )
            sev = "high" if results["acl"].get("public_access") else "medium"
            findings.append({
                "severity": sev,
                "title": f"S3 bucket ACL readable ({results['bucket_name']})",
                "detail": f"Bucket ACL is accessible. Grants: {grants_desc or 'none parsed'}",
                "evidence": grants_desc,
            })

        if results["upload_test"]["writable"]:
            findings.append({
                "severity": "critical",
                "title": f"S3 bucket writable ({results['bucket_name']})",
                "detail": "PUT upload succeeded without credentials.",
                "evidence": f"PUT /{results['upload_test']['key']} -> 200",
            })

        for f in findings:
            self.store.insert_finding(
                request_id=0,
                category="cloud-s3",
                severity=f["severity"],
                title=f["title"],
                detail=f["detail"],
                evidence=f.get("evidence", ""),
            )

    # ── GCP GCS ──────────────────────────────────────────────

    def test_gcs(self, bucket_url: str) -> dict:
        """Full GCS bucket security audit."""
        parsed = urlparse(bucket_url)
        host = parsed.hostname or ""

        # Determine bucket name
        if host == "storage.googleapis.com":
            # Path-style: storage.googleapis.com/BUCKET
            bucket_name = parsed.path.strip("/").split("/")[0] if parsed.path else ""
            base = f"{parsed.scheme}://{host}/{bucket_name}"
        elif host.endswith(".storage.googleapis.com"):
            bucket_name = host.replace(".storage.googleapis.com", "")
            base = f"{parsed.scheme}://{host}"
        else:
            bucket_name = host.split(".")[0]
            base = f"{parsed.scheme}://{host}"

        results = {
            "provider": "gcp",
            "bucket_url": bucket_url,
            "bucket_name": bucket_name,
            "base_url": base,
            "listing": None,
            "iam": None,
            "upload_test": None,
            "findings": [],
        }

        # 1. Bucket listing via JSON API
        results["listing"] = self._gcs_list_bucket(bucket_name)

        # 2. IAM policy check
        results["iam"] = self._gcs_check_iam(bucket_name)

        # 3. Upload test
        results["upload_test"] = self._gcs_upload_test(bucket_name)

        # Generate findings
        self._gcs_generate_findings(results)

        return results

    def _gcs_list_bucket(self, bucket_name: str) -> dict:
        """Test bucket listing via GCS JSON API."""
        result = {"accessible": False, "objects": []}

        url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o?maxResults=50"
        resp = self._request("GET", url, source_tag="gcs-list")

        if resp.get("status") == 200:
            body = resp.get("response_body", "")
            try:
                data = json.loads(body)
                if "items" in data:
                    result["accessible"] = True
                    result["objects"] = [
                        item.get("name", "") for item in data["items"]
                    ]
            except (json.JSONDecodeError, KeyError):
                if '"kind": "storage#objects"' in body:
                    result["accessible"] = True

        result["status"] = resp.get("status")
        return result

    def _gcs_check_iam(self, bucket_name: str) -> dict:
        """Check bucket IAM policy."""
        result = {"accessible": False, "bindings": []}

        url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/iam"
        resp = self._request("GET", url, source_tag="gcs-iam")

        if resp.get("status") == 200:
            body = resp.get("response_body", "")
            try:
                data = json.loads(body)
                result["accessible"] = True
                result["bindings"] = data.get("bindings", [])
                # Check for allUsers / allAuthenticatedUsers
                for binding in result["bindings"]:
                    members = binding.get("members", [])
                    if "allUsers" in members:
                        result["public_access"] = True
                    if "allAuthenticatedUsers" in members:
                        result["authenticated_access"] = True
            except (json.JSONDecodeError, KeyError):
                pass

        result["status"] = resp.get("status")
        return result

    def _gcs_upload_test(self, bucket_name: str) -> dict:
        """Test upload to GCS bucket."""
        result = {"writable": False}

        test_name = f"webprobe-write-test-{uuid.uuid4().hex[:8]}.txt"
        url = (
            f"https://storage.googleapis.com/upload/storage/v1/b/{bucket_name}/o"
            f"?uploadType=media&name={test_name}"
        )
        resp = self._request(
            "POST", url,
            headers={"Content-Type": "text/plain"},
            content=b"webprobe upload test",
            source_tag="gcs-upload-test",
        )

        if resp.get("status") == 200:
            result["writable"] = True
            result["object_name"] = test_name

        result["status"] = resp.get("status")
        return result

    def _gcs_generate_findings(self, results: dict):
        """Generate findings from GCS audit."""
        findings = results["findings"]

        if results["listing"]["accessible"]:
            count = len(results["listing"]["objects"])
            findings.append({
                "severity": "high",
                "title": f"GCS bucket listing accessible ({results['bucket_name']})",
                "detail": f"Bucket listing is open. {count} objects visible.",
                "evidence": ", ".join(results["listing"]["objects"][:10]),
            })

        if results["iam"]["accessible"]:
            sev = "high" if results["iam"].get("public_access") else "medium"
            bindings_desc = json.dumps(results["iam"]["bindings"][:5])
            findings.append({
                "severity": sev,
                "title": f"GCS bucket IAM policy readable ({results['bucket_name']})",
                "detail": f"IAM policy is publicly accessible.",
                "evidence": bindings_desc[:500],
            })

        if results["upload_test"]["writable"]:
            findings.append({
                "severity": "critical",
                "title": f"GCS bucket writable ({results['bucket_name']})",
                "detail": "Upload succeeded without credentials.",
                "evidence": f"POST upload -> 200, object: {results['upload_test'].get('object_name')}",
            })

        for f in findings:
            self.store.insert_finding(
                request_id=0,
                category="cloud-gcs",
                severity=f["severity"],
                title=f["title"],
                detail=f["detail"],
                evidence=f.get("evidence", ""),
            )

    # ── SAS Token / Presigned URL Scanner ────────────────────

    def scan_js_for_sas_tokens(self) -> list:
        """Search captured JS for Azure SAS tokens, AWS presigned URLs, GCS signed URLs."""
        js_files = self.store.get_js_bodies()
        results = []

        for js in js_files:
            body = js.get("body", "")
            if not body:
                continue

            # Azure SAS tokens
            for m in SAS_TOKEN_RE.finditer(body):
                token = m.group(0)
                # Extract params from SAS
                sas_params = {}
                for part in token.lstrip("?&").split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        sas_params[k] = v

                results.append({
                    "type": "azure_sas",
                    "source_url": js["url"],
                    "source_request_id": js["id"],
                    "token_preview": token[:120],
                    "params": sas_params,
                    "context": body[max(0, m.start() - 60):m.end() + 20][:200],
                })

            # AWS presigned URLs
            for m in AWS_PRESIGNED_RE.finditer(body):
                # Get surrounding URL context
                start = max(0, m.start() - 200)
                context = body[start:m.end() + 20]
                # Try to extract the full URL
                url_match = re.search(r'https?://[^\s"\'`<>]+', context)
                results.append({
                    "type": "aws_presigned",
                    "source_url": js["url"],
                    "source_request_id": js["id"],
                    "signature_preview": m.group(0)[:80],
                    "context": context[:300],
                    "full_url": url_match.group(0) if url_match else None,
                })

            # GCS signed URLs
            for m in GCS_SIGNED_RE.finditer(body):
                start = max(0, m.start() - 200)
                context = body[start:m.end() + 20]
                url_match = re.search(r'https?://[^\s"\'`<>]+', context)
                results.append({
                    "type": "gcs_signed",
                    "source_url": js["url"],
                    "source_request_id": js["id"],
                    "token_preview": m.group(0)[:120],
                    "context": context[:300],
                    "full_url": url_match.group(0) if url_match else None,
                })

        # Store findings for discovered tokens
        for r in results:
            sev = "high" if r["type"] == "azure_sas" else "medium"
            self.store.insert_finding(
                request_id=r["source_request_id"],
                category=f"cloud-{r['type']}",
                severity=sev,
                title=f"Cloud credential in JS: {r['type']}",
                detail=f"Found {r['type']} in {r['source_url']}",
                evidence=r.get("token_preview", r.get("signature_preview", "")),
            )

        return results

    # ── Run All ──────────────────────────────────────────────

    def run_all(self, url: str) -> dict:
        """Auto-detect provider and run full audit."""
        provider = self.detect_provider(url)

        result = {
            "url": url,
            "provider": provider,
            "audit": None,
            "sas_tokens": [],
        }

        if provider == "azure":
            result["audit"] = self.test_azure(url)
        elif provider == "aws":
            result["audit"] = self.test_s3(url)
        elif provider == "gcp":
            result["audit"] = self.test_gcs(url)
        else:
            # Try all providers' basic tests
            result["audit"] = {
                "provider": "unknown",
                "note": f"Could not detect cloud provider from URL: {url}",
                "url": url,
            }

        # Always scan JS for tokens
        result["sas_tokens"] = self.scan_js_for_sas_tokens()

        return result
