# stacksniff API — Frontend Reference

> **This is the definitive integration guide for frontend teams.**
> Base URL after deployment: `http://<your-server-ip>/api/`

---

## Quick Start

Run these three commands in order to verify your deployment is working.

### 1. Health check (no auth required)
```bash
curl -s http://<server-ip>/api/health/ | python3 -m json.tool
```
Expected response:
```json
{
  "status": "ok",
  "checks": {
    "database": "ok",
    "celery": "ok"
  }
}
```

### 2. Create a scan
```bash
TOKEN=$(cat /opt/stacksniff/API_TOKEN.txt)

curl -s -X POST http://<server-ip>/api/scan/tech/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}' | python3 -m json.tool
```
Save the returned `id` field.

### 3. Poll for result
```bash
curl -s http://<server-ip>/api/scans/<id>/ \
     -H "Authorization: Token $TOKEN" | python3 -m json.tool
```
Repeat every 3–5 seconds until `"status": "completed"`.

---

## Authentication

All scan endpoints require a **DRF Token** in the `Authorization` header.

```http
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

**Where to get your token:**
- The token is printed in the terminal at the end of `setup.sh`
- It is also saved to `/opt/stacksniff/API_TOKEN.txt`

**curl example:**
```bash
curl -H "Authorization: Token $TOKEN" http://<server-ip>/api/scans/
```

**JavaScript fetch example:**
```javascript
const TOKEN = 'your_token_here';

const headers = {
  'Authorization': `Token ${TOKEN}`,
  'Content-Type': 'application/json',
};
```

> **Note:** `GET /api/health/` does **not** require authentication — use it for load-balancer probes.

---

## Testing with Postman (Walkthrough)

A complete, pre-configured Postman Collection is available in the repository root at `stacksniff_postman_collection.json`.

### 1. Import the Collection
1. Open Postman.
2. Click **Import** in the top-left corner.
3. Select or drag the `stacksniff_postman_collection.json` file from the workspace root directory.
4. Click **Import**. You will see the **stacksniff API** collection in the sidebar.

### 2. Configure Collection Variables
1. Click the parent folder **stacksniff API** in the sidebar.
2. Go to the **Variables** tab in the main editor pane.
3. Set your variables:
   - `base_url`: `http://127.0.0.1:8000` (for localhost development).
   - `token`: (Optional in local `DEBUG=True` mode, otherwise paste your generated DRF Token).
4. Save the collection variables (**Ctrl + S**).

### 3. Run a Scan & Check Results
1. **Health Check:** Expand **Health** and click **Send** on **Health Check** (unauthenticated). Verify that `"database": "ok"` and `"celery": "ok"`.
2. **Start Scan:** Expand **Shortcut Scans** and click **Send** on **Create Tech Scan** (feel free to modify the `url` key in the request **Body** tab).
3. **Get Scan ID:** Copy the returned `"id"` (UUID) from the JSON response.
4. **Update Variable:** Paste this UUID into the `scan_id` field in your Collection Variables, or directly replace the `{{scan_id}}` parameter in subsequent request URLs.
5. **Poll Status:** Go to **Advanced Jobs** -> **Get Job Details** and click **Send**. Wait a few seconds and repeat until `"status"` changes from `"pending"` or `"running"` to `"completed"`.
6. **Browse Results:** Expand the **Job Results** folder and query sub-resources like `/technologies/`, `/endpoints/`, or `/evidence/` to inspect the results.

---

## Scan Endpoints (Shortcuts — use these)

These one-shot endpoints are the primary interface. Send a URL, get a job ID back, then poll until done.

| Endpoint | What It Scans | Typical Time | Use Case |
|---|---|---|---|
| `POST /api/scan/tech/` | Technology fingerprinting only | ~30s | "What stack is this site using?" |
| `POST /api/scan/full/` | Tech + subdomains + endpoints | ~90s | Full recon on a target |
| `POST /api/scan/endpoints/` | API endpoint detection only | ~40s | "What APIs does this site expose?" |
| `POST /api/scan/subdomains/` | Subdomain discovery only | ~15–30s | "What subdomains exist?" |

### Request body (all shortcuts)

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | ✅ | — | Target URL (must be `http://` or `https://`) |
| `timeout` | float | ❌ | `30.0` | Per-collector timeout in seconds |
| `force_rescan` | boolean | ❌ | `false` | Bypass 30-minute cache and force fresh scan |

### POST /api/scan/tech/

Launches header + HTML + cookie + JS analysis. Skips subdomains and endpoint probing.

```bash
curl -s -X POST http://<server-ip>/api/scan/tech/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://stripe.com"}'
```

```json
{
  "id": "e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809",
  "url": "https://stripe.com",
  "status": "pending",
  "created_at": "2026-06-25T07:00:00Z",
  "options": {
    "scan_technologies": true,
    "scan_subdomains": false,
    "scan_endpoints": false,
    "browser": true
  }
}
```

### POST /api/scan/full/

All collectors active. Includes browser-rendered JS analysis.

```bash
curl -s -X POST http://<server-ip>/api/scan/full/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com", "timeout": 60}'
```

### POST /api/scan/endpoints/

Detects REST/GraphQL endpoints from HTML, JS bundles, and framework probing. Browser enabled for JS-rendered routes.

```bash
curl -s -X POST http://<server-ip>/api/scan/endpoints/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

### POST /api/scan/subdomains/

Certificate Transparency + DNS lookup. **No browser launched** — fastest and lightest scan.

```bash
curl -s -X POST http://<server-ip>/api/scan/subdomains/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com", "force_rescan": true}'
```

### Polling pattern (JavaScript)

```javascript
async function scanUrl(url, type = 'tech') {
  const TOKEN = 'your_token_here';
  const BASE  = 'http://<server-ip>';

  // 1. Create the scan job
  const job = await fetch(`${BASE}/api/scan/${type}/`, {
    method: 'POST',
    headers: {
      'Authorization': `Token ${TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  }).then(r => {
    if (!r.ok) throw new Error(`Create failed: ${r.status}`);
    return r.json();
  });

  // 2. Poll until complete
  while (true) {
    await new Promise(r => setTimeout(r, 3000)); // 3-second interval

    const status = await fetch(`${BASE}/api/scans/${job.id}/`, {
      headers: { 'Authorization': `Token ${TOKEN}` },
    }).then(r => r.json());

    if (status.status === 'completed') return status.result;
    if (status.status === 'failed')    throw new Error(status.error_message);
    // 'pending' or 'running' → keep polling
  }
}

// Usage
scanUrl('https://stripe.com', 'tech')
  .then(result => console.log(result.technologies))
  .catch(err   => console.error(err));
```

---

## Job Management Endpoints

Use these when you need full control over scan options or want to list/filter existing jobs.

### POST /api/scans/

Creates a new scan job with full option control.

```bash
curl -s -X POST http://<server-ip>/api/scans/ \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://example.com",
       "browser": true,
       "timeout": 30.0,
       "force_rescan": false,
       "scan_technologies": true,
       "scan_subdomains": true,
       "scan_endpoints": true
     }'
```

Returns `201 Created` with a `ScanJob` object.

### GET /api/scans/

Lists all scan jobs. Supports filtering.

| Query Parameter | Type | Description |
|---|---|---|
| `url` | string | Case-insensitive substring filter on URL |
| `status` | string | Filter by `pending`, `running`, `completed`, or `failed` |
| `created_after` | ISO datetime | Jobs created on or after this timestamp |
| `created_before` | ISO datetime | Jobs created on or before this timestamp |
| `page` | integer | Page number (default: 1, page size: 20) |

```bash
# List completed jobs for a specific domain
curl -s "http://<server-ip>/api/scans/?url=stripe.com&status=completed" \
     -H "Authorization: Token $TOKEN"
```

### GET /api/scans/{id}/

Get a single job with full nested result once completed.

```bash
curl -s http://<server-ip>/api/scans/e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809/ \
     -H "Authorization: Token $TOKEN"
```

**Status values:**

| Status | Meaning |
|---|---|
| `pending` | Job queued, Celery worker not yet started |
| `running` | Scan actively in progress |
| `completed` | Done — `result` field is populated |
| `failed` | Error occurred — check `error_message` |

### DELETE /api/scans/{id}/

Cancels an active scan (revokes the Celery task) and removes the database record.

```bash
curl -s -X DELETE http://<server-ip>/api/scans/e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809/ \
     -H "Authorization: Token $TOKEN"
```

Returns `204 No Content`.

---

## Result Sub-resources

Once a job is `completed`, you can fetch individual data segments without pulling the entire result object. All return `404` if the job is not yet complete.

### GET /api/scans/{id}/result/
Full result object (same as the nested `result` in the job endpoint).

### GET /api/scans/{id}/technologies/
Array of `Technology` objects detected on the target.

```bash
curl -s http://<server-ip>/api/scans/<id>/technologies/ \
     -H "Authorization: Token $TOKEN"
```

### GET /api/scans/{id}/endpoints/
Array of `ApiEndpoint` objects found during the scan.

### GET /api/scans/{id}/subdomains/
Array of `Subdomain` objects discovered via CT logs and DNS.

### GET /api/scans/{id}/dependencies/
Array of `RuntimeDependency` objects (third-party scripts, CDNs, analytics, etc.).

### GET /api/scans/{id}/evidence/

Returns the raw `CollectedEvidence` gathered by all collectors — before any
fingerprint matching. Intended for the hybrid React client, which runs
`FingerprintMatcher` + `ApiDetector` locally in a Web Worker.

```bash
curl -s http://<server-ip>/api/scans/<id>/evidence/ \
     -H "Authorization: Token $TOKEN"
```

```json
{
  "raw_evidence": {
    "headers":               { "Server": "nginx", "X-Powered-By": "PHP/8.1" },
    "cookies":               { "PHPSESSID": "abc123" },
    "html":                  "<html>...",
    "meta_tags":             { "generator": "WordPress 6.4" },
    "script_srcs":           ["https://example.com/wp-includes/js/jquery.min.js"],
    "link_hrefs":            [],
    "js_globals":            { "wp": "[object Object]" },
    "dom":                   {},
    "network_requests":      [...],
    "probed_paths":          [...],
    "framework_endpoints":   [
      {
        "url": "https://example.com/wp-admin/",
        "status_code": 200,
        "status_label": "exposed",
        "content_type": "text/html; charset=UTF-8",
        "confidence": 0.95,
        "source_wordlist": "wordpress.txt",
        "implied_techs": ["wordpress"]
      }
    ],
    "runtime_dependencies":  [...],
    "discovered_subdomains": [...]
  }
}
```

> **Note:** `html` is returned untruncated. nginx gzip compression handles wire
> cost. CLI-side and client-side matching see identical evidence.

---

## Response Schemas

### ScanJob

```typescript
interface ScanJob {
  id:              string;       // UUID
  url:             string;       // Scanned URL
  status:          'pending' | 'running' | 'completed' | 'failed';
  created_at:      string;       // ISO 8601
  started_at:      string | null;
  completed_at:    string | null;
  celery_task_id:  string | null;
  error_message:   string | null;
  options: {
    browser:             boolean;
    timeout:             number;
    scan_technologies:   boolean;
    scan_subdomains:     boolean;
    scan_endpoints:      boolean;
  };
  result: ScanResult | null;     // null until status === 'completed'
}
```

### ScanResult

```typescript
interface ScanResult {
  id:                     string;
  url:                    string;
  scan_time:              string;       // ISO 8601 timestamp
  duration_seconds:       number;
  technologies:           Technology[];
  api_endpoints:          ApiEndpoint[];
  runtime_dependencies:   RuntimeDependency[];
  discovered_subdomains:  Subdomain[];
  raw_evidence?:          CollectedEvidence; // omitted by default (use /api/scans/{id}/evidence/ endpoint)
  openapi_spec_found:     boolean;
  phases_completed:       string[];     // e.g. ["http", "browser"]
  rules_count:            number;       // Total fingerprint rules evaluated
}
```

### Technology

```typescript
interface Technology {
  name:       string;   // e.g. "Nginx"
  category:   string;   // e.g. "web-servers", "javascript-frameworks"
  version:    string | null;
  confidence: number;   // 0.0–1.0
  evidence:   Evidence[];
}

interface Evidence {
  source:  'header' | 'html' | 'cookie' | 'js_global' | 'script_src' | 'url';
  key:     string;      // e.g. "Server"
  matched: string;      // Actual matched string
  pattern: string;      // Regex pattern that matched
}
```

### ApiEndpoint

```typescript
interface ApiEndpoint {
  url:             string;
  method:          'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | string;
  content_type:    string | null;
  pattern_matched: string;   // Human-readable rule name
  confidence:      number;   // 0.0–1.0
}
```

### Subdomain

```typescript
interface Subdomain {
  subdomain:          string;        // e.g. "api.example.com"
  full_url:           string;        // e.g. "https://api.example.com"
  status_code:        number;        // HTTP response status (e.g. 200, 301, 403)
  content_type:       string | null;
  redirect_location:  string | null; // target location if redirect
  response_time_ms:   number;        // response time in milliseconds
  detected_tech:      string | null; // e.g. "Nginx"
  detected_category:  string | null; // e.g. "web-servers"
  ct_source?:         string | null; // CT log source (e.g. "crt.sh")
}
```

### RuntimeDependency

```typescript
interface RuntimeDependency {
  domain:             string;        // e.g. "cdn.jsdelivr.net"
  category:           string;        // Wappalyzer category name or "Unclassified"
  technology_name:    string | null; // e.g. "jsDelivr"
  resource_types:     string[];      // e.g. ["script", "stylesheet"]
  request_count:      number;
  example_urls:       string[];      // list of resource URLs requested
}
```

### CollectedEvidence

Returned by `GET /api/scans/{id}/evidence/` inside the `raw_evidence` key.
This is the complete collector output before fingerprint analysis.

```typescript
interface CollectedEvidence {
  headers:               Record<string, string>;
  cookies:               Record<string, string>;
  html:                  string;                         // full page HTML, untruncated
  meta_tags:             Record<string, string>;
  script_srcs:           string[];
  link_hrefs:            string[];
  js_globals:            Record<string, string>;         // window.* globals captured by browser
  dom:                   Record<string, object[]>;       // DOM selector → element list
  network_requests:      NetworkRequest[];               // XHR / fetch calls captured by browser
  probed_paths:          NetworkRequest[];               // framework probe results
  static_endpoints:      string[];
  spec_endpoints:        string[];                       // OpenAPI / Swagger URLs found
  framework_endpoints:   FrameworkEndpoint[];            // routes from framework-specific probes
  runtime_dependencies:  object[];                       // third-party scripts/CDNs
  discovered_subdomains: object[];
}

interface FrameworkEndpoint {
  url:                 string;
  status_code:         number;
  status_label:        string;                         // e.g. "exposed", "forbidden", "redirect"
  content_type:        string | null;
  confidence:          number;
  source_wordlist:     string;                         // e.g. "wordpress.txt"
  top_level_keys?:     string[];                       // keys present in JSON response body
  redirect_location?:  string;                         // present for 3xx responses
  implied_techs:       string[];                       // techs implied by the wordlist (Phase 4 matching)
}

interface NetworkRequest {
  url:              string;
  method:           string;
  resource_type:    string;
  response_status?: number;
  response_headers?: Record<string, string>;
}
```

---

## Error Responses

All errors return JSON with an `error` key.

| Status | Trigger | Response Body |
|---|---|---|
| `400 Bad Request` | Missing or invalid `url` field | `{"url": ["Enter a valid URL."]}` |
| `401 Unauthorized` | Missing or invalid token | `{"detail": "Authentication credentials were not provided."}` |
| `404 Not Found` | Job ID doesn't exist, or result not ready yet | `{"error": "Scan result is not available. Scan status: running"}` |
| `429 Too Many Requests` | Exceeded 10 scans/min per IP (app layer) | `{"error": "Rate limit exceeded. You may submit 10 scans per minute."}` |
| `503 Service Unavailable` | Health check: DB or Celery degraded | `{"status": "degraded", "checks": {"database": "ok", "celery": "error: timeout"}}` |

**429 response includes:**
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## JavaScript Integration Example

Drop-in polling helper with error handling and timeout:

```javascript
const STACKSNIFF_TOKEN  = 'your_token_here';
const STACKSNIFF_BASE   = 'http://<server-ip>';
const POLL_INTERVAL_MS  = 3000;
const MAX_POLL_ATTEMPTS = 100; // ~5 minutes

async function stacksniffRequest(path, options = {}) {
  const res = await fetch(`${STACKSNIFF_BASE}${path}`, {
    ...options,
    headers: {
      'Authorization': `Token ${STACKSNIFF_TOKEN}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (res.status === 429) {
    const retry = parseInt(res.headers.get('Retry-After') || '60', 10);
    throw new Error(`Rate limited. Retry after ${retry}s`);
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HTTP ${res.status}: ${body}`);
  }
  return res.json();
}

async function scanUrl(url, type = 'tech') {
  // 1. Create the job
  const job = await stacksniffRequest(`/api/scan/${type}/`, {
    method: 'POST',
    body: JSON.stringify({ url }),
  });

  console.log(`Scan started: ${job.id} (${type})`);

  // 2. Poll for completion
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

    const current = await stacksniffRequest(`/api/scans/${job.id}/`);

    if (current.status === 'completed') {
      console.log(`Scan complete in ${current.result.duration_seconds}s`);
      return current.result;
    }

    if (current.status === 'failed') {
      throw new Error(`Scan failed: ${current.error_message}`);
    }

    console.log(`Still ${current.status}... (poll ${attempt + 1}/${MAX_POLL_ATTEMPTS})`);
  }

  throw new Error('Scan timed out after polling');
}

// ─── Usage examples ───────────────────────────────────────────────────────────

// Tech stack only (~30s)
scanUrl('https://stripe.com', 'tech')
  .then(result => {
    result.technologies.forEach(t =>
      console.log(`${t.name} ${t.version ?? ''} [${t.category}]`)
    );
  });

// Full scan (~90s)
scanUrl('https://example.com', 'full')
  .then(result => {
    console.log('Technologies:', result.technologies.length);
    console.log('Subdomains:',   result.discovered_subdomains.length);
    console.log('Endpoints:',    result.api_endpoints.length);
  });

// Subdomains only (~15–30s)
scanUrl('https://example.com', 'subdomains')
  .then(result =>
    result.discovered_subdomains.forEach(s =>
      console.log(`${s.domain} [${s.category}]`)
    )
  );
```

---

## Scan Options Reference

Full option table for `POST /api/scans/` (fine-grained control):

| Option | Type | Default | Effect |
|---|---|---|---|
| `url` | string | **required** | Target URL to scan |
| `browser` | boolean | `true` | Launch Chromium for JS rendering, XHR capture, JS globals |
| `timeout` | float | `30.0` | Per-collector timeout in seconds |
| `force_rescan` | boolean | `false` | Bypass 30-minute result cache and run a fresh scan |
| `scan_technologies` | boolean | `true` | Run tech fingerprinting (headers, HTML, cookies, JS globals) |
| `scan_subdomains` | boolean | `true` | Run CT log + DNS subdomain discovery |
| `scan_endpoints` | boolean | `true` | Run API endpoint detection and framework probing |

> **Performance tip:** Only enable the scan types you need. A `subdomains`-only scan (`scan_technologies=false`, `scan_endpoints=false`, `browser=false`) is ~5× faster than a full scan because no Chromium process is launched.

---

## Performance Notes

### Measured scan times (typical targets)

| Scan Type | Typical Time | What runs |
|---|---|---|
| `tech` | 20–40s | HTTP, cookies, HTML, browser JS |
| `endpoints` | 30–50s | HTTP, HTML, JS bundles, browser, framework probes |
| `subdomains` | 10–30s | CT lookup (crt.sh + HackerTarget), HEAD probing |
| `full` | 60–120s | All of the above concurrently |

Times vary significantly based on target response times and number of JS bundles.

### Caching

- Results are cached for **30 minutes** by default
- Use `force_rescan: true` to bypass the cache
- Cache TTL is configurable via the `STACKSNIFF_CACHE_TTL` env variable (seconds)

### Rate limits

| Layer | Limit | Response |
|---|---|---|
| Django app | 10 POST scans per IP per minute | `429 Too Many Requests` + `Retry-After: 60` |
| Nginx | 30 requests per IP per minute (all routes) | `429` (nginx-level) |
| Browser pool | Max 3 concurrent Chromium instances (default) | Queued internally |

### Concurrent scan behavior

- Multiple scans can be submitted simultaneously — they queue in Celery
- Celery workers: 10 gevent green-threads by default
- Browser slots: 3 concurrent maximum (configurable via `STACKSNIFF_MAX_BROWSERS`)
- Subdomains-only scans never consume browser slots — safe to run in parallel with full scans

---

## Development Startup

Start both processes locally for development:

```bash
# Terminal 1 — Django (ASGI via uvicorn, auto-reload)
cd stacksniff-api
uv run uvicorn config.asgi:application --host 127.0.0.1 --port 8000 --reload

# Terminal 2 — Celery worker
cd stacksniff-api
uv run celery -A config worker --pool=gevent --concurrency=10 --loglevel=info
```

In dev mode (`DEBUG=True`) authentication defaults to `AllowAny` — no token needed.
