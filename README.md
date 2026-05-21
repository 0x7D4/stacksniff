# stacksniff

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)



Detect web technology stacks, APIs, and backend software from any URL.

---

## What It Does

`stacksniff` is a local, scriptable command-line tool and developer library designed to inspect target URLs and identify their underlying technology stacks and exposed API endpoints. By using multiple layers of active and passive evidence collection, it uncovers frameworks, libraries, servers, CDNs, and API services operating on a page.

The tool coordinates four distinct detection layers:
1. **HTTP Header & Cookie Fingerprinting:** Inspects raw HTTP headers (such as `Server`, `X-Powered-By`) and session cookie structures against pattern databases.
2. **Headless Browser Interception:** Launches a headless Chromium browser instance to intercept dynamic XHR/fetch network requests and DOM additions.
3. **JS Bundle Static Analysis:** Downloads and scans client-side JavaScript bundles and their source maps using regex extraction to uncover hidden backend routes.
4. **Active Discovery Probing:** Targets well-known endpoints (e.g. `/robots.txt`, `/.well-known/security.txt`, and OpenAPI specifications) to detect APIs and system routes.

Unlike commercial SaaS detection services, `stacksniff` runs entirely locally, relies on a modular database of **7,500+ fingerprints** sourced directly from the open-source Wappalyzer repository, and integrates easily into continuous integration (CI) workflows or vulnerability scanning pipelines.

---

## Installation

### Prerequisites
* **Python 3.11+**
* [**uv**](https://github.com/astral-sh/uv) (fast Python package installer and runner)

### Clone & Install
```bash
# Clone the repository and sync dependencies
git clone https://github.com/0x7d4/stacksniff.git
cd stacksniff
uv sync
```

### Browser Setup

Install the Playwright browser binaries:
```bash
uv run playwright install chromium
```

**Linux (Ubuntu/Debian) System Dependencies:**
If you run stacksniff on a headless Linux server or container, you may encounter missing system libraries for Chromium (e.g., `libnspr4.so`). If this happens, install the system dependencies using Playwright's helper or fall back to manual installation:
```bash
# Automatically install all required system libraries
uv run playwright install-deps chromium

# Fallback: manually install minimal required shared libraries
sudo apt-get install -y libnspr4 libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2
```

### Build Fingerprints
Before scanning, compile the local technology signature database:
```bash
uv run stacksniff update-fingerprints
```

---

## Usage — CLI

`stacksniff` provides two primary commands: `scan` and `update-fingerprints`.

### 1. Default Scan
Runs a full analysis including HTTP inspection and headless browser tracking. 

```bash
$env:PYTHONIOENCODING="utf-8"
uv run stacksniff scan https://aiori.in --verbose
```

**Actual Scan Output:**
```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ stacksniff — scanning https://aiori.in                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                               Detected Technologies                               
  Technology      Category                   Version   Confidence  
 ──────────────────────────────────────────────────────────────────
  Nginx           web-server                 1.24.0    █████ 100%  
   ↳ header       Server                               matched: nginx/1.24.0 
                                                       (Ubuntu)    
  DataTables      js-library                 1.11.5    ████░ 95%   
   ↳ script       script_src                           matched:    
                                                       https://cdn.datatables.net/… 
   ↳ js_global    $.fn.dataTable.version               matched: 1.11.5 
   ↳ js_global    jQuery.fn.dataTable.version          matched: 1.11.5 
  Font Awesome    other                      6.0.0     ████░ 95%   
   ↳ script       script_src                           matched:    
                                                       https://cdnjs.cloudflare.co… 
   ↳ dom          selector                             matched: Found element:     
                                                       [class*='fa'] 
   ↳ dom          selector                             matched: Found element:     
                                                       link[href*='font-awesome']  
  jQuery          js-library                 3.6.0     ████░ 95%   
   ↳ script       script_src                           matched:    
                                                       https://code.jquery.com/jqu… 
   ↳ js_global    $.fn.jquery                          matched: 3.6.0  
   ↳ js_global    jQuery.fn.jquery                     matched: 3.6.0  
   ↳ js_global    jQuery.prototype.jquery              matched: 3.6.0  
  reCAPTCHA       other                                ████░ 95%   
   ↳ script       script_src                           matched:    
                                                       https://www.google.com/reca… 
   ↳ js_global    Recaptcha                            matched:    
                                                       {"anchor":{"ErrorMain":…    
   ↳ js_global    recaptcha                            matched:    
                                                       {"anchor":{"ErrorMain":…    
   ↳ dom          selector                             matched: Found element:     
                                                       #recaptcha_image,           
                                                       iframe, div.g-recaptcha     
  SweetAlert2     js-library                 11        ████░ 95%   
   ↳ script       script_src                           matched:    
                                                       https://cdn.jsdelivr.ne…    
   ↳ js_global    Sweetalert2                          matched: function  
  cdnjs           cdn                                  ████░ 85%   
   ↳ script       script_src                           matched:    
                                                       https://cdnjs.cloudflar…    
   ↳ dom          selector                             matched: Found element:     
                                                       link        
  Django          framework                            ████░ 85%   
   ↳ html         raw_html                             matched: <input  
                                                       type="hidden"    
                                                       name="csrfmiddlewaretok… 
                                                       value="R5q3IrtNf8xAPia4… 
   ↳ dom          selector                             matched: Found element:     
                                                       input       
  jsDelivr        cdn                                  ████░ 85%   
   ↳ script       script_src                           matched:    
                                                       https://cdn.jsdelivr.ne…    
   ↳ dom          selector                             matched: Found element:     
                                                       link        
  lit-element     js-library                 4.2.2     ████░ 85%   
   ↳ js_global    litElementVersions.0                 matched: 4.2.2  
  lit-html        js-library                 3.3.2     ████░ 85%   
   ↳ js_global    litHtmlVersions.0                    matched: 3.3.2  
  Tailwind CSS    framework                  2.2.19    ████░ 85%   
   ↳ dom          link                                 matched: Found: link 
                                                       (attributes: {'href':    
                                                       'https://cdn.jsdelivr.n… 
  ApexCharts.js   other                                ███░░ 75%   
   ↳ js_global    ApexCharts                           matched: function  
  Bootstrap       framework                            ███░░ 75%   
   ↳ html         raw_html                             matched: <link   
                                                       href="/static/css/boots… 
  ECharts         other                                ███░░ 75%   
   ↳ dom          selector                             matched: Found element:     
                                                       div[_echarts_instance_]     
  Google Font API other                                ███░░ 75%   
   ↳ dom          link                                 matched: Found: link 
                                                       (attributes: {'href':    
                                                       'https://fonts.googleap… 
  Google Maps     other                                ███░░ 75%   
   ↳ script       script_src                           matched:    
                                                       https://maps.googleapis… 
  jQuery CDN      cdn                                  ███░░ 75%   
   ↳ script       script_src                           matched:    
                                                       https://code.jquery.com… 
  Ubuntu          other                                ███░░ 75%   
   ↳ header       Server                               matched: nginx/1.24.0    
                                                       (Ubuntu)    
  Cloudflare      cdn                                  ███░░ 60%   
   ↳ implies      implies                              matched: Implied by 
                                                       cdnjs       
  Python          programming-language                 ███░░ 60%   
   ↳ implies      implies                              matched: Implied by 
                                                       Django      

┌─ Detected API Endpoints ────────────────────────────────────────────────────┐
│ • GET    /api/common/cluster-locations → application/json (REST API)        │
│ • GET    /maps/api/mapsjs/gen_204 → application/json; charset=UTF-8 (REST   │
│ API)                                                                        │
│ • GET    /api/anchor/root-server-list → application/json (REST API)         │
│ • POST   /api/anchor/root-server-state-wise-latency → application/json      │
│ (REST API)                                                                  │
│ • GET    /api/anchor/city-latency (REST API)                                │
│ • GET    /api/anchor/serve-map-coordinate (REST API)                        │
│ • GET    /api/common/research-layout (REST API)                             │
│ • GET    /api/anchor/check-latency (REST API)                               │
│ • GET    /api/common/anchor-locations (REST API)                            │
│ • GET    /api/common/unicast-anchor-locations (REST API)                    │
│ • GET    /api/anchor/serve-location-piechart-data (REST API)                │
│ • GET    /api/cityl (REST API)                                              │
│ • GET    /api/cl (REST API)                                                 │
│ • GET    /api/rl (REST API)                                                 │
│ • GET    /api/slpd (REST API)                                               │
│ • GET    /api/smc (REST API)                                                │
└─────────────────────────────────────────────────────────────────────────────┘

Scanned in 32.1s | 21 technologies | 16 endpoints
```

### 2. Fast HTTP-only Scan (No Browser)
Skips Playwright browser launching for an HTTP-only analysis:
```bash
uv run stacksniff scan https://aiori.in --no-browser
```

### 3. Detailed Evidence Scan
Outputs the matching evidence source keys, DOM components, and matching strings inline:
```bash
uv run stacksniff scan https://aiori.in --verbose
```

### 4. Output Raw JSON to Stdout
```bash
uv run stacksniff scan https://aiori.in --json
```

### 5. Write Scan Report to File
```bash
uv run stacksniff scan https://aiori.in --output aiori_report.json
```

### 6. Rebuild Fingerprints
```bash
uv run stacksniff update-fingerprints
```

**Output:**
```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ stacksniff — updating technology fingerprints                               │
└─────────────────────────────────────────────────────────────────────────────┘
                           Fingerprints Update Summary                            
  Metric                                                                Count     
 ─────────────────────────────────────────────────────────────────────────────    
  Technologies Added (Upstream)                                          7510     
  Technologies Updated (Upstream)                                           0     
  Technologies Preserved (Custom)                                          18     
  Total Technologies                                                     7528     

Successfully wrote fingerprints to C:\IIFON\URL\fingerprints\tech.yaml
```

### 7. Dry-Run Fingerprint Updates
Fetches and processes Wappalyzer's upstream signature changes without saving the file:
```bash
uv run stacksniff update-fingerprints --dry-run
```

---

## Usage — Python API

You can use the scanner programmatically inside your asynchronous Python applications:

```python
import asyncio
from stacksniff.scanner import Scanner

async def main():
    scanner = Scanner()
    result = await scanner.scan("https://aiori.in")
    
    print(f"Scan completed in {result.meta.duration_seconds:.2f}s")
    print(f"Detected {len(result.technologies)} technologies:")
    for tech in result.technologies:
        print(f" - {tech.name} (Category: {tech.category}, Version: {tech.version}, Confidence: {tech.confidence})")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Detection Layers

| Layer | Method | Confidence | Requires Browser |
|---|---|---|---|
| **HTTP Headers** | Matches headers (e.g. `Server`, `X-Powered-By`) using regexes | ~60% - 90% | No |
| **Cookies** | Evaluates response set-cookie parameters | ~80% - 90% | No |
| **HTML Meta** | Queries `<meta>` element names and contents via BeautifulSoup | ~80% - 90% | No |
| **JS Globals** | Resolves nested objects (`window.litHtmlVersions`) via browser context traversal | ~80% - 95% | Yes |
| **XHR Interception** | Captures active async request/response transactions | ~70% - 90% | Yes |
| **JS Static Analysis** | Extracts target endpoints from downloaded scripts and source maps | ~60% - 80% | No |
| **OpenAPI Spec** | Automatically parses retrieved OpenAPI / Swagger schemas | 100% | No |
| **Well-known Path Probes** | Verifies existence of endpoints like `/robots.txt` or `/.well-known/security.txt` | ~70% - 85% | No |

---

## Fingerprint Rules

All signatures are maintained in a structured format within `fingerprints/tech.yaml`.

### Fingerprint Schema
An entry matches a technology when the defined rules evaluate successfully:
* `headers`: Map of header keys to matching regex.
* `cookies`: Map of cookie names to matching regex.
* `html`: List of HTML patterns to match.
* `scripts`: List of script URLs to match.
* `js_globals`: Dict of global JS keys to regex value constraints.
* `dom`: Dict of CSS selectors to properties/existence assertions.
* `implies`: A list of other technology IDs automatically inferred by this match.
* `confidence`: Default baseline match confidence.

### Minimal Example Rule
```yaml
  lit-element:
    name: lit-element
    website: https://lit.dev/
    category: js-library
    js_globals:
      litElementVersions.0: ^([\d\.]+)$
    confidence: 100
```

### Adding Custom Rules
To add your own signatures, append them to `fingerprints/tech.yaml` under the appropriate category name. Custom rules are preserved when running `update-fingerprints`.

---

## Output Format

Running `stacksniff` with `--json` produces structured output. Below is the simplified JSON structure from the scan of `https://aiori.in`:

```json
{
  "url": "https://aiori.in",
  "scan_time": "2026-05-21T19:23:24.480022+00:00",
  "technologies": [
    {
      "name": "Nginx",
      "category": "web-server",
      "version": "1.24.0",
      "confidence": 1.0,
      "evidence": [
        {
          "source": "header",
          "key": "Server",
          "matched": "nginx/1.24.0 (Ubuntu)",
          "pattern": "nginx(?:/([\\d.]+))?"
        }
      ]
    },
    {
      "name": "jQuery",
      "category": "js-library",
      "version": "3.6.0",
      "confidence": 0.95,
      "evidence": [
        {
          "source": "script",
          "key": "script_src",
          "matched": "https://code.jquery.com/jquery-3.6.0.min.js",
          "pattern": "jquery"
        },
        {
          "source": "js_global",
          "key": "$.fn.jquery",
          "matched": "3.6.0",
          "pattern": "([\\d.]+)"
        }
      ]
    }
  ],
  "api_endpoints": [
    {
      "url": "/api/common/cluster-locations",
      "method": "GET",
      "content_type": "application/json",
      "pattern_matched": "REST API",
      "confidence": 0.8
    },
    {
      "url": "/api/anchor/root-server-state-wise-latency",
      "method": "POST",
      "content_type": "application/json",
      "pattern_matched": "REST API",
      "confidence": 0.8
    }
  ],
  "meta": {
    "duration_seconds": 31.093999999808148,
    "phases_completed": [
      "http",
      "browser"
    ],
    "fingerprints_version": "1.0.0",
    "rules_count": 7510
  },
  "openapi_spec_found": false
}
```

---

## Development

Use the following commands to run the test suite and enforce code style compliance:

```bash
# Run unit and integration tests
uv run pytest

# Check code syntax and rules
uv run ruff check src tests

# Check static typing
uv run mypy src
```

---

## Known Limitations

* **Authenticated Contexts:** Scans run inside clean, unauthenticated browser sessions. Endpoints hidden behind authenticated user flows (like admin dashboards) will not be intercepted.
* **Third-Party Integrations:** API requests to external services (e.g. Google Maps SDK) are captured in network traffic and may appear as endpoints. Filtering parameters are continuously updated to reduce these false positives.
* **SPA Engine Loading:** Heavy Javascript websites might time out in low-resource container runs. For rapid scans in minimal environments, use the `--no-browser` option.

---

