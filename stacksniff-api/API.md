# Stacksniff REST API Documentation

This document describes the REST API endpoints exposed by `stacksniff-api` for scanning URLs and retrieving technology stack details.

---

## Authentication

In the production environment, authentication is enforced using **Django REST Framework (DRF) Token Authentication**.

All API requests must include the token in the `Authorization` header:

```http
Authorization: Token <your_token_here>
```

### Creating an Authentication Token

You can generate a token for any user using the Django management command:

```bash
python manage.py drf_create_token <username>
```

In the development environment (`DEBUG=True`), permissions default to `AllowAny` to simplify integration, but token authentication is still enabled and can be tested.

---

## Endpoints

### 1. Create a Scan Job

Starts an asynchronous scanning task for a target URL.

* **URL:** `/api/scans/`
* **Method:** `POST`
* **Headers:**
  * `Content-Type: application/json`
* **Request Body:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | String | Yes | - | The target URL to scan (must be valid HTTP/HTTPS URL) |
| `browser` | Boolean | No | `true` | If `true`, runs browser-based collectors (Chromium) |
| `timeout` | Float | No | `30.0` | Internal timeout for individual collectors |
| `force_rescan` | Boolean | No | `false` | If `true`, bypasses stacksniff's file-based cache and triggers a fresh scan |

* **Request Example:**
  ```json
  {
    "url": "https://example.com",
    "browser": true,
    "timeout": 30.0,
    "force_rescan": false
  }
  ```

* **Response Example (`201 Created`):**
  ```json
  {
    "id": "e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809",
    "url": "https://example.com",
    "status": "pending",
    "created_at": "2026-06-14T12:00:00Z",
    "started_at": null,
    "completed_at": null,
    "celery_task_id": "893c52a0-43ef-4e31-8ff8-4ff4b2413e11",
    "error_message": null,
    "options": {
      "browser": true,
      "timeout": 30.0
    },
    "result": null
  }
  ```

---

### 2. List Scan Jobs

Retrieves a paginated list of all scan jobs, sorted newest first.

* **URL:** `/api/scans/`
* **Method:** `GET`
* **Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `page` | Integer | Page number (default: 1, pagination size is 20) |
| `url` | String | Filters jobs whose URL contains this substring (case-insensitive) |
| `status` | String | Filters jobs by status (`pending`, `running`, `completed`, `failed`) |
| `created_after` | ISO DateTime | Filters jobs created on or after this timestamp (e.g. `2026-06-14T00:00:00Z`) |
| `created_before` | ISO DateTime | Filters jobs created on or before this timestamp |

* **Response Example (`200 OK`):**
  ```json
  {
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
      {
        "id": "e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809",
        "url": "https://example.com",
        "status": "completed",
        "created_at": "2026-06-14T12:00:00Z",
        "started_at": "2026-06-14T12:00:01Z",
        "completed_at": "2026-06-14T12:00:15Z",
        "celery_task_id": "893c52a0-43ef-4e31-8ff8-4ff4b2413e11",
        "error_message": null,
        "options": {
          "browser": true,
          "timeout": 30.0
        },
        "result": {
          "id": "e0b02bb9-5100-4bbf-93f8-8bb8a241a82f",
          "url": "https://example.com",
          "scan_time": "2026-06-14T12:00:14Z",
          "duration_seconds": 13.4,
          "technologies": [...],
          "api_endpoints": [...],
          "runtime_dependencies": [...],
          "discovered_subdomains": [...],
          "openapi_spec_found": false,
          "phases_completed": ["http", "browser"],
          "rules_count": 142
        }
      }
    ]
  }
  ```

---

### 3. Retrieve Scan Job Details

Retrieves details for a single scan job. If completed, includes the full nested result.

* **URL:** `/api/scans/{id}/`
* **Method:** `GET`
* **Response Example (`200 OK`):**
  ```json
  {
    "id": "e4b3e83b-ea0e-436d-b8d4-5fe5c2a13809",
    "url": "https://example.com",
    "status": "completed",
    "created_at": "2026-06-14T12:00:00Z",
    "started_at": "2026-06-14T12:00:01Z",
    "completed_at": "2026-06-14T12:00:15Z",
    "celery_task_id": "893c52a0-43ef-4e31-8ff8-4ff4b2413e11",
    "error_message": null,
    "options": {
      "browser": true,
      "timeout": 30.0
    },
    "result": {
      "id": "e0b02bb9-5100-4bbf-93f8-8bb8a241a82f",
      "url": "https://example.com",
      "scan_time": "2026-06-14T12:00:14Z",
      "duration_seconds": 13.4,
      "technologies": [
        {
          "name": "Nginx",
          "category": "web-servers",
          "version": "1.24.0",
          "confidence": 1.0,
          "evidence": [
            {
              "source": "header",
              "key": "Server",
              "matched": "nginx/1.24.0",
              "pattern": "nginx(?:/([\\d.]+))?"
            }
          ]
        }
      ],
      "api_endpoints": [
        {
          "url": "https://example.com/api/v1/users",
          "method": "GET",
          "content_type": "application/json",
          "pattern_matched": "REST /api/v*",
          "confidence": 0.8
        }
      ],
      "runtime_dependencies": [
        {
          "domain": "google-analytics.com",
          "category": "analytics",
          "matched_by": "script_src"
        }
      ],
      "discovered_subdomains": [
        {
          "domain": "api.example.com",
          "category": "api_host",
          "matched_by": "api_endpoint"
        }
      ],
      "openapi_spec_found": false,
      "phases_completed": ["http", "browser"],
      "rules_count": 142
    }
  }
  ```

---

### 4. Cancel a Scan Job

Cancels a scan job if it is active (revoking the Celery task) and deletes its database record.

* **URL:** `/api/scans/{id}/`
* **Method:** `DELETE`
* **Response:** `24 No Content`

---

### 5. Custom Sub-resource Endpoints

For high-volume client polling or simpler frontend extraction, you can fetch specific segments of a scan's results directly once completed. If the scan is not complete, these return a `404 Not Found`.

#### Get Full Scan Result
* **URL:** `/api/scans/{id}/result/`
* **Method:** `GET`
* **Response:** Returns the nested `result` dictionary.

#### Get Technologies
* **URL:** `/api/scans/{id}/technologies/`
* **Method:** `GET`
* **Response:** Array of matched technology objects.

#### Get Endpoints
* **URL:** `/api/scans/{id}/endpoints/`
* **Method:** `GET`
* **Response:** Array of detected API endpoints.

#### Get Subdomains
* **URL:** `/api/scans/{id}/subdomains/`
* **Method:** `GET`
* **Response:** Array of discovered subdomains.

#### Get Dependencies
* **URL:** `/api/scans/{id}/dependencies/`
* **Method:** `GET`
* **Response:** Array of runtime external dependencies.

---

## Polling Strategy

For the best user experience on the frontend:
1. **Create the scan:** Call `POST /api/scans/` and save the scan job `id`.
2. **Poll the job status:** Call `GET /api/scans/{id}/` every `2` to `5` seconds.
3. **Finish:** When `status` changes to `completed`, extract the `result` field. If `failed`, check the `error_message` field.
