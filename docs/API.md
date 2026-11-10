# PatchPilot API Reference

> Complete REST API documentation for the PatchPilot cybersecurity code scanning platform.

**Base URL**: `http://localhost:8000` (development) or `https://your-domain.com` (production)

**Interactive Docs**: Visit `/docs` for the Swagger UI or `/redoc` for ReDoc.

---

## Table of Contents

- [Health & Status](#health--status)
- [Scanning](#scanning)
- [Reports](#reports)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)

---

## Health & Status

### Root Health Check

Returns basic server status.

**Endpoint**: `GET /`

**Response** `200 OK`:

```json
{
  "name": "PatchPilot",
  "version": "1.0.0",
  "status": "running",
  "message": "Find the flaw. Fix the code. Prove the patch."
}
```

**Example**:

```bash
curl http://localhost:8000/
```

---

### Detailed Health Check

Returns detailed health information including scanner and AI service status.

**Endpoint**: `GET /api/health`

**Response** `200 OK`:

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3621.5,
  "scanners": {
    "sql_injection": "active",
    "credentials": "active",
    "unsafe_exec": "active",
    "python_security": "active"
  },
  "ai_service": "connected",
  "ai_model": "gemma-4-27b"
}
```

**Response when AI is unavailable** `200 OK`:

```json
{
  "status": "degraded",
  "version": "1.0.0",
  "uptime_seconds": 3621.5,
  "scanners": {
    "sql_injection": "active",
    "credentials": "active",
    "unsafe_exec": "active",
    "python_security": "active"
  },
  "ai_service": "disconnected",
  "ai_model": "gemma-4-27b"
}
```

**Example**:

```bash
curl http://localhost:8000/api/health
```

---

## Scanning

### Scan a File (Upload)

Upload a source code file for security scanning.

**Endpoint**: `POST /api/scan`

**Content-Type**: `multipart/form-data`

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | file | Yes | Source code file to scan (max 5 MB) |

**Response** `200 OK`:

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "filename": "app.py",
  "language": "python",
  "scanned_at": "2026-10-31T12:00:00Z",
  "summary": {
    "total_findings": 8,
    "critical": 3,
    "high": 2,
    "medium": 2,
    "low": 1,
    "scanners_run": [
      "sql_injection",
      "credentials",
      "unsafe_exec",
      "python_security"
    ]
  },
  "findings": [
    {
      "id": "finding-001",
      "scanner": "sql_injection",
      "severity": "critical",
      "title": "SQL Injection via f-string",
      "description": "User-controlled input is directly interpolated into a SQL query using an f-string, enabling SQL injection attacks.",
      "cwe_id": "CWE-89",
      "cwe_name": "SQL Injection",
      "line_number": 42,
      "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
      "ai_explanation": "An attacker can manipulate the user_id parameter to inject arbitrary SQL commands. For example, passing '1 OR 1=1' would return all users, while '1; DROP TABLE users--' could destroy the entire table.",
      "suggested_fix": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
      "confidence": "high"
    }
  ]
}
```

**Error Responses**:

| Status | Description |
|--------|-------------|
| `400` | No file provided or file is empty |
| `413` | File exceeds maximum size (5 MB) |
| `415` | Unsupported file type |
| `500` | Internal scanning error |

**Example**:

```bash
curl -X POST http://localhost:8000/api/scan \
  -F "file=@vulnerable_app.py"
```

---

### Scan Code Text

Submit code as text for security scanning (no file upload required).

**Endpoint**: `POST /api/scan/text`

**Content-Type**: `application/json`

**Request Body**:

```json
{
  "code": "import sqlite3\n\ndef get_user(user_id):\n    conn = sqlite3.connect('app.db')\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    return conn.execute(query).fetchone()\n",
  "filename": "app.py",
  "language": "python"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | Source code to scan |
| `filename` | string | No | Filename for context (default: `untitled.py`) |
| `language` | string | No | Language identifier (default: `python`) |

**Response** `200 OK`:

Same response schema as `POST /api/scan`.

**Error Responses**:

| Status | Description |
|--------|-------------|
| `400` | Empty code body |
| `422` | Invalid request format |
| `500` | Internal scanning error |

**Example**:

```bash
curl -X POST http://localhost:8000/api/scan/text \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"admin123\"\neval(user_input)",
    "filename": "example.py",
    "language": "python"
  }'
```

---

### Get Scan Results

Retrieve results for a previously completed scan.

**Endpoint**: `GET /api/scan/{scan_id}`

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | string (UUID) | Unique scan identifier |

**Response** `200 OK`:

Same response schema as `POST /api/scan`.

**Error Responses**:

| Status | Description |
|--------|-------------|
| `404` | Scan not found |

**Example**:

```bash
curl http://localhost:8000/api/scan/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

### List All Scans

Retrieve a paginated list of all completed scans.

**Endpoint**: `GET /api/scans`

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | integer | `0` | Number of records to skip |
| `limit` | integer | `20` | Maximum records to return (max: 100) |

**Response** `200 OK`:

```json
{
  "total": 42,
  "skip": 0,
  "limit": 20,
  "scans": [
    {
      "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "app.py",
      "language": "python",
      "scanned_at": "2026-10-31T12:00:00Z",
      "summary": {
        "total_findings": 8,
        "critical": 3,
        "high": 2,
        "medium": 2,
        "low": 1
      }
    },
    {
      "scan_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "filename": "utils.py",
      "language": "python",
      "scanned_at": "2026-10-31T11:30:00Z",
      "summary": {
        "total_findings": 2,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0
      }
    }
  ]
}
```

**Example**:

```bash
# First page
curl "http://localhost:8000/api/scans?skip=0&limit=20"

# Second page
curl "http://localhost:8000/api/scans?skip=20&limit=20"
```

---

## Reports

### Generate a PDF Report

Generate a professional PDF report for a completed scan.

**Endpoint**: `POST /api/report/{scan_id}`

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | string (UUID) | Unique scan identifier |

**Response** `200 OK`:

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "report_status": "generated",
  "report_path": "/api/report/a1b2c3d4-e5f6-7890-abcd-ef1234567890/download",
  "generated_at": "2026-10-31T12:05:00Z",
  "page_count": 12
}
```

**Error Responses**:

| Status | Description |
|--------|-------------|
| `404` | Scan not found |
| `500` | Report generation failed |

**Example**:

```bash
curl -X POST http://localhost:8000/api/report/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

### Download a PDF Report

Download the generated PDF report file.

**Endpoint**: `GET /api/report/{scan_id}/download`

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | string (UUID) | Unique scan identifier |

**Response** `200 OK`:

- **Content-Type**: `application/pdf`
- **Content-Disposition**: `attachment; filename="patchpilot-report-{scan_id}.pdf"`
- **Body**: Binary PDF file

**Error Responses**:

| Status | Description |
|--------|-------------|
| `404` | Scan or report not found |

**Example**:

```bash
# Download the report
curl -o report.pdf \
  http://localhost:8000/api/report/a1b2c3d4-e5f6-7890-abcd-ef1234567890/download

# Open the report (macOS)
open report.pdf

# Open the report (Windows)
start report.pdf
```

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "detail": "Human-readable error message describing what went wrong."
}
```

### Standard HTTP Status Codes

| Status Code | Meaning | Common Causes |
|-------------|---------|---------------|
| `400` | Bad Request | Missing required fields, empty input, invalid file |
| `404` | Not Found | Invalid scan_id or report not generated yet |
| `413` | Payload Too Large | File exceeds the 5 MB upload limit |
| `415` | Unsupported Media Type | File type not supported for scanning |
| `422` | Validation Error | Request body doesn't match expected schema |
| `429` | Too Many Requests | Rate limit exceeded (see below) |
| `500` | Internal Server Error | Unexpected server-side failure |

### Validation Error Response (422)

FastAPI returns detailed validation errors:

```json
{
  "detail": [
    {
      "loc": ["body", "code"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## Rate Limiting

PatchPilot implements basic rate limiting to protect the AI service from excessive usage:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /api/scan` | 30 requests | per minute |
| `POST /api/scan/text` | 30 requests | per minute |
| `POST /api/report/{scan_id}` | 10 requests | per minute |
| All other endpoints | 120 requests | per minute |

### Rate Limit Headers

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 27
X-RateLimit-Reset: 1698753660
```

### Rate Limit Exceeded Response

When the rate limit is exceeded, the API returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 30

{
  "detail": "Rate limit exceeded. Please retry after 30 seconds."
}
```

> **Note**: Rate limiting is applied per IP address. In production, consider using an API key-based rate limiting strategy for more granular control.
