# PATCHPILOT Architecture

> Find the flaw. Fix the code. Prove the patch.

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    PATCHPILOT                            │
│                                                          │
│  ┌──────────────┐         ┌──────────────────────────┐  │
│  │   Frontend    │  HTTP   │        Backend           │  │
│  │   Next.js     │◄──────►│        FastAPI           │  │
│  │   TypeScript  │  JSON   │        Python            │  │
│  │   Tailwind    │         │                          │  │
│  │   Monaco      │         │  ┌────────────────────┐  │  │
│  └──────────────┘         │  │  Security Engine    │  │  │
│                           │  │                    │  │  │
│                           │  │  ├─ SQL Injection  │  │  │
│                           │  │  ├─ Hardcoded Cred │  │  │
│                           │  │  ├─ Unsafe Eval    │  │  │
│                           │  │  └─ Python Static  │  │  │
│                           │  └────────────────────┘  │  │
│                           │                          │  │
│                           │  ┌────────────────────┐  │  │
│                           │  │  AI Service        │  │  │
│                           │  │  Gemma 4 via       │  │  │
│                           │  │  DigitalOcean      │  │  │
│                           │  │  Gradient          │  │  │
│                           │  └────────────────────┘  │  │
│                           │                          │  │
│                           │  ┌────────────────────┐  │  │
│                           │  │  Report Generator  │  │  │
│                           │  │  PDF / JSON        │  │  │
│                           │  └────────────────────┘  │  │
│                           └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Security Scanning Pipeline

1. **Input Validation** — Code size limits, language detection, sanitization
2. **AST Parsing** — Python code parsed into Abstract Syntax Tree (never executed)
3. **Rule Evaluation** — Each scanner runs against the AST/source independently
4. **Result Aggregation** — Vulnerabilities merged, deduplicated, severity-ranked
5. **AI Analysis** — Gemma 4 explains vulnerabilities and generates patches
6. **Patch Validation** — Re-scan patched code to verify fixes
7. **Report Generation** — PDF/JSON report with before/after comparison

## Scanner Details

### SQL Injection Scanner
- Detects string concatenation in SQL queries
- Identifies f-string interpolation in queries
- Flags `.format()` usage in query strings
- Checks for missing parameterized queries

### Hardcoded Credentials Scanner
- Regex patterns for passwords, API keys, tokens, secrets
- Entropy analysis for high-randomness strings
- Known credential variable name patterns
- AWS, GitHub, Slack token format detection

### Unsafe Eval Scanner
- AST detection of `eval()`, `exec()`, `compile()`
- `os.system()`, `subprocess` with `shell=True`
- `pickle.loads()` on untrusted data
- `__import__()` with user input

### Python Static Scanner
- Import of known-dangerous modules
- Missing input validation patterns
- Insecure default configurations
- Debug mode in production settings

## API Design

| Method | Endpoint       | Purpose                          |
|--------|---------------|----------------------------------|
| POST   | /api/scan     | Submit code for security scanning |
| POST   | /api/patch    | Generate AI security patches      |
| POST   | /api/rescan   | Re-scan patched code              |
| POST   | /api/report   | Generate downloadable report      |
| GET    | /api/health   | Service health check              |

## Technology Stack

| Layer      | Technology                      |
|-----------|--------------------------------|
| Frontend  | Next.js 14, TypeScript, Tailwind CSS, Monaco Editor |
| Backend   | Python 3.11, FastAPI, Pydantic v2 |
| AI        | Google Gemma 4 via DigitalOcean Gradient |
| Scanning  | AST, regex, custom rules       |
| Reports   | ReportLab (PDF), JSON           |
| CI/CD     | GitHub Actions                  |
| Deploy    | DigitalOcean App Platform       |

## Security Principles

1. **No Code Execution** — User code is NEVER executed on the server
2. **AST-Only Analysis** — All analysis is done via parsing, not running
3. **Input Limits** — Maximum code size enforced (512KB default)
4. **No Credential Storage** — All API keys via environment variables
5. **Stateless** — No database required; scan results returned immediately
