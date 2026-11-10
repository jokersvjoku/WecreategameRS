<p align="center">
  <img src="https://img.shields.io/badge/PATCHPILOT-Cybersecurity-06b6d4?style=for-the-badge&logo=shield&logoColor=white" alt="PATCHPILOT" />
</p>

<h1 align="center">PATCHPILOT</h1>

<p align="center">
  <strong>Find the flaw. Fix the code. Prove the patch.</strong>
</p>

</p>

<p align="center">
  <img src="https://img.shields.io/badge/Track-Open--Weight_AI-10b981?style=flat-square" alt="Open-Weight AI" />
  <img src="https://img.shields.io/badge/AI-Google_Gemma_4-4285F4?style=flat-square" alt="Gemma 4" />
  <img src="https://img.shields.io/badge/Deploy-DigitalOcean-0080FF?style=flat-square" alt="DigitalOcean" />
  <img src="https://img.shields.io/github/license/Swastikvitthare/patchpilot?style=flat-square" alt="License" />
</p>

---

## 🌐 Live Interactive Demo

Test PATCHPILOT directly in your browser without local setup:  
👉 **https://swastikvitthare.github.io/PatchPilot/)**

---

## What is PATCHPILOT?

PATCHPILOT is an AI-powered cybersecurity application that scans Python code for security vulnerabilities, explains them using Google Gemma 4, generates verified patches, and produces professional security reports.

### Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Code Scanner** | Monaco-based code editor with file upload support (.py) |
| 💉 **SQL Injection Detection** | Identifies concatenation, f-strings, and .format() in SQL queries (CWE-89) |
| 🔑 **Credential Detection** | Finds hardcoded passwords, API keys, AWS tokens, and secrets (CWE-798) |
| ⚠️ **Unsafe Eval Detection** | Flags eval(), exec(), os.system(), subprocess shell=True, pickle.loads() |
| 🐍 **Python Static Analysis** | Detects dangerous imports, debug mode, insecure random usage |
| 🤖 **AI Explanations** | Gemma 4 explains each vulnerability in plain language |
| 🩹 **Auto-Patching** | AI-generated security patches with confidence scores |
| ↔️ **Diff Comparison** | Side-by-side original vs. patched code view in Monaco Editor |
| ✅ **Re-scanning** | Verify patches by re-scanning the corrected code |
| 📄 **Downloadable Reports** | Export complete security reports with full analysis |

---

## Quick Start (Local)

### Prerequisites

- Python 3.11+
- Node.js 20+

### 1-Click Launch (Windows)

```bat
git clone https://github.com/Swastikvitthare/patchpilot.git
cd patchpilot
start.bat
```

> `start.bat` automatically checks dependencies and opens the backend on `http://localhost:8000` and the frontend on `http://localhost:3000`.

### Manual Launch

**Backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows (or source venv/bin/activate on Unix)
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Open:
- **App:** http://localhost:3000
- **API Docs:** http://localhost:8000/docs

---

## Architecture

```
patchpilot/
├── backend/               # Python FastAPI backend
│   ├── app/
│   │   ├── main.py        # FastAPI application + CORS
│   │   ├── config.py      # Pydantic Settings
│   │   ├── models/        # Pydantic data models
│   │   ├── routers/       # Scanner, Patcher, Report API routes
│   │   ├── scanners/      # SQL Injection, Credentials, Eval, Python Static
│   │   ├── services/      # Gemma 4 client, Patch generator, PDF report
│   │   └── utils/         # Sanitizer & security limits
│   ├── tests/             # Pytest test suite (26 unit tests)
│   └── demo/              # Vulnerable code examples
├── frontend/              # Next.js 14 TypeScript frontend
│   └── src/
│       ├── app/           # App Router pages (Scanner, Results, Patch, Report)
│       ├── components/    # Monaco Editor, Diff Viewer, Severity Badges
│       ├── lib/           # Typed API client + in-browser fallback scanner
│       └── hooks/         # Scanner state management
├── .github/workflows/     # CI & GitHub Pages automated deployment
└── docker-compose.yml     # Docker deployment configuration
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

---

## AI Configuration (Google Gemma 4)

PATCHPILOT connects to **Google Gemma 4** via DigitalOcean Gradient for:
- Plain-language vulnerability root-cause explanations
- Targeted, contextual security patch synthesis
- Developer fix recommendations

### Environment Variables (.env)

```env
GEMMA_API_KEY=your_api_key_here
GEMMA_API_URL=https://your-gradient-endpoint.digitaloceanspaces.com/v1
GEMMA_MODEL=google/gemma-4-27b-it
DIGITALOCEAN_API_TOKEN=your_token_here
```

### Graceful Degradation

If AI credentials are not provided or the backend is offline:
- ✅ All deterministic security scanners run normally
- ✅ Rule-based verified security patches are generated automatically
- ✅ Re-scanning verification functions 100%
- ✅ Security reports remain downloadable

---

## Security Scanning Rules

### 1. SQL Injection (CWE-89)
- String concatenation in queries (`SELECT ... + user_input`)
- f-string interpolation (`f"SELECT ... {user_input}"`)
- `.format()` formatting (`"SELECT ... {}".format(user_input)`)
- `%` string formatting (`"SELECT ... %s" % user_input`)

### 2. Hardcoded Credentials (CWE-798)
- AWS Access Key IDs (`AKIA...`)
- Variables assigned literal secret strings (`password`, `api_key`, `token`, `secret`)
- Private key patterns and API tokens

### 3. Unsafe Code Execution (CWE-95, CWE-78)
- `eval()` and `exec()` calls
- `os.system()` and command execution
- `subprocess` with `shell=True`
- Insecure deserialization with `pickle.loads()`

### 4. Security Misconfigurations (CWE-94, CWE-338)
- Flask / Django `debug=True` in production
- Use of insecure `random` module for cryptography/tokens
- Insecure `assert` statements used for authorization

---

## Automated Deployment

### GitHub Pages (Frontend)

Every push to `main` automatically triggers the GitHub Actions workflow in `.github/workflows/deploy-pages.yml` to build and deploy to GitHub Pages:
- **URL:** [https://swastikvitthare.github.io/patchpilot/](https://swastikvitthare.github.io/patchpilot/)

### DigitalOcean App Platform (Full Stack)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for full instructions on deploying the FastAPI backend and connecting Gemma 4 inference on DigitalOcean Gradient.

---

## Running Tests

```bash
cd backend
venv\Scripts\activate
python -m pytest tests/test_scanners.py -v
```

---

## License

[MIT](LICENSE)
