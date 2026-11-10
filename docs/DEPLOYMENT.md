# PATCHPILOT Deployment Guide

## Local Development

### Prerequisites
- Python 3.11+
- Node.js 20+
- pnpm (recommended) or npm
- Git

### Backend Setup
```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
cp ../.env.example ../.env
# Edit ../.env with your configuration

uvicorn app.main:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
pnpm install
cp ../.env.example .env.local
# Edit .env.local — only NEXT_PUBLIC_* variables are needed

pnpm dev
```

### Access
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

---

## Docker Deployment

```bash
# From project root
cp .env.example .env
# Edit .env with real values

docker compose up --build
```

---

## DigitalOcean App Platform

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial PATCHPILOT release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/patchpilot.git
git push -u origin main
```

### Step 2: Create App on DigitalOcean
1. Go to https://cloud.digitalocean.com/apps
2. Click "Create App"
3. Connect your GitHub repository
4. DigitalOcean will detect the `docker-compose.yml` or you can configure manually:

#### Backend Component
- **Source:** `/backend`
- **Type:** Web Service
- **Build Command:** `pip install -r requirements.txt`
- **Run Command:** `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **HTTP Port:** 8000
- **Environment Variables:** Set all from `.env.example`

#### Frontend Component
- **Source:** `/frontend`
- **Type:** Web Service
- **Build Command:** `pnpm install && pnpm build`
- **Run Command:** `pnpm start`
- **HTTP Port:** 3000
- **Environment Variables:**
  - `NEXT_PUBLIC_API_URL` = `https://your-backend-url.ondigitalocean.app/api`

### Step 3: Configure Gemma 4 on DigitalOcean Gradient
1. Go to DigitalOcean Gradient (GPU cloud)
2. Deploy Gemma 4 model endpoint
3. Note the inference endpoint URL and API key
4. Set `GEMMA_API_URL` and `GEMMA_API_KEY` in your backend environment

### Step 4: Configure CORS
Update `CORS_ORIGINS` environment variable to include your frontend production URL.

---

## Environment Variables Reference

| Variable               | Required | Default                          | Description                        |
|------------------------|----------|----------------------------------|------------------------------------|
| GEMMA_API_KEY          | No*      | —                                | API key for Gemma 4 inference      |
| GEMMA_API_URL          | No*      | —                                | Gemma 4 endpoint URL               |
| GEMMA_MODEL            | No       | google/gemma-4-27b-it            | Model identifier                   |
| BACKEND_HOST           | No       | 0.0.0.0                          | Backend bind host                  |
| BACKEND_PORT           | No       | 8000                             | Backend bind port                  |
| CORS_ORIGINS           | No       | http://localhost:3000             | Comma-separated allowed origins    |
| MAX_CODE_SIZE_KB       | No       | 512                              | Max uploaded code size in KB       |
| NEXT_PUBLIC_API_URL    | Yes      | http://localhost:8000/api         | Backend API URL for frontend       |

*Without Gemma 4 credentials, the app runs in degraded mode: scanning works but AI explanations and patches are unavailable.
