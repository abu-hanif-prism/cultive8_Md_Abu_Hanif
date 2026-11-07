# Local AI Security Log Analyzer

Scaffold: Next.js (App Router, TypeScript, Tailwind) frontend + FastAPI backend. No AI features yet.

## Backend (http://localhost:8000)
```
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env        # optional
uvicorn main:app --reload --port 8000
```
Health check: `GET /api/health`

## Frontend (http://localhost:3000)
```
cd frontend
npm install
npm run dev
```
Set `NEXT_PUBLIC_API_URL` to override the backend URL.
