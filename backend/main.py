import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from analysis import router as analysis_router  # noqa: E402
from analysis import system_router  # noqa: E402
from ingest import router as ingest_router  # noqa: E402

app = FastAPI(title="Local AI Security Log Analyzer API")

origins = [o.strip() for o in os.getenv("FRONTEND_ORIGIN", "http://localhost:3000,http://127.0.0.1:3000").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(ingest_router)
app.include_router(analysis_router)
app.include_router(system_router)

@app.get("/api/health")
def health():
    return {"status": "ok", "message": "Security Analyzer API is running"}

