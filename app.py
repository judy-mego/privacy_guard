"""Local PII Redactor — web UI (runs entirely on your machine).

Run:  uvicorn app:app --reload   →   open http://localhost:8000

Nothing is sent to any external service. The redaction happens locally in
redactor.py; this server just serves the page and runs that function.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

import redactor

app = FastAPI(title="Local PII Redactor", version="1.0")
BASE = Path(__file__).parent


class RedactRequest(BaseModel):
    text: str
    custom_terms: list[str] = []


class RehydrateRequest(BaseModel):
    text: str
    mapping: dict


@app.get("/")
def home():
    return FileResponse(BASE / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "local_only": True}


@app.post("/api/redact")
def redact(req: RedactRequest):
    return redactor.redact(req.text, custom_terms=req.custom_terms)


@app.post("/api/rehydrate")
def rehydrate(req: RehydrateRequest):
    return {"text": redactor.rehydrate(req.text, req.mapping)}
