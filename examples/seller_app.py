"""Example Mudrika seller node: a paid document-extraction microservice.

Run:
    python -m examples.seller_app            # serves on http://localhost:8000

Endpoints:
    POST /admin/agents                      register an agent (id, public key, credits)
    GET  /admin/agents/{agent_id}/balance
    POST /api/v1/forensics/verify           @mudrika(cost=15) — the paid service

The paid handler is where you plug in the Meta Model API calls (SAM 3.1
segmentation via POST /v1/responses + Muse Spark multimodal extraction). The
mock below keeps the example runnable without credentials.
"""
from __future__ import annotations

import os

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from mudrika import MudrikaLedger, generate_keypair, load_public_key
from mudrika.server import MudrikaRouter, mudrika

REDIS_URL = os.environ.get("MUDRIKA_REDIS_URL", "redis://localhost:6379/0")
SELLER_ID = "mudrika-seller"
# Optional: when set, admin routes (agent registration / funding) require
# this token. In production, registration and top-ups MUST sit behind trusted,
# authenticated administration — never public.
ADMIN_TOKEN = os.environ.get("MUDRIKA_ADMIN_TOKEN")

app = FastAPI(title="Mudrika Seller Node", version="0.1.0")
redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
ledger = MudrikaLedger(redis_client)
router = MudrikaRouter(ledger=ledger, seller_id=SELLER_ID)


def _require_admin(request: Request) -> None:
    """Fail closed: admin routes are disabled unless a token is configured."""
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="admin endpoints disabled: set MUDRIKA_ADMIN_TOKEN to enable agent registration/funding",
        )
    if request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin token required")


class RegisterAgent(BaseModel):
    agent_id: str
    public_key_hex: str = Field(min_length=64)
    initial_credits: int = Field(default=100, gt=0)


@app.post("/admin/agents")
async def register_agent(body: RegisterAgent, request: Request):
    _require_admin(request)
    await ledger.register_agent(body.agent_id, body.public_key_hex, body.initial_credits)
    return {"agent_id": body.agent_id, "initial_credits": body.initial_credits}


@app.get("/admin/agents/{agent_id}/balance")
async def balance(agent_id: str, request: Request):
    _require_admin(request)
    return {"agent_id": agent_id, "balance": await ledger.get_balance(agent_id)}


class VerifyRequest(BaseModel):
    document_image_b64: str


@router.post("/api/v1/forensics/verify")
@mudrika(cost=15, capability="sam-3.1+muse-spark-extraction")
async def verify(body: VerifyRequest):
    """Paid microservice: segment the document, extract structured fields.

    Credits were already deducted atomically before this handler ran; if this
    handler fails, the middleware refunds them. Plug the Meta Model API calls
    here, e.g.:

        # SAM 3.1: segment stamps/seals/signatures
        #   POST https://api.meta.ai/v1/responses  model="sam-3.1"
        # Muse Spark: structured extraction from the cropped regions
        #   POST https://api.meta.ai/v1/responses  model="muse-spark-1.3"
    """
    if len(body.document_image_b64) < 32:
        raise HTTPException(status_code=422, detail="document image too small to analyze")
    return {
        "capability": "sam-3.1+muse-spark-extraction",
        "stamps_detected": 1,
        "signatures_detected": 1,
        "extracted_fields": {"issuer": "EXAMPLE MEDICAL BOARD", "expiry": "2027-04-01"},
        "note": "extraction + consistency check; issuer authenticity requires an authoritative registry",
    }


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
