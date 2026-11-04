"""Issuer node: a (fictional) medical council selling credential matches over Mudrika.

Run:  uvicorn credentials.issuer_app:app --port 8000

On startup the issuer segments every certificate it has issued with SAM 3.1
and stores the regions' fingerprints in its reference index (Redis). The paid
endpoint near-matches a submitted certificate (metadata + SAM crops) against
that index and returns a result signed with the issuer's Ed25519 key.

Pricing: 15 credits per lookup. A completed lookup is charged whatever the
verdict; credits are refunded only when the issuer fails to produce a result.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from mudrika import MudrikaLedger
from mudrika.canonical import load_public_key, sign_message
from mudrika.server import MudrikaRouter, mudrika

from . import certs, matching, segment
from .meta_client import ModelError, muse_json
from .vision import from_b64

log = logging.getLogger("mudrika.issuer")
logging.basicConfig(level=logging.INFO)

REDIS_URL = os.environ.get("MUDRIKA_REDIS_URL", "redis://localhost:6379/0")
SELLER_ID = os.environ.get("MUDRIKA_SELLER_ID", "demo-medical-council")
ADMIN_TOKEN = os.environ.get("MUDRIKA_ADMIN_TOKEN")
DEMO_MODE = os.environ.get("MUDRIKA_DEMO", "1") == "1"
MATCH_COST = int(os.environ.get("MUDRIKA_MATCH_COST", "15"))
INDEX_KEY = f"mudrika:issuer:{SELLER_ID}:index:v2"


def _issuer_secret() -> str:
    seed = os.environ.get("ISSUER_SIGNING_SEED", "local-dev-issuer-seed")
    return hashlib.sha256(seed.encode()).hexdigest()


ISSUER_SECRET = _issuer_secret()
ISSUER_PUBLIC = load_public_key(ISSUER_SECRET)

app = FastAPI(title="Mudrika issuer node — Demo Medical Council", version="0.2.0")
redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
ledger = MudrikaLedger(redis_client)
router = MudrikaRouter(ledger=ledger, seller_id=SELLER_ID)

STATE: dict = {"index": [], "status": "starting", "started_at": time.time(), "detail": ""}


# ---------------- reference index ----------------
async def build_index(force: bool = False) -> None:
    STATE["status"] = "indexing"
    index: list[dict] = []
    for record in certs.REGISTRY:
        cached = None if force else await redis_client.hget(INDEX_KEY, record.cert_id)
        if cached:
            index.append(json.loads(cached))
            continue
        img = certs.render(record)
        segs = await segment.segment(img, layout_fallback=True)
        entry = {
            "cert_id": record.cert_id,
            "metadata": record.metadata(),
            "segments": segs,
            "regions": segment.fingerprints(img, segs, with_png=True),
            "indexed_at": int(time.time()),
        }
        # Cache once SAM found at least one region, so restarts don't re-spend
        # SAM 3.1 credits; a total API failure is retried on the next start.
        # POST /admin/reindex forces a rebuild.
        if any(s["source"] == "sam-3.1" for s in segs.values()):
            await redis_client.hset(INDEX_KEY, record.cert_id, json.dumps(entry))
        index.append(entry)
        log.info("indexed %s: %s", record.cert_id, {r: s["source"] for r, s in segs.items()})
    STATE["index"] = index
    STATE["status"] = "ready"


@app.on_event("startup")
async def _startup() -> None:
    async def runner() -> None:
        try:
            await build_index()
        except Exception as exc:  # keep serving; /status shows the failure
            log.exception("index build failed")
            STATE["status"] = "failed"
            STATE["detail"] = str(exc)[:300]

    asyncio.create_task(runner())


NOTICE = ("Machine-to-machine API for the open-source Mudrika demo. The 'Demo Medical Council' and all "
          "certificates are fictional. Source: https://github.com/RamanthArupa/mudrika")


@app.middleware("http")
async def _no_index(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /\n"


# ---------------- admin (trusted) ----------------
def _require_admin(request: Request) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(503, "admin endpoints disabled: set MUDRIKA_ADMIN_TOKEN")
    if request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise HTTPException(403, "admin token required")


class RegisterAgent(BaseModel):
    agent_id: str
    public_key_hex: str = Field(min_length=64, max_length=64)
    initial_credits: int = Field(default=100, ge=0)


class TopUp(BaseModel):
    credits: int = Field(gt=0, le=10_000)


@app.post("/admin/agents")
async def register_agent(body: RegisterAgent, request: Request):
    _require_admin(request)
    try:
        await ledger.register_agent(body.agent_id, body.public_key_hex, body.initial_credits)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"agent_id": body.agent_id, "balance": await ledger.get_balance(body.agent_id)}


@app.post("/admin/agents/{agent_id}/topup")
async def top_up(agent_id: str, body: TopUp, request: Request):
    """Simulated credit-pack purchase: no real money moves in this MVP."""
    _require_admin(request)
    if await ledger.get_public_key(agent_id) is None:
        raise HTTPException(404, "unknown agent")
    return {"agent_id": agent_id, "balance": await ledger.top_up(agent_id, body.credits)}


@app.get("/admin/agents/{agent_id}/balance")
async def balance(agent_id: str, request: Request):
    _require_admin(request)
    return {"agent_id": agent_id, "balance": await ledger.get_balance(agent_id)}


@app.post("/admin/reindex")
async def reindex(request: Request):
    _require_admin(request)
    await redis_client.delete(INDEX_KEY)
    asyncio.create_task(build_index(force=True))
    return {"status": "reindexing"}


# ---------------- public ----------------
@app.get("/")
async def root():
    return {
        "service": "Mudrika issuer node",
        "notice": NOTICE,
        "issuer": certs.ISSUER,
        "seller_id": SELLER_ID,
        "status": STATE["status"],
        "certificates_indexed": len(STATE["index"]),
        "docs": "/docs",
    }


@app.get("/.well-known/mudrika")
async def well_known():
    return {
        "protocol": "mudrika/1.0",
        "notice": NOTICE,
        "seller_id": SELLER_ID,
        "issuer": certs.ISSUER,
        "issuer_public_key": ISSUER_PUBLIC,
        "offers": [{
            "method": "POST",
            "path": "/api/v1/credentials/match",
            "cost": MATCH_COST,
            "capability": "credential-match:sam-3.1",
            "charged_when": "a match result is produced (any verdict); refunded on issuer failure",
        }],
    }


@app.get("/status")
async def status():
    return {
        "status": STATE["status"],
        "detail": STATE["detail"],
        "index": [
            {"cert_id": e["cert_id"], "sources": {r: s["source"] for r, s in e["segments"].items()}}
            for e in STATE["index"]
        ],
    }


@app.get("/registry/{cert_id}.png")
async def registry_image(cert_id: str):
    """Reference certificate image (fictional data) for the dashboard."""
    for record in certs.REGISTRY:
        if record.cert_id == cert_id:
            return Response(certs.to_png(certs.render(record)), media_type="image/png")
    raise HTTPException(404, "unknown certificate")


# ---------------- paid lookup ----------------
class RegionFingerprint(BaseModel):
    dhash: str = Field(pattern=r"^[0-9a-f]{16,64}$")
    color: list[int] = Field(min_length=3, max_length=3)
    size: list[int] = Field(default_factory=list)
    png_b64: Optional[str] = Field(default=None, max_length=400_000)


class MatchRequest(BaseModel):
    metadata: dict[str, Optional[str]]
    regions: dict[str, RegionFingerprint] = Field(default_factory=dict)
    case_id: str = ""
    simulate_issuer_failure: bool = False


async def _adjudicate(region: str, submitted_png: str, reference_png: str) -> Optional[dict]:
    """Ask Muse Spark to compare a submitted crop with the issuer's reference crop."""
    sub, ref = from_b64(submitted_png), from_b64(reference_png)
    if sub is None or ref is None:
        return None
    try:
        return await muse_json(
            "Image 1 is the official " + region + " on a certificate we issued. Image 2 is the " + region
            + " cropped from a certificate someone submitted. Do they come from the same original "
            + "(ignore scan noise, scale and slight rotation)? Reply with JSON only: "
            + '{"same_origin": true|false, "confidence": 0-1, "reason": "<one sentence>"}',
            images=[certs.to_png(ref), certs.to_png(sub)],
        )
    except ModelError as exc:
        log.warning("adjudication failed: %s", exc)
        return None


@router.post("/api/v1/credentials/match")
@mudrika(cost=MATCH_COST, capability="credential-match:sam-3.1")
async def credential_match(body: MatchRequest):
    """Paid: near-match a submitted certificate against the issuer's SAM-segmented index.

    Credits are already deducted when this runs; any exception refunds them.
    """
    if body.simulate_issuer_failure and DEMO_MODE:
        raise HTTPException(503, "issuer registry temporarily unavailable (simulated)")
    if STATE["status"] != "ready":
        raise HTTPException(503, f"reference index not ready ({STATE['status']})")

    regions = {k: v.model_dump() for k, v in body.regions.items()}
    result = matching.match(body.metadata, regions, STATE["index"])
    best = result["best"]

    adjudication = {}
    if result["verdict"] == "NEAR_MATCH":
        ref = next(e for e in STATE["index"] if e["cert_id"] == best["cert_id"])
        for region, score in best["visual_detail"].items():
            sub_png = regions.get(region, {}).get("png_b64")
            ref_png = ref["regions"].get(region, {}).get("png_b64")
            if score < 0.75 and sub_png and ref_png:
                verdict = await _adjudicate(region, sub_png, ref_png)
                if verdict is not None:
                    adjudication[region] = verdict

    payload = {
        "issuer": certs.ISSUER,
        "seller_id": SELLER_ID,
        "case_id": body.case_id,
        "verdict": result["verdict"],
        "matched_cert_id": best["cert_id"] if result["verdict"] != "NO_MATCH" else None,
        "matched_fields": best["metadata_detail"],
        "scores": {
            "metadata": best["metadata_score"],
            "visual": best["visual_score"],
            "total": best["total_score"],
            "regions": best["visual_detail"],
        },
        "flags": result["flags"],
        "adjudication": adjudication,
        "models": ["sam-3.1 (issuer index)", "muse-spark (adjudication)" if adjudication else None],
        "issued_at": int(time.time()),
    }
    payload["models"] = [m for m in payload["models"] if m]
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {"result": payload, "issuer_signature": sign_message(message, ISSUER_SECRET), "issuer_public_key": ISSUER_PUBLIC}


app.include_router(router)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))


if __name__ == "__main__":
    main()
