"""Medaffin onboarding agent: the buyer side of Mudrika, plus the demo dashboard.

Run:  ISSUER_URL=http://localhost:8000 uvicorn credentials.medaffin_app:app --port 8001

For each healthcare expert who applies to join Medaffin:
1. SAM 3.1 (Meta Model API) segments the uploaded certificate: seal, signature, photo.
2. Muse Spark (Meta Model API) reads the metadata: name, registration number, issuer...
3. The agent opens a case with a per-applicant credit budget. It calls the
   issuer's paid match endpoint, receives HTTP 402, and decides: deterministic
   budget guards first, then Muse Spark Open (Baseten) judges whether the spend
   is worth it. Approval signs an Ed25519 voucher; the issuer charges atomically.
4. The issuer returns a signed near-match result; Medaffin verifies the
   signature and decides: verified, review by the credentialing team, or reject.

Only the cropped regions and the extracted metadata leave Medaffin, never the
full certificate.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from PIL import Image

from mudrika import Decision, MudrikaClient, PurchaseContext
from mudrika.canonical import load_public_key, verify_message

from . import certs, segment
from .meta_client import ModelError, muse_json, muse_open_json

log = logging.getLogger("mudrika.medaffin")
logging.basicConfig(level=logging.INFO)

ISSUER_URL = os.environ.get("ISSUER_URL", "http://localhost:8000").rstrip("/")
ADMIN_TOKEN = os.environ.get("MUDRIKA_ADMIN_TOKEN", "")
AGENT_ID = os.environ.get("MEDAFFIN_AGENT_ID", "medaffin-onboarding-01")
START_CREDITS = int(os.environ.get("MEDAFFIN_START_CREDITS", "300"))
STATIC = Path(__file__).parent / "static"

# --- abuse protection for the public demo -----------------------------------
# Every case spends real Meta / Baseten credits, so the public dashboard is
# gated. Leave DEMO_ACCESS_CODE unset for local runs.
DEMO_ACCESS_CODE = os.environ.get("DEMO_ACCESS_CODE", "")
CASES_PER_IP_PER_HOUR = int(os.environ.get("DEMO_CASES_PER_IP_PER_HOUR", "15"))
CASES_PER_DAY = int(os.environ.get("DEMO_CASES_PER_DAY", "300"))
MAX_UPLOAD_BYTES = int(os.environ.get("DEMO_MAX_UPLOAD_BYTES", str(4 * 1024 * 1024)))
_ip_hits: dict[str, deque] = {}
_day_hits: deque = deque()
# Sample certificates are fixed images: their SAM 3.1 + Muse results are
# cached after the first successful run, so repeat demos cost one decision call.
_SAMPLE_CACHE: dict[str, dict] = {}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def _check_access(code: Optional[str]) -> None:
    if DEMO_ACCESS_CODE and not hmac.compare_digest((code or "").strip(), DEMO_ACCESS_CODE):
        raise HTTPException(401, "access code required: this public demo spends real model credits")


def _rate_limit(request: Request) -> None:
    now = time.time()
    while _day_hits and now - _day_hits[0] > 86400:
        _day_hits.popleft()
    if len(_day_hits) >= CASES_PER_DAY:
        raise HTTPException(429, "daily demo limit reached; run it locally from the README")
    hits = _ip_hits.setdefault(_client_ip(request), deque())
    while hits and now - hits[0] > 3600:
        hits.popleft()
    if len(hits) >= CASES_PER_IP_PER_HOUR:
        raise HTTPException(429, "too many cases from this address; try again in an hour")
    hits.append(now)
    _day_hits.append(now)


def _agent_secret() -> str:
    seed = os.environ.get("AGENT_SIGNING_SEED", "local-dev-agent-seed")
    return hashlib.sha256(seed.encode()).hexdigest()


AGENT_SECRET = _agent_secret()
AGENT_PUBLIC = load_public_key(AGENT_SECRET)
SAMPLES = certs.applicant_samples()

app = FastAPI(title="Medaffin onboarding agent (Mudrika buyer)", version="0.2.0")


async def _admin(method: str, path: str, body: Optional[dict] = None) -> dict:
    async with httpx.AsyncClient(timeout=20) as http:
        resp = await http.request(method, f"{ISSUER_URL}{path}", json=body, headers={"x-admin-token": ADMIN_TOKEN})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, f"issuer admin {path}: {resp.text[:200]}")
    return resp.json()


async def ensure_registered() -> int:
    """Register this agent's public key with the issuer (idempotent) and return the balance."""
    try:
        data = await _admin("POST", "/admin/agents", {
            "agent_id": AGENT_ID, "public_key_hex": AGENT_PUBLIC, "initial_credits": START_CREDITS,
        })
        return int(data["balance"])
    except HTTPException as exc:
        if exc.status_code == 409:
            raise HTTPException(409, "agent id is registered with a different key; change MEDAFFIN_AGENT_ID") from exc
        raise


async def issuer_balance() -> Optional[int]:
    try:
        return int((await _admin("GET", f"/admin/agents/{AGENT_ID}/balance"))["balance"])
    except Exception:
        return None


# ---------------- pages ----------------
@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
async def config():
    return {"access_code_required": bool(DEMO_ACCESS_CODE)}


@app.get("/api/samples")
async def samples():
    return [{"key": s.key, "title": s.title, "description": s.description, "image": f"/samples/{s.key}.png"}
            for s in SAMPLES.values()]


@app.get("/samples/{key}.png")
async def sample_image(key: str):
    if key not in SAMPLES:
        raise HTTPException(404, "unknown sample")
    return Response(certs.to_png(SAMPLES[key].image), media_type="image/png")


@app.get("/api/agent")
async def agent_info():
    balance = None
    issuer = None
    try:
        await ensure_registered()
        balance = await issuer_balance()
        async with httpx.AsyncClient(timeout=10) as http:
            issuer = (await http.get(f"{ISSUER_URL}/.well-known/mudrika")).json()
            issuer["status"] = (await http.get(f"{ISSUER_URL}/status")).json()["status"]
    except Exception as exc:
        log.warning("agent info: %s", exc)
    return {"agent_id": AGENT_ID, "public_key": AGENT_PUBLIC, "balance": balance, "issuer": issuer, "issuer_url": ISSUER_URL}


@app.post("/api/topup")
async def topup(credits: int = Form(100), access_code: str = Form("")):
    _check_access(access_code)
    await ensure_registered()
    return await _admin("POST", f"/admin/agents/{AGENT_ID}/topup", {"credits": max(1, min(credits, 100))})


# ---------------- the onboarding case ----------------
EXTRACT_PROMPT = (
    "This is a medical practitioner's registration certificate. Extract the fields exactly as printed. "
    "Reply with JSON only: {\"name\": str, \"registration_number\": str, \"qualification\": str, "
    "\"issue_date\": str, \"issuer\": str}. Use null for a field you cannot read."
)

DECIDER_SYSTEM = (
    "You are the budget officer of Medaffin's onboarding agent. Medaffin verifies healthcare experts before they "
    "join. A paid credential-match lookup has been quoted by a certificate issuer. Decide whether to approve the "
    "spend. Approve when the issuer is plausibly the body named on the certificate and the lookup fits the budget. "
    "Decline when the issuer does not correspond to the certificate, or the spend would leave no budget for the "
    "case. Reply with JSON only: {\"approve\": true|false, \"summary\": \"<one sentence>\"}"
)


class _Cached(Exception):
    pass


def _same_issuer(a: Optional[str], b: Optional[str]) -> bool:
    norm = lambda v: " ".join((v or "").lower().split())
    return bool(a and b) and (norm(a) in norm(b) or norm(b) in norm(a))


def make_decider(metadata: dict, issuer_name: str, trace: list):
    if segment.offline() or not os.environ.get("BASETEN_API_KEY"):
        async def rule_decider(ctx: PurchaseContext) -> Decision:
            if not _same_issuer(metadata.get("issuer"), issuer_name):
                decision = Decision(approve=False, summary="certificate names a different issuer than the seller; declining")
            else:
                decision = Decision(approve=True, summary="issuer matches the certificate and the lookup fits the case budget")
            trace.append({"step": "decision_model", "source": "offline rule (no Baseten key)",
                          "approve": decision.approve, "summary": decision.summary, "ms": 0})
            return decision

        return rule_decider

    async def decider(ctx: PurchaseContext) -> Decision:
        started = time.perf_counter()
        user = json.dumps({
            "mission": ctx.mission,
            "certificate_issuer": metadata.get("issuer"),
            "seller_issuer": issuer_name,
            "capability": ctx.capability,
            "cost_credits": ctx.cost,
            "case_budget_remaining": ctx.local_remaining,
        })
        try:
            data = await muse_open_json(DECIDER_SYSTEM, user)
            approve = data.get("approve")
            summary = str(data.get("summary", ""))[:280]
            if not isinstance(approve, bool):
                decision = Decision(approve=False, summary="malformed decision; declining by default")
            else:
                decision = Decision(approve=approve, summary=summary or ("approved" if approve else "declined"))
            source = "muse-spark-open (Baseten)"
        except ModelError as exc:
            decision = Decision(approve=False, summary=f"decider unavailable, declining by default: {str(exc)[:120]}")
            source = "fail-closed"
        trace.append({"step": "decision_model", "source": source, "approve": decision.approve,
                      "summary": decision.summary, "ms": int((time.perf_counter() - started) * 1000)})
        return decision

    return decider


def onboarding_outcome(verdict: Optional[str], declined: bool, refunded: bool) -> dict:
    if declined:
        return {"status": "not_checked", "label": "Not checked", "detail": "The agent declined to buy the lookup."}
    if refunded:
        return {"status": "retry", "label": "Issuer unavailable", "detail": "Credits refunded. Retry the case later."}
    return {
        "MATCH": {"status": "verified", "label": "Verified", "detail": "The issuer confirmed this credential."},
        "NEAR_MATCH": {"status": "review", "label": "Credentialing review",
                       "detail": "Close to an issued record but not identical. A credentialing reviewer decides."},
        "NO_MATCH": {"status": "rejected", "label": "Not verified", "detail": "The issuer has no matching record."},
    }.get(verdict or "", {"status": "error", "label": "Error", "detail": "No result from the issuer."})


@app.post("/api/cases")
async def run_case(
    request: Request,
    sample: str = Form("genuine"),
    budget: int = Form(40),
    simulate_issuer_failure: bool = Form(False),
    access_code: str = Form(""),
    upload: Optional[UploadFile] = File(None),
):
    _check_access(access_code)
    _rate_limit(request)
    budget = max(5, min(int(budget), 100))
    case_id = "case-" + uuid.uuid4().hex[:8]
    steps: list[dict] = []
    started_case = time.perf_counter()

    # 1. intake
    truth: Optional[dict] = None
    if upload is not None and upload.filename:
        raw = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"certificate image must be under {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
        try:
            img = Image.open(io.BytesIO(raw)).convert("RGB")
        except Exception as exc:
            raise HTTPException(422, "upload is not an image") from exc
        img.thumbnail((1400, 1400))
        source_label = upload.filename
    else:
        if sample not in SAMPLES:
            raise HTTPException(404, "unknown sample")
        img, truth, source_label = SAMPLES[sample].image, SAMPLES[sample].truth, SAMPLES[sample].title
    cache_key = sample if upload is None or not upload.filename else None
    cached = _SAMPLE_CACHE.get(cache_key) if cache_key else None
    steps.append({"step": "intake", "title": "Expert applies", "status": "ok",
                  "detail": {"source": source_label, "width": img.width, "height": img.height}})

    # 2. SAM 3.1 segmentation (buyer side)
    t = time.perf_counter()
    if cached:
        segs = json.loads(json.dumps(cached["segs"]))
        for item in segs.values():
            if item.get("source") == "sam-3.1":
                item["source"] = "sam-3.1 (cached)"
    else:
        segs = await segment.segment(img, layout_fallback=segment.offline())
    found = {r: s for r, s in segs.items() if s.get("box")}
    steps.append({"step": "segment", "title": "SAM 3.1 segments the certificate",
                  "status": "ok" if found else "warn",
                  "detail": {"regions": segs}, "ms": int((time.perf_counter() - t) * 1000)})
    regions = cached["regions"] if cached else segment.fingerprints(img, segs, with_png=True)

    # 3. Muse Spark metadata extraction
    t = time.perf_counter()
    try:
        if cached:
            raise _Cached()
        if segment.offline():
            if truth is None:
                raise ModelError("offline mode: uploads need META_API_KEY; use a sample certificate")
            raise ModelError("offline mode")
        metadata = await muse_json(EXTRACT_PROMPT, images=[certs.to_png(img)])
        meta_source = os.environ.get("META_MUSE_MODEL", "muse-spark-1.3")
        meta_status = "ok"
    except _Cached:
        metadata, meta_source, meta_status = dict(cached["metadata"]), cached["meta_source"] + " (cached)", "ok"
    except ModelError as exc:
        if truth is None:
            steps.append({"step": "extract", "title": "Muse reads metadata", "status": "error", "detail": str(exc)[:300]})
            return {"case_id": case_id, "steps": steps, "outcome": onboarding_outcome(None, False, False)}
        if segment.offline():
            metadata, meta_source, meta_status = dict(truth), "offline mode: the sample's known fields", "warn"
        else:
            metadata, meta_source, meta_status = dict(truth), f"sample ground truth (model error: {str(exc)[:80]})", "warn"
    metadata = {k: (str(v) if v is not None else None) for k, v in metadata.items()
                if k in ("name", "registration_number", "qualification", "issue_date", "issuer")}
    if cache_key and not cached and meta_status == "ok" and any(v.get("source") == "sam-3.1" for v in segs.values()):
        _SAMPLE_CACHE[cache_key] = {"segs": segs, "regions": regions, "metadata": metadata, "meta_source": meta_source}
    steps.append({"step": "extract", "title": "Muse Spark reads the metadata", "status": meta_status,
                  "detail": {"metadata": metadata, "source": meta_source}, "ms": int((time.perf_counter() - t) * 1000)})

    # 4. Mudrika purchase: 402 -> budget decision -> signed voucher -> atomic charge
    await ensure_registered()
    balance_before = await issuer_balance()
    async with httpx.AsyncClient(timeout=10) as http:
        issuer_info = (await http.get(f"{ISSUER_URL}/.well-known/mudrika")).json()
    decision_trace: list[dict] = []
    client = MudrikaClient(
        agent_id=AGENT_ID,
        secret_key_hex=AGENT_SECRET,
        base_url=ISSUER_URL,
        budget=budget,
        per_call_max=25,
        decider=make_decider(metadata, issuer_info.get("issuer", ""), decision_trace),
        mission=f"Verify the registration certificate of applicant '{metadata.get('name')}' before onboarding to Medaffin",
        timeout=150.0,
    )
    body = {
        "metadata": metadata,
        "regions": regions,
        "case_id": case_id,
        "simulate_issuer_failure": bool(simulate_issuer_failure),
    }
    t = time.perf_counter()
    try:
        resp = await client.post("/api/v1/credentials/match", json_body=body, idempotency_key=case_id)
    finally:
        await client.aclose()
    balance_after = await issuer_balance()
    steps.append({
        "step": "payment", "title": "Mudrika: HTTP 402, budget, signed payment",
        "status": "ok" if resp.charged else ("warn" if resp.declined or resp.refunded else "error"),
        "detail": {
            "case_budget": budget,
            "protocol_trace": resp.trace,
            "decision": decision_trace,
            "charged": resp.charged,
            "refunded": resp.refunded,
            "declined": resp.declined,
            "decision_summary": resp.decision_summary,
            "http_status": resp.status_code,
            "balance_before": balance_before,
            "balance_after": balance_after,
            "case_budget_left": client.remaining_budget,
        },
        "ms": int((time.perf_counter() - t) * 1000),
    })

    # 5. verify the issuer's signed result
    verdict = None
    if resp.status_code == 200 and resp.charged:
        data = resp.json()
        result = data["result"]
        message = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        sig_ok = (data.get("issuer_public_key") == issuer_info.get("issuer_public_key")
                  and verify_message(message, data.get("issuer_signature", ""), issuer_info.get("issuer_public_key", "")))
        verdict = result["verdict"] if sig_ok else None
        steps.append({"step": "match", "title": "Issuer's signed match result",
                      "status": "ok" if sig_ok else "error",
                      "detail": {"signature_valid": sig_ok, "result": result,
                                 "reference_image": f"{ISSUER_URL}/registry/{result['matched_cert_id']}.png"
                                 if result.get("matched_cert_id") else None}})
    elif resp.status_code not in (200, 402):
        try:
            err = resp.json()
        except Exception:
            err = resp.body.decode("utf-8", "replace")[:300]
        steps.append({"step": "match", "title": "Issuer's signed match result", "status": "warn", "detail": {"error": err}})

    outcome = onboarding_outcome(verdict, resp.declined, resp.refunded or (resp.status_code >= 500))
    steps.append({"step": "decision", "title": "Medaffin onboarding decision", "status": "ok", "detail": outcome})
    return {"case_id": case_id, "steps": steps, "outcome": outcome,
            "ms": int((time.perf_counter() - started_case) * 1000)}


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))


if __name__ == "__main__":
    main()
