"""End-to-end Mudrika demo: one seller, one budget-aware buyer agent.

Shows the full negotiation in the terminal:

    402 challenge -> budget decision -> Ed25519 signed retry -> 200 OK

and a second purchase that the buyer *declines* because the remaining budget
is insufficient — the moment that proves the agent is actually budget-aware.

Run:
    python -m examples.run_demo
"""
from __future__ import annotations

import asyncio
import json

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI

from mudrika import Decision, MudrikaClient, MudrikaLedger, generate_keypair, load_public_key
from mudrika.server import MudrikaRouter, mudrika

AGENT = "agent_medaffin_01"


async def main() -> None:
    redis_client = aioredis.from_url("redis://localhost:6379/15", decode_responses=True)
    # Clean up only this demo agent's ledger state (no blanket FLUSHDB).
    async for key in redis_client.scan_iter(match=f"mudrika:{{{AGENT}}}:*"):
        await redis_client.delete(key)
    ledger = MudrikaLedger(redis_client)

    # --- seller node ---
    app = FastAPI()
    router = MudrikaRouter(ledger=ledger, seller_id="mudrika-seller")

    @router.post("/api/v1/forensics/verify")
    @mudrika(cost=15, capability="sam-3.1+muse-spark-extraction")
    async def verify(body: dict):
        return {"extracted_fields": {"issuer": "EXAMPLE MEDICAL BOARD", "expiry": "2027-04-01"}}

    @router.post("/api/v1/badge/mint")
    @mudrika(cost=20, capability="muse-image-badge")
    async def badge(body: dict):
        return {"badge_url": "https://cdn.example/badge-9f2.png"}

    app.include_router(router)

    # --- buyer agent with a 25-credit budget ---
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    async def smart_buyer(ctx) -> Decision:
        # Stand-in for the Muse Spark Open reasoning callback (examples/baseten_decider.py).
        # Required capability for the mission -> approve; optional -> approve only if rich.
        if "extraction" in ctx.capability:
            return Decision(approve=True, summary="credential extraction is required for the mission")
        if ctx.local_remaining - ctx.cost >= 10:
            return Decision(approve=True, summary="optional badge, but budget allows it")
        return Decision(approve=False, summary="optional badge declined: keep reserve for mission-critical calls")

    transport = httpx.ASGITransport(app=app)
    client = MudrikaClient(
        agent_id=AGENT,
        secret_key_hex=keys.secret_hex,
        base_url="http://testserver",
        budget=25,  # can afford the 15-credit extraction, NOT also the 20-credit badge
        decider=smart_buyer,
        mission="Verify the physician's credential and issue a verification badge",
        transport=transport,
    )

    print("== Purchase 1: credential extraction (15 credits) ==")
    r1 = await client.post("/api/v1/forensics/verify", json_body={"document_image_b64": "a" * 64}, idempotency_key="op-demo-1")
    print(json.dumps(r1.trace, indent=2))
    print(f"-> status={r1.status_code} charged={r1.charged} body={r1.json()}")
    print(f"-> server balance={await ledger.get_balance(AGENT)} local budget={client.remaining_budget}\n")

    print("== Purchase 2: badge mint (20 credits) — buyer must decline ==")
    r2 = await client.post("/api/v1/badge/mint", json_body={"style": "gold"})
    print(json.dumps(r2.trace, indent=2))
    print(f"-> declined={r2.declined} summary={r2.decision_summary!r}")
    print(f"-> server balance={await ledger.get_balance(AGENT)} local budget={client.remaining_budget}\n")

    print("== Purchase 3: same idempotency key as purchase 1 (replay) ==")
    r3 = await client.post("/api/v1/forensics/verify", json_body={"document_image_b64": "a" * 64}, idempotency_key="op-demo-1")
    r4 = await client.post("/api/v1/forensics/verify", json_body={"document_image_b64": "a" * 64}, idempotency_key="op-demo-1")
    print(f"-> statuses: {r3.status_code}, {r4.status_code} (cached={r4.headers.get('x-mudrika-cached')})")
    print(f"-> server balance={await ledger.get_balance(AGENT)} (unchanged: replay is free)\n")

    await client.aclose()
    await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
