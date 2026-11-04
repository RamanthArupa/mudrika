"""Integration tests for the Mudrika protocol against real Redis.

Covers: full handshake, tampering (body/price/signature), expired challenges,
idempotent replay, concurrent duplicates, insufficient funds, refund-once
semantics, idempotency-key conflicts, and client-side budget enforcement
under concurrency.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException

from mudrika import (
    Decision,
    MudrikaClient,
    MudrikaLedger,
    build_auth_message,
    generate_keypair,
    load_public_key,
    sha256_hex,
    sign_message,
)
from mudrika.server import MudrikaRouter, mudrika

REDIS_URL = "redis://localhost:6379/15"
SELLER = "seller-1"
AGENT = "agent_medaffin_01"


@pytest_asyncio.fixture
async def redis_client():
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    yield r
    await r.aclose()


@pytest_asyncio.fixture
async def ledger(redis_client):
    return MudrikaLedger(redis_client)


@pytest_asyncio.fixture
async def harness(ledger):
    calls = {"verify": 0, "flaky": 0, "bad_request": 0, "conflict": 0, "decline": 0}

    app = FastAPI()
    router = MudrikaRouter(ledger=ledger, seller_id=SELLER)

    @router.post("/api/v1/forensics/verify")
    @mudrika(cost=15, capability="sam-3.1+muse-spark-forensics")
    async def verify(payload: dict):
        calls["verify"] += 1
        return {"extracted": True, "calls": calls["verify"], "echo": payload}

    @router.post("/api/v1/flaky")
    @mudrika(cost=5, capability="flaky")
    async def flaky(payload: dict):
        calls["flaky"] += 1
        raise RuntimeError("upstream model backend failed")

    @router.post("/api/v1/bad-request")
    @mudrika(cost=3, capability="bad")
    async def bad_request(payload: dict):
        calls["bad_request"] += 1
        raise HTTPException(status_code=422, detail="document unreadable")

    @router.post("/api/v1/conflict")
    @mudrika(cost=5, capability="conflict")
    async def conflict(payload: dict):
        calls["conflict"] += 1
        raise HTTPException(status_code=409, detail="conflicting resource state")

    @router.post("/api/v1/decline")
    @mudrika(cost=5, capability="decline")
    async def decline(payload: dict):
        calls["decline"] += 1
        raise HTTPException(status_code=402, detail="payment required by upstream")

    @router.post("/api/v1/raw")
    @mudrika(cost=2, capability="raw")
    async def raw(payload: dict):
        from fastapi import Response as FastAPIResponse

        calls["raw"] = calls.get("raw", 0) + 1
        return FastAPIResponse(
            content=b"\x89PNG\r\n\x1a\nraw-bytes",
            media_type="application/octet-stream",
            headers={"X-Custom": "v1"},
        )

    @router.post("/api/v1/streaming")
    @mudrika(cost=4, capability="stream")
    async def streaming(payload: dict):
        from fastapi.responses import StreamingResponse

        async def gen():
            yield b"chunk"

        return StreamingResponse(gen(), media_type="text/plain")

    app.include_router(router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as raw:
        yield raw, ledger, calls, app


async def register(ledger, agent_id=AGENT, credits=100):
    keys = generate_keypair()
    await ledger.register_agent(agent_id, load_public_key(keys.secret_hex), credits)
    return keys


def make_client(raw_or_app, keys, agent_id=AGENT, **kwargs):
    if isinstance(raw_or_app, httpx.AsyncClient):
        transport = raw_or_app._transport
    else:
        transport = httpx.ASGITransport(app=raw_or_app)
    kwargs.setdefault("budget", 100)
    return MudrikaClient(
        agent_id=agent_id,
        secret_key_hex=keys.secret_hex,
        base_url="http://testserver",
        transport=transport,
        **kwargs,
    )


def signed_voucher_headers(keys, *, nonce, idem, body, cost=15, agent=AGENT, seller=SELLER, target="/api/v1/forensics/verify"):
    message = build_auth_message(
        agent_id=agent,
        seller_id=seller,
        method="POST",
        request_target=target,
        body_sha256=sha256_hex(body),
        cost=cost,
        nonce=nonce,
        idempotency_key=idem,
    )
    return {
        "X-Mudrika-Agent-ID": agent,
        "X-Mudrika-Idempotency-Key": idem,
        "X-Mudrika-Nonce": nonce,
        "X-Mudrika-Signature": sign_message(message, keys.secret_hex),
        "Content-Type": "application/json",
    }


async def get_challenge(raw, path, idem, body=b"{}", agent=AGENT):
    return await raw.post(
        path,
        content=body,
        headers={
            "X-Mudrika-Agent-ID": agent,
            "X-Mudrika-Idempotency-Key": idem,
            "Content-Type": "application/json",
        },
    )


# --- 1. full handshake ---
async def test_full_handshake_charges_once_and_returns_200(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    result = await client.post("/api/v1/forensics/verify", json_body={"doc": "certificate.png"})

    assert result.status_code == 200
    assert result.charged and result.cost == 15
    assert calls["verify"] == 1
    assert await ledger.get_balance(AGENT) == 85
    assert client.remaining_budget == 85
    assert [e["event"] for e in result.trace] == ["challenge", "decision", "signed_retry", "settled"]
    assert result.headers["x-mudrika-remaining-balance"] == "85"
    await client.aclose()


# --- 2. tampered body: signature no longer matches what the server received ---
async def test_tampered_body_is_rejected_without_charge(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger)

    body_a = json.dumps({"doc": "a"}, sort_keys=True).encode()
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k1", body_a)
    nonce = r1.headers["x-mudrika-nonce"]

    # Sign for body A but transmit body B.
    headers = signed_voucher_headers(keys, nonce=nonce, idem="k1", body=body_a)
    r2 = await raw.post(
        "/api/v1/forensics/verify",
        content=json.dumps({"doc": "b"}, sort_keys=True).encode(),
        headers=headers,
    )
    assert r2.status_code == 402
    assert r2.headers["x-mudrika-error"] == "invalid-signature"
    assert await ledger.get_balance(AGENT) == 100
    assert calls["verify"] == 0


# --- 3. invalid signature ---
async def test_invalid_signature_is_rejected_without_charge(harness):
    raw, ledger, calls, _ = harness
    await register(ledger)
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k2")
    nonce = r1.headers["x-mudrika-nonce"]
    r2 = await raw.post(
        "/api/v1/forensics/verify",
        content=b"{}",
        headers={
            "X-Mudrika-Agent-ID": AGENT,
            "X-Mudrika-Idempotency-Key": "k2",
            "X-Mudrika-Nonce": nonce,
            "X-Mudrika-Signature": "ab" * 64,
        },
    )
    assert r2.status_code == 402
    assert r2.headers["x-mudrika-error"] == "invalid-signature"
    assert await ledger.get_balance(AGENT) == 100


# --- 4. forged price: sign a cheaper cost than the seller quoted ---
async def test_forged_price_is_rejected_without_charge(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger)
    body = b"{}"
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k3", body)
    nonce = r1.headers["x-mudrika-nonce"]
    headers = signed_voucher_headers(keys, nonce=nonce, idem="k3", body=body, cost=1)  # forged price
    r2 = await raw.post("/api/v1/forensics/verify", content=body, headers=headers)
    assert r2.status_code == 402
    assert r2.headers["x-mudrika-error"] == "invalid-signature"
    assert await ledger.get_balance(AGENT) == 100


# --- 5. expired challenge: server re-issues, client recovers, nothing charged for the dead nonce ---
async def test_expired_challenge_reissues_without_charge(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger)
    body = b"{}"
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k4", body)
    nonce = r1.headers["x-mudrika-nonce"]
    # Simulate TTL expiry of that challenge.
    await ledger.redis.delete(f"mudrika:{{{AGENT}}}:challenge:{nonce}")

    # Retry with the dead nonce -> CHALLENGE_INVALID -> fresh 402, no charge.
    headers = signed_voucher_headers(keys, nonce=nonce, idem="k4", body=body)
    r2 = await raw.post("/api/v1/forensics/verify", content=body, headers=headers)
    assert r2.status_code == 402
    assert r2.headers["x-mudrika-nonce"] != nonce  # a fresh challenge was issued
    assert await ledger.get_balance(AGENT) == 100
    assert calls["verify"] == 0


# --- 6. idempotent replay returns the cached response ---
async def test_replay_returns_cached_response_without_recharge(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)
    await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k5")
    assert calls["verify"] == 1

    # The exact request the client would resend after losing the response.
    # An unsigned duplicate is always challenged (no auth bypass), but a
    # signed replay is answered from the operation cache.
    body = json.dumps({"doc": "x"}, sort_keys=True).encode()
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k5", body)
    assert r1.status_code == 402  # unsigned replay is challenged, never served from cache
    headers = signed_voucher_headers(keys, nonce=r1.headers["x-mudrika-nonce"], idem="k5", body=body)
    r2 = await raw.post("/api/v1/forensics/verify", content=body, headers=headers)

    assert r2.status_code == 200
    assert r2.headers.get("x-mudrika-cached") == "true"
    assert r2.json()["calls"] == 1  # executed once, replayed from cache
    assert calls["verify"] == 1
    assert await ledger.get_balance(AGENT) == 85  # charged once
    await client.aclose()


# --- 7. concurrent duplicates: one execution, one debit ---
async def test_concurrent_duplicates_execute_once_and_charge_once(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger)
    body = json.dumps({"doc": "x"}, sort_keys=True).encode()
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k6", body)
    headers = signed_voucher_headers(keys, nonce=r1.headers["x-mudrika-nonce"], idem="k6", body=body)

    r_a, r_b = await asyncio.gather(
        raw.post("/api/v1/forensics/verify", content=body, headers=headers),
        raw.post("/api/v1/forensics/verify", content=body, headers=headers),
    )
    # One executes; the duplicate either conflicts (409 in-progress) or gets the
    # cached response (200 + X-Mudrika-Cached) if the first one already finished.
    statuses = sorted([r_a.status_code, r_b.status_code])
    assert statuses in ([200, 409], [200, 200])
    if statuses == [200, 200]:
        cached = r_a if r_a.headers.get("x-mudrika-cached") else r_b
        assert cached.headers.get("x-mudrika-cached") == "true"
    assert calls["verify"] == 1  # executed once
    assert await ledger.get_balance(AGENT) == 85  # charged once


# --- 8. insufficient funds: no negative balance ---
async def test_insufficient_funds_never_goes_negative(harness):
    raw, ledger, _, app = harness
    keys = await register(ledger, credits=10)
    client = make_client(app, keys)

    result = await client.post("/api/v1/forensics/verify", json_body={})
    assert result.status_code == 402
    assert result.declined
    assert "insufficient funds" in result.decision_summary.replace("insufficient-funds", "insufficient funds")
    assert await ledger.get_balance(AGENT) == 10
    assert client.remaining_budget == 100  # reservation restored
    await client.aclose()


# --- 9. handler failure refunds exactly once ---
async def test_handler_failure_refunds_exactly_once(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    result = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k9")
    assert result.status_code == 502
    assert result.refunded
    assert calls["flaky"] == 1
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100

    # Repeated finalization must not double-refund.
    again = await ledger.finalize(AGENT, "k9", "REFUNDED", None)
    assert again.status == "ALREADY_FINALIZED"
    assert await ledger.get_balance(AGENT) == 100
    await client.aclose()


# --- 10. controlled non-2xx (HTTPException) also refunds ---
async def test_non_2xx_response_refunds(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    result = await client.post("/api/v1/bad-request", json_body={}, idempotency_key="k10")
    assert result.status_code == 422
    assert result.refunded
    assert calls["bad_request"] == 1
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100
    await client.aclose()


# --- 11. idempotency key reuse with different content -> 409, no charge ---
async def test_idempotency_key_reuse_with_different_content_conflicts(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)
    await client.post("/api/v1/forensics/verify", json_body={"doc": "one"}, idempotency_key="k11")
    assert calls["verify"] == 1

    result = await client.post("/api/v1/forensics/verify", json_body={"doc": "two"}, idempotency_key="k11")
    assert result.status_code == 409 and result.declined
    assert "already used for a different request" in result.decision_summary
    assert await ledger.get_balance(AGENT) == 85
    assert calls["verify"] == 1
    assert client.remaining_budget == 85  # the settled operation's books are untouched
    await client.aclose()


# --- 12. client budget: second unaffordable purchase is declined locally ---
async def test_client_declines_when_budget_exhausted(harness):
    raw, ledger, _, app = harness
    keys = await register(ledger)
    client = make_client(app, keys, budget=20)

    first = await client.post("/api/v1/forensics/verify", json_body={})
    assert first.status_code == 200
    second = await client.post("/api/v1/forensics/verify", json_body={})
    assert second.declined
    assert "insufficient local budget" in second.decision_summary
    assert client.remaining_budget == 5
    assert await ledger.get_balance(AGENT) == 85  # server charged once
    await client.aclose()


# --- 13. concurrent client approvals cannot exceed the budget ---
async def test_concurrent_client_purchases_respect_budget(harness):
    raw, ledger, _, app = harness
    keys = await register(ledger)
    client = make_client(app, keys, budget=20)

    async def always_approve(ctx):
        return Decision(approve=True, summary="model approved")

    client.decider = always_approve
    r1, r2 = await asyncio.gather(
        client.post("/api/v1/forensics/verify", json_body={"n": 1}),
        client.post("/api/v1/forensics/verify", json_body={"n": 2}),
    )
    outcomes = sorted([(r1.status_code, r1.declined), (r2.status_code, r2.declined)])
    assert outcomes == [(200, False), (402, True)]  # one succeeds, one declined locally
    assert client.remaining_budget == 5
    assert await ledger.get_balance(AGENT) == 85
    await client.aclose()


# --- 14. malformed decider output declines by default ---
async def test_malformed_decider_declines(harness):
    raw, ledger, _, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    async def broken_decider(ctx):
        return "yes obviously"  # not a Decision

    client.decider = broken_decider
    result = await client.post("/api/v1/forensics/verify", json_body={})
    assert result.declined
    assert await ledger.get_balance(AGENT) == 100
    await client.aclose()


# --- 15. client replay of a settled operation: free, no second approval, even with an exhausted budget ---
async def test_client_replay_of_settled_operation_is_free(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys, budget=25)
    first = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k15")
    assert first.status_code == 200 and first.charged
    assert client.remaining_budget == 10

    # Budget is now too low for a *new* purchase, but replaying the settled
    # operation (same key, same body) returns the cached result for free,
    # without a second purchase approval.
    replay = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k15")
    assert replay.status_code == 200
    assert replay.headers.get("x-mudrika-cached") == "true"
    assert not replay.charged
    assert "replay" in [e["event"] for e in replay.trace]
    assert calls["verify"] == 1
    assert client.remaining_budget == 10  # no new approval or reservation
    assert await ledger.get_balance(AGENT) == 85
    await client.aclose()


# --- 16. a refunded operation must never re-execute ---
async def test_refunded_operation_retry_does_not_reexecute(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    first = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k16")
    assert first.status_code == 502 and first.refunded

    # Retry the SAME key: the client refuses locally (terminal REFUNDED
    # tombstone) — the seller is never even asked, and the handler never
    # re-runs for free.
    retry = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k16")
    assert retry.status_code == 409 and retry.declined
    assert "already refunded" in retry.decision_summary
    assert calls["flaky"] == 1  # executed exactly once
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100  # restored exactly once, no double restore

    # Retrying the work is a NEW operation: new idempotency key. (The flaky
    # handler fails again, is refunded again — one charge, one refund, once.)
    second = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k16b")
    assert second.status_code == 502 and second.refunded
    assert calls["flaky"] == 2
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100
    await client.aclose()


# --- 17. two distinct concurrent purchases competing for insufficient funds ---
async def test_concurrent_purchases_cannot_overdraw(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger, credits=20)  # can afford only ONE 15-credit call
    body = b"{}"

    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k17a", body)
    r2 = await get_challenge(raw, "/api/v1/forensics/verify", "k17b", body)
    h1 = signed_voucher_headers(keys, nonce=r1.headers["x-mudrika-nonce"], idem="k17a", body=body)
    h2 = signed_voucher_headers(keys, nonce=r2.headers["x-mudrika-nonce"], idem="k17b", body=body)

    ra, rb = await asyncio.gather(
        raw.post("/api/v1/forensics/verify", content=body, headers=h1),
        raw.post("/api/v1/forensics/verify", content=body, headers=h2),
    )
    statuses = sorted([ra.status_code, rb.status_code])
    assert statuses == [200, 402]  # one executes, one is refused for funds
    assert calls["verify"] == 1
    assert await ledger.get_balance(AGENT) == 5  # never negative


# --- 18. request validation failure refunds ---
async def test_validation_error_refunds(harness):
    raw, ledger, calls, _ = harness
    keys = await register(ledger)
    r1 = await get_challenge(raw, "/api/v1/forensics/verify", "k18", b"not json at all")
    headers = signed_voucher_headers(keys, nonce=r1.headers["x-mudrika-nonce"], idem="k18", body=b"not json at all")
    r2 = await raw.post(
        "/api/v1/forensics/verify",
        content=b"not json at all",
        headers={**headers, "Content-Type": "application/json"},
    )
    assert r2.status_code == 422
    assert r2.headers.get("x-mudrika-refunded") == "true"
    assert await ledger.get_balance(AGENT) == 100


# --- 19. streaming responses are refused (and refunded), not settled ---
async def test_streaming_response_refused_and_refunded(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    result = await client.post("/api/v1/streaming", json_body={}, idempotency_key="k19")
    assert result.status_code == 502
    assert result.refunded
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100
    await client.aclose()


# --- 20. wallet takeover: re-registration with a different key is rejected ---
async def test_reregistration_with_different_key_rejected(harness):
    raw, ledger, _, _ = harness
    keys = await register(ledger)
    attacker_keys = generate_keypair()
    with pytest.raises(ValueError):
        await ledger.register_agent(AGENT, load_public_key(attacker_keys.secret_hex), 999)
    # Balance untouched by the failed takeover; same-key re-registration is a no-op.
    assert await ledger.get_balance(AGENT) == 100
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)
    assert await ledger.get_balance(AGENT) == 100


# --- 21. a re-challenge quoting a different price must be re-authorized ---
async def test_price_change_on_rechallenge_is_reauthorized():
    import httpx
    from mudrika import MudrikaClient, generate_keypair, load_public_key
    import redis.asyncio as aioredis
    from mudrika import MudrikaLedger

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}
    nonces = iter(["n1", "n2"])

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:  # first challenge: affordable price
            return httpx.Response(402, headers={"x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                                                "x-mudrika-seller-id": "seller-1"})
        if calls["n"] == 2:  # signed retry answered with a fresh, pricier challenge
            return httpx.Response(402, headers={"x-mudrika-cost": "30", "x-mudrika-nonce": "n2",
                                                "x-mudrika-seller-id": "seller-1"})
        if calls["n"] == 3:  # unsigned re-challenge: allowed (the decision comes next)
            return httpx.Response(402, headers={"x-mudrika-cost": "30", "x-mudrika-nonce": "n3",
                                                "x-mudrika-seller-id": "seller-1"})
        raise AssertionError("client must not sign the unaffordable price")

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    result = await client.post("/api/v1/x", json_body={})
    assert result.declined
    assert "quote changed while the operation is unresolved" in result.decision_summary
    assert client.remaining_budget == 5  # reservation retained: the op is unresolved
    assert calls["n"] == 2  # the 30-credit quote was never signed
    await client.aclose()
    await r.aclose()


# --- 22. percent-encoded paths and query strings sign and verify exactly ---
async def test_encoded_path_and_query_handshake(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    result = await client.post("/api/v1/forensics/verify?tag=a%2Fb&x=1", json_body={"doc": "x"})
    assert result.status_code == 200 and result.charged
    assert await ledger.get_balance(AGENT) == 85
    await client.aclose()


# --- 23. concurrent calls with the same idempotency key: one charge total ---
async def test_concurrent_same_key_calls_charge_once(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys, budget=30)

    r1, r2 = await asyncio.gather(
        client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k23"),
        client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k23"),
    )
    outcomes = sorted([r1.status_code, r2.status_code])
    assert outcomes == [200, 200]  # serialized by the per-op lock: execute, then cached replay
    assert calls["verify"] == 1
    assert await ledger.get_balance(AGENT) == 85  # charged once
    assert client.remaining_budget == 15  # one deduction of 15 total
    await client.aclose()


# --- 24. concurrent different-key registrations: exactly one wins ---
async def test_concurrent_registration_race(harness):
    raw, ledger, _, _ = harness
    k1, k2 = generate_keypair(), generate_keypair()
    results = await asyncio.gather(
        ledger.register_agent("race-agent", load_public_key(k1.secret_hex), 50),
        ledger.register_agent("race-agent", load_public_key(k2.secret_hex), 50),
        return_exceptions=True,
    )
    assert sorted(isinstance(e, ValueError) for e in results) == [False, True]
    stored = await ledger.get_public_key("race-agent")
    assert stored in (load_public_key(k1.secret_hex), load_public_key(k2.secret_hex))
    assert await ledger.get_balance("race-agent") == 50


# --- 25. replay after the seller's terminal record expired: refused, never a fresh purchase ---
async def test_replay_after_terminal_expiry_is_refused(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys, budget=20)
    first = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k25")
    assert first.status_code == 200 and first.charged
    assert client.remaining_budget == 5

    # Simulate the seller's terminal retention expiring.
    await ledger.redis.delete(f"mudrika:{{{AGENT}}}:op:k25")

    # The replay must NOT be signed into a fresh purchase — even though the
    # budget could not afford one anyway (double enforcement).
    replay = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k25")
    assert replay.declined
    assert "replay unavailable" in replay.decision_summary  # never re-signed into a new purchase
    assert calls["verify"] == 1  # never re-executed
    assert await ledger.get_balance(AGENT) == 85  # never re-charged
    assert client.remaining_budget == 5  # books unchanged
    await client.aclose()


# --- 26. unknown ledger state fails closed: no execution, no charge ---
async def test_unknown_ledger_state_fails_closed(harness):
    from mudrika.ledger import ChargeResult

    raw, ledger, calls, app = harness

    class WeirdLedger(type(ledger)):
        async def charge(self, *a, **k):
            return ChargeResult(status="GHOST_STATE")

    weird = WeirdLedger(ledger.redis)
    keys = await register(ledger)
    app2 = FastAPI()
    router2 = MudrikaRouter(ledger=weird, seller_id=SELLER)

    @router2.post("/api/v1/ghost")
    @mudrika(cost=5, capability="ghost")
    async def ghost(payload: dict):
        calls["ghost"] = calls.get("ghost", 0) + 1
        return {"ok": True}

    app2.include_router(router2)
    transport = httpx.ASGITransport(app=app2)
    client = MudrikaClient(agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
                          budget=100, transport=transport)
    result = await client.post("/api/v1/ghost", json_body={})
    assert result.status_code == 500
    assert "unknown-ledger-state" in str(result.trace) or any(
        e.get("error") == "unknown-ledger-state" for e in result.trace
    ) or result.headers.get("x-mudrika-error") == "unknown-ledger-state"
    assert calls.get("ghost", 0) == 0  # never executed
    assert await ledger.get_balance(AGENT) == 100  # never charged
    await client.aclose()


# --- 27. lost-success recovery: charge succeeded, response lost, same-voucher retry ---
async def test_lost_success_recovery_deducts_once():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:  # unsigned initial request -> challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1", "x-mudrika-op-state": "unknown"})
        if calls["n"] == 2:  # signed retry: server charges, but the response is lost
            raise httpx.ConnectError("connection dropped after charge")
        # identical-voucher retry: the seller settled the operation -> cached
        assert request.headers.get("x-mudrika-signature"), "must resend the signed voucher"
        return httpx.Response(200, headers={"x-mudrika-cached": "true"}, json={"extracted": True})

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    result = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"})
    assert result.status_code == 200
    assert result.headers.get("x-mudrika-cached") == "true"
    assert not result.charged  # served from the operation cache
    assert client.remaining_budget == 5  # ONE deduction: the charge stood
    events = [e["event"] for e in result.trace]
    assert "ambiguous_timeout" in events and "cached_replay" in events
    await client.aclose()
    await r.aclose()


# --- 28. ambiguous purchase later confirmed refunded: reservation restored exactly once ---
async def test_ambiguous_then_refunded_restores_exactly_once():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:  # challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1", "x-mudrika-op-state": "unknown"})
        if calls["n"] == 2:  # signed retry: response lost (charged? unknown)
            raise httpx.ConnectError("dropped")
        if calls["n"] == 3:  # identical-voucher retry: handler failed, refunded
            return httpx.Response(502, headers={"x-mudrika-refunded": "true"}, json={"error": "handler-failed-refunded"})
        if calls["n"] == 4:  # later attempt, same key: challenge says refunded
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n2",
                "x-mudrika-seller-id": "seller-1", "x-mudrika-op-state": "refunded"})
        # signed retry on the refunded op: terminal refusal
        return httpx.Response(409, headers={"x-mudrika-error": "operation-refunded"}, json={"error": "operation-refunded"})

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    first = await client.post("/api/v1/x", json_body={}, idempotency_key="k28")
    assert first.refunded
    assert client.remaining_budget == 20  # restored exactly once

    # A later attempt on the same key: the challenge reports the op refunded,
    # the client re-authorizes, the seller refuses terminally, and the second
    # reservation is released exactly once (no double restore).
    # Later attempts on the same key: local tombstone declines — the client
    # never re-signs and never even contacts the seller again (so a deleted
    # seller-side terminal record cannot turn into a re-purchase).
    second = await client.post("/api/v1/x", json_body={}, idempotency_key="k28")
    assert second.status_code == 409 and second.declined
    assert "already refunded" in second.decision_summary
    assert client.remaining_budget == 20  # still 20: no double restore
    assert calls["n"] == 3  # no further requests were sent
    await client.aclose()
    await r.aclose()


# --- 29. buffered-response replay preserves exact bytes and relevant headers ---
async def test_replay_preserves_bytes_and_headers(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    first = await client.post("/api/v1/raw", json_body={}, idempotency_key="k29")
    assert first.status_code == 200 and first.charged
    assert first.body == b"\x89PNG\r\n\x1a\nraw-bytes"
    assert first.headers.get("x-custom") == "v1"

    replay = await client.post("/api/v1/raw", json_body={}, idempotency_key="k29")
    assert replay.status_code == 200
    assert replay.headers.get("x-mudrika-cached") == "true"
    assert replay.body == b"\x89PNG\r\n\x1a\nraw-bytes"  # exact bytes, not JSON-mangled
    assert replay.headers.get("x-custom") == "v1"  # relevant headers preserved
    assert replay.headers.get("content-type") == "application/octet-stream"
    assert calls["raw"] == 1
    assert await ledger.get_balance(AGENT) == 98  # charged once
    await client.aclose()


# --- 30. two lost responses, later confirmed refund: reservation restored exactly once ---
async def test_double_loss_then_confirmed_refund_restores_once():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:  # challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1"})
        if calls["n"] in (2, 3):  # both the send and the same-voucher retry are lost
            raise httpx.ConnectError("dropped")
        # later resend of the original voucher: the seller confirms it was refunded
        return httpx.Response(409, headers={"x-mudrika-error": "operation-refunded"},
                              json={"error": "operation-refunded"})

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    first = await client.post("/api/v1/x", json_body={}, idempotency_key="k30")
    assert first.status_code == 0 and first.charged  # ambiguous
    assert client.remaining_budget == 5  # reservation retained

    # The ambiguous op is resolved by RESENDING the original voucher once
    # more: the seller confirms the refund; the reservation is restored
    # exactly once and the key becomes a terminal tombstone.
    second = await client.post("/api/v1/x", json_body={}, idempotency_key="k30")
    assert second.status_code == 409 and second.declined
    assert second.refunded is True
    assert "operation refunded" in second.decision_summary
    assert client.remaining_budget == 20  # restored exactly once
    assert calls["n"] == 4  # the resend; no new voucher was signed

    # Any further same-key attempt is a local decline — no request at all.
    third = await client.post("/api/v1/x", json_body={}, idempotency_key="k30")
    assert third.status_code == 409 and third.declined
    assert "already refunded" in third.decision_summary
    assert calls["n"] == 4
    await client.aclose()
    await r.aclose()


# --- 31. different content on an ambiguous operation: rejected locally, books untouched ---
async def test_different_content_after_ambiguous_rejected_locally():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1"})
        raise httpx.ConnectError("dropped")  # both attempts lost

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    first = await client.post("/api/v1/x", json_body={"doc": "one"}, idempotency_key="k31")
    assert first.status_code == 0  # ambiguous, reservation retained
    assert client.remaining_budget == 5

    # Same key, different body: rejected locally; the original operation's
    # reservation is untouched.
    second = await client.post("/api/v1/x", json_body={"doc": "two"}, idempotency_key="k31")
    assert second.status_code == 409 and second.declined
    assert "already used for a different request" in second.decision_summary
    assert client.remaining_budget == 5  # untouched
    await client.aclose()
    await r.aclose()


# --- 32. lost-success recovery on the REAL seller transport ---
async def test_lost_success_recovery_on_real_transport(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)

    class ResponseDropper:
        """ASGI wrapper: lets the app fully process (charge + execute +
        finalize) the first signed request for an idempotency key, then drops
        its response with a transport error. Later requests pass through."""

        def __init__(self, app, idem):
            self.app = app
            self.idem = idem
            self.signed_signatures = []

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                if headers.get("x-mudrika-idempotency-key") == self.idem and headers.get("x-mudrika-signature"):
                    self.signed_signatures.append(headers["x-mudrika-signature"])
                    if len(self.signed_signatures) == 1:
                        async def swallow(message):
                            pass  # app runs to completion; the response is dropped

                        await self.app(scope, receive, swallow)
                        raise httpx.ConnectError("response lost after charge")
            await self.app(scope, receive, send)

    dropper = ResponseDropper(app, "k32")
    client = make_client(dropper, keys, budget=20)

    result = await client.post("/api/v1/forensics/verify", json_body={"doc": "x"}, idempotency_key="k32")

    # The client resent the IDENTICAL signed voucher (same signature bytes).
    assert len(dropper.signed_signatures) == 2
    assert dropper.signed_signatures[0] == dropper.signed_signatures[1]
    assert result.status_code == 200
    assert result.headers.get("x-mudrika-cached") == "true"
    assert calls["verify"] == 1  # one execution
    assert await ledger.get_balance(AGENT) == 85  # one debit
    assert client.remaining_budget == 5  # one local deduction: the charge stood
    await client.aclose()


# --- 33. a same-price re-challenge must NEVER produce a second signature ---
async def test_same_price_rechallenge_never_resigns():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}
    signatures = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        sig = request.headers.get("x-mudrika-signature")
        if sig:
            signatures.append(sig)
        if calls["n"] == 1:  # challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1"})
        # Any subsequent signed request on this key: a fresh SAME-PRICE
        # challenge (as if the nonce expired). The client must keep resending
        # the ORIGINAL voucher and never sign the new nonce.
        return httpx.Response(402, headers={
            "x-mudrika-cost": "15", "x-mudrika-nonce": "n2",
            "x-mudrika-seller-id": "seller-1"})

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    result = await client.post("/api/v1/x", json_body={}, idempotency_key="k33")
    assert result.declined
    assert "replacement challenge for an unresolved operation" in result.decision_summary
    assert len(set(signatures)) == 1  # exactly one DISTINCT signature for this operation, ever
    assert client.remaining_budget == 5  # reservation retained

    # Repeated retries: the client resends the same voucher, gets the same
    # replacement challenge, declines again — still exactly one signature.
    for _ in range(2):
        again = await client.post("/api/v1/x", json_body={}, idempotency_key="k33")
        assert again.declined
        assert "replacement challenge" in again.decision_summary
    assert len(set(signatures)) == 1  # resends only — never a second signature
    assert client.remaining_budget == 5
    await client.aclose()
    await r.aclose()


# --- 34. refunded tombstone survives seller-side record deletion: no re-purchase ---
async def test_refunded_tombstone_prevents_repurchase_after_record_expiry():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}
    signatures = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        sig = request.headers.get("x-mudrika-signature")
        if sig:
            signatures.append(sig)
        if calls["n"] == 1:  # challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1"})
        if calls["n"] == 2:  # charged, executed, refunded — response says so
            return httpx.Response(502, headers={"x-mudrika-refunded": "true"},
                                  json={"error": "handler-failed-refunded"})
        # From here the seller behaves as if its terminal record expired:
        # any request would get a fresh challenge. The client must never
        # send one on this key.
        raise AssertionError("client must not re-purchase a refunded operation")

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    first = await client.post("/api/v1/x", json_body={}, idempotency_key="k34")
    assert first.refunded
    assert client.remaining_budget == 20

    # Repeated same-key retries: all local tombstone declines. Even with the
    # seller's record gone, there is no new voucher, no execution, no debit,
    # and no budget double-restoration.
    for _ in range(3):
        retry = await client.post("/api/v1/x", json_body={}, idempotency_key="k34")
        assert retry.status_code == 409 and retry.declined
        assert "already refunded" in retry.decision_summary
    assert len(signatures) == 1  # one signature for this operation, ever
    assert calls["n"] == 2  # no further requests were sent
    assert client.remaining_budget == 20  # restored exactly once
    await client.aclose()
    await r.aclose()


# --- 35. refund tombstone vs a DELETED seller terminal record (real harness) ---
async def test_refund_tombstone_survives_seller_record_deletion(harness, redis_client):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    # Count every request the client sends for this idempotency key.
    sent = {"n": 0}

    class RequestCounter:
        def __init__(self, app, idem):
            self.app = app
            self.idem = idem

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                if headers.get("x-mudrika-idempotency-key") == self.idem:
                    sent["n"] += 1
            await self.app(scope, receive, send)

    client = make_client(RequestCounter(app, "k35"), keys)

    first = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k35")
    assert first.status_code == 502 and first.refunded
    assert calls["flaky"] == 1
    assert client.remaining_budget == 100  # restored exactly once
    requests_after_refund = sent["n"]

    # The seller's terminal REFUNDED record is deleted from Redis (as if its
    # retention TTL expired). The client's tombstone must still prevent any
    # re-purchase.
    op_key = f"mudrika:{{{AGENT}}}:op:k35"
    assert await redis_client.exists(op_key) == 1
    assert await redis_client.delete(op_key) == 1
    assert await redis_client.exists(op_key) == 0

    for _ in range(3):
        retry = await client.post("/api/v1/flaky", json_body={}, idempotency_key="k35")
        assert retry.status_code == 409 and retry.declined
        assert "already refunded" in retry.decision_summary

    assert sent["n"] == requests_after_refund  # not a single further request
    assert calls["flaky"] == 1  # never re-executed
    assert await ledger.get_balance(AGENT) == 100  # never re-charged
    assert client.remaining_budget == 100  # never double-restored
    await client.aclose()


# --- 36. insufficient funds on a resend of an AMBIGUOUS op: reservation held ---
async def test_insufficient_funds_after_ambiguous_send_retains_reservation():
    import httpx
    import redis.asyncio as aioredis
    from mudrika import MudrikaClient, MudrikaLedger, generate_keypair, load_public_key

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.flushdb()
    ledger = MudrikaLedger(r)
    keys = generate_keypair()
    await ledger.register_agent(AGENT, load_public_key(keys.secret_hex), 100)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:  # challenge
            return httpx.Response(402, headers={
                "x-mudrika-cost": "15", "x-mudrika-nonce": "n1",
                "x-mudrika-seller-id": "seller-1"})
        if calls["n"] == 2:  # signed send: response lost (charged? unknown)
            raise httpx.ConnectError("dropped")
        if calls["n"] == 3:  # same-voucher retry: server says insufficient funds
            return httpx.Response(402, headers={"x-mudrika-error": "insufficient-funds"},
                                  json={"error": "insufficient-funds"})
        # Later resend of the SAME voucher: the original send did land — cached success.
        return httpx.Response(200, headers={"x-mudrika-cached": "true"}, json={"ok": True})

    client = MudrikaClient(
        agent_id=AGENT, secret_key_hex=keys.secret_hex, base_url="http://testserver",
        budget=20, transport=httpx.MockTransport(handler),
    )
    first = await client.post("/api/v1/x", json_body={}, idempotency_key="k36")
    assert first.status_code == 402 and first.declined
    assert "reservation retained, reconciliation required" in first.decision_summary
    assert client.remaining_budget == 5  # the 15-credit reservation is HELD

    # The lost send later lands: the cached success commits the reservation.
    second = await client.post("/api/v1/x", json_body={}, idempotency_key="k36")
    assert second.status_code == 200
    assert client.remaining_budget == 5  # committed as the spend
    await client.aclose()
    await r.aclose()


# --- 37. a handler-refunded 409 restores the reservation, not "in progress" ---
async def test_handler_raised_409_with_refund_restores_once(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)
    client = make_client(app, keys)

    first = await client.post("/api/v1/conflict", json_body={}, idempotency_key="k37")
    # The handler raised HTTPException(409); the seller refunded it. The
    # client must treat this as a confirmed refund — not "in progress".
    assert first.status_code == 409
    assert first.declined
    assert first.refunded is True
    assert "operation refunded" in first.decision_summary
    assert calls["conflict"] == 1  # executed (and failed) exactly once
    assert await ledger.get_balance(AGENT) == 100  # charged then refunded
    assert client.remaining_budget == 100  # restored exactly once

    # Repeated same-key retries: local tombstone declines, no re-execution,
    # no re-charge, no double restoration.
    for _ in range(2):
        retry = await client.post("/api/v1/conflict", json_body={}, idempotency_key="k37")
        assert retry.status_code == 409 and retry.declined
        assert "already refunded" in retry.decision_summary
    assert calls["conflict"] == 1
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100
    await client.aclose()


# --- 38. a handler-refunded 402 after an ambiguous send restores exactly once ---
async def test_handler_raised_402_with_refund_restores_once(harness):
    raw, ledger, calls, app = harness
    keys = await register(ledger)

    class FirstSignedSendDropped:
        """Raises a transport error on the first signed request for the key;
        later requests reach the app normally."""

        def __init__(self, app, idem):
            self.app = app
            self.idem = idem
            self.signed_seen = 0

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                if headers.get("x-mudrika-idempotency-key") == self.idem and headers.get("x-mudrika-signature"):
                    self.signed_seen += 1
                    if self.signed_seen == 1:
                        raise httpx.ConnectError("dropped before reaching the app")
            await self.app(scope, receive, send)

    wrapper = FirstSignedSendDropped(app, "k38")
    client = make_client(wrapper, keys)

    first = await client.post("/api/v1/decline", json_body={}, idempotency_key="k38")
    # The signed send was lost; the same-voucher retry reached the handler,
    # which raised HTTPException(402) and was refunded by the seller. The
    # client must classify this as a CONFIRMED REFUND — not a challenge.
    assert first.status_code == 402
    assert first.refunded is True
    assert first.declined
    assert "operation refunded" in first.decision_summary
    assert calls["decline"] == 1  # executed (and failed) exactly once
    assert await ledger.get_balance(AGENT) == 100  # charged then refunded
    assert client.remaining_budget == 100  # restored exactly once

    # Repeated same-key retries: local tombstone declines, no re-execution,
    # no re-charge, no double restoration.
    for _ in range(2):
        retry = await client.post("/api/v1/decline", json_body={}, idempotency_key="k38")
        assert retry.status_code == 409 and retry.declined
        assert "already refunded" in retry.decision_summary
    assert calls["decline"] == 1
    assert await ledger.get_balance(AGENT) == 100
    assert client.remaining_budget == 100
    await client.aclose()
