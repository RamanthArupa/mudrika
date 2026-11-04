"""FastAPI server-side Mudrika machinery.

Usage:

    router = MudrikaRouter(ledger=ledger, seller_id="mudrika-seller")

    @router.post("/api/v1/forensics/verify")
    @mudrika(cost=15, capability="sam-3.1+muse-spark-forensics")
    async def verify(payload: VerifyRequest):
        ...  # your model call; credits are already deducted

The @mudrika decorator only annotates the endpoint (cost, capability); a custom
APIRoute performs the 402 challenge / Ed25519 verification / atomic charge and
the finalize-or-refund wrap around your handler. Because it is implemented as a
custom route class, dependency injection, request validation and OpenAPI
schemas keep working.

Semantics (documented, deliberate):
- Any non-2xx response or handler exception refunds the credits. A paid
  operation only settles as SUCCEEDED when the buyer got a 2xx.
- 2xx JSON responses are cached and replayed for duplicate idempotency keys.
- Streaming responses are not cached (still charged once, finalized normally).
- Exactly-once *external* execution is not guaranteed (a crash between model
  call and finalize needs reconciliation); exactly-once *charging* is.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute

from .canonical import (
    PROTOCOL_VERSION,
    build_auth_message,
    build_fingerprint,
    sha256_hex,
    verify_message,
)
from .ledger import MudrikaLedger


@dataclass(frozen=True)
class MudrikaEndpointMeta:
    cost: int
    capability: str


def mudrika(*, cost: int, capability: str = "") -> Callable:
    """Mark an endpoint as a paid Mudrika microservice."""
    if not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0:
        raise ValueError("cost must be a positive integer")

    def decorator(fn: Callable) -> Callable:
        fn._mudrika = MudrikaEndpointMeta(cost=cost, capability=capability)  # type: ignore[attr-defined]
        return fn

    return decorator


def MudrikaRouter(*args: Any, ledger: MudrikaLedger, seller_id: str = "mudrika-seller", **kwargs: Any) -> APIRouter:
    """APIRouter whose routes enforce the Mudrika protocol on @mudrika endpoints."""
    router = APIRouter(*args, **kwargs)
    router.route_class = _make_mudrika_route_class(ledger, seller_id)
    return router


def _make_mudrika_route_class(ledger: MudrikaLedger, seller_id: str) -> type[APIRoute]:
    class MudrikaRoute(APIRoute):
        def get_route_handler(self) -> Callable:
            original = super().get_route_handler()
            meta: Optional[MudrikaEndpointMeta] = getattr(self.endpoint, "_mudrika", None)
            if meta is None:
                return original

            async def mudrika_handler(request: Request) -> Response:
                return await self._negotiate(request, original, meta)

            return mudrika_handler

        async def _negotiate(self, request: Request, original: Callable, meta: MudrikaEndpointMeta) -> Response:
            agent_id = request.headers.get("x-mudrika-agent-id")
            idem = request.headers.get("x-mudrika-idempotency-key")
            if not agent_id or not idem:
                return _fail(400, "missing-headers", "X-Mudrika-Agent-ID and X-Mudrika-Idempotency-Key are required")

            body = await request.body()
            # Sign the exact wire target (percent-encoded path + query as sent),
            # not a decoded reconstruction.
            raw_path = (request.scope.get("raw_path") or request.url.path.encode()).decode("latin-1")
            query = (request.scope.get("query_string") or b"").decode("latin-1")
            target = raw_path + (f"?{query}" if query else "")
            fingerprint = build_fingerprint(
                method=request.method,
                request_target=target,
                body_sha256=sha256_hex(body),
                cost=meta.cost,
                idempotency_key=idem,
            )

            signature = request.headers.get("x-mudrika-signature")
            if not signature:
                # Unauthenticated request: always challenge. (Never serve
                # cached results without a valid voucher — the signature is
                # what proves the buyer's authorization.)
                return await self._challenge(request, agent_id, fingerprint, meta)

            public_key_hex = await ledger.get_public_key(agent_id)
            if public_key_hex is None:
                return _fail(402, "unknown-agent", f"agent '{agent_id}' is not registered")

            nonce = request.headers.get("x-mudrika-nonce")
            message = build_auth_message(
                agent_id=agent_id,
                seller_id=seller_id,
                method=request.method,
                request_target=target,
                body_sha256=sha256_hex(body),
                cost=meta.cost,
                nonce=nonce or "",
                idempotency_key=idem,
            )
            if not verify_message(message, signature, public_key_hex):
                return _fail(402, "invalid-signature", "Ed25519 signature does not match the request")

            charge = await ledger.charge(agent_id, idem, nonce or "", fingerprint, meta.cost)

            if charge.status == "SUCCEEDED" and charge.cached_response is not None:
                cached = json.loads(charge.cached_response)
                headers = {**(cached.get("headers") or {}), "X-Mudrika-Cached": "true"}
                if charge.remaining is not None:
                    headers["X-Mudrika-Remaining-Balance"] = str(charge.remaining)
                return Response(
                    status_code=cached["status_code"],
                    content=base64.b64decode(cached["body_b64"]),
                    media_type=cached.get("media_type"),
                    headers=headers,
                )

            if charge.status == "SUCCEEDED":  # cached response missing (non-JSON 2xx)
                return _fail(409, "replay-uncacheable", "operation already settled; response was not cacheable")

            if charge.status == "IN_PROGRESS":
                return _fail(409, "operation-in-progress", "duplicate request while the operation is executing")

            if charge.status == "REFUNDED":
                # Terminal: the operation already failed and was refunded.
                # Re-running it would be executing for free — refuse.
                return _fail(409, "operation-refunded", "operation previously failed and was refunded; start a new operation")

            if charge.status == "CONFLICT":
                return _fail(409, "idempotency-key-conflict", charge.detail)

            if charge.status == "CHALLENGE_INVALID":
                return await self._challenge(request, agent_id, fingerprint, meta)

            if charge.status == "INSUFFICIENT_FUNDS":
                return _fail(402, "insufficient-funds", f"balance {charge.remaining} < cost {meta.cost}")

            if charge.status != "CHARGED":
                # Unknown ledger states fail closed: never execute a paid handler
                # unless the ledger explicitly reported a successful charge.
                return _fail(500, "unknown-ledger-state", f"charge returned unexpected status {charge.status}")

            # CHARGED — run the paid handler, then finalize or refund.
            try:
                response = await original(request)
            except RequestValidationError as exc:
                # Buyer sent a malformed body: refund and report a 422.
                await ledger.finalize(agent_id, idem, "REFUNDED", None)
                return JSONResponse(
                    status_code=422,
                    content={"detail": jsonable_encoder(exc.errors())},
                    headers={"X-Mudrika-Refunded": "true"},
                )
            except HTTPException as exc:
                # Controlled error (validation, business rules): refund and
                # surface the endpoint's own status code with a refund flag.
                await ledger.finalize(agent_id, idem, "REFUNDED", None)
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers={"X-Mudrika-Refunded": "true"},
                )
            except Exception:
                logger.exception("paid handler failed; refunding %s credits to %s", meta.cost, agent_id)
                await ledger.finalize(agent_id, idem, "REFUNDED", None)
                # Return a refund-flagged response so the buyer can restore its
                # local reservation (the exception escapes FastAPI's handler).
                return _fail(
                    502,
                    "handler-failed-refunded",
                    f"paid handler failed; {meta.cost} credits refunded",
                    extra_headers={"X-Mudrika-Refunded": "true"},
                )

            if isinstance(response, StreamingResponse) or getattr(response, "background", None) is not None:
                # Streaming bodies and background tasks execute *after* settlement,
                # breaking the refund guarantee — refuse (and refund) regardless
                # of the status code, before any finalization path.
                reason = (
                    "streaming-not-supported"
                    if isinstance(response, StreamingResponse)
                    else "background-tasks-not-supported"
                )
                await ledger.finalize(agent_id, idem, "REFUNDED", None)
                return _fail(
                    502,
                    reason,
                    f"{reason} by this Mudrika version",
                    extra_headers={"X-Mudrika-Refunded": "true"},
                )

            if 200 <= response.status_code < 300:
                response_json = None
                if hasattr(response, "body"):  # bounded, buffered responses only
                    try:
                        if len(response.body) <= MAX_CACHED_RESPONSE_BYTES:
                            preserved_headers = {
                                k: v
                                for k, v in response.headers.items()
                                if k.lower() not in HOP_BY_HOP_HEADERS
                            }
                            response_json = json.dumps(
                                {
                                    "status_code": response.status_code,
                                    "media_type": response.media_type,
                                    "body_b64": base64.b64encode(response.body).decode("ascii"),
                                    "headers": preserved_headers,
                                }
                            )
                    except Exception:
                        response_json = None
                await ledger.finalize(agent_id, idem, "SUCCEEDED", response_json)
                response.headers["X-Mudrika-Remaining-Balance"] = str(charge.remaining)
                return response

            # Non-2xx: the buyer did not get the service, so refund.
            await ledger.finalize(agent_id, idem, "REFUNDED", None)
            response.headers["X-Mudrika-Refunded"] = "true"
            if charge.remaining is not None:
                response.headers["X-Mudrika-Remaining-Balance"] = str(charge.remaining)
            return response

        async def _challenge(self, request: Request, agent_id: str, fingerprint: str, meta: MudrikaEndpointMeta) -> Response:
            nonce = await ledger.issue_challenge(agent_id, fingerprint, meta.cost, meta.capability)
            # Operation-state hint (state only, never response data): lets the
            # buyer avoid signing a fresh voucher for an operation whose
            # terminal record expired — a replay must not become a new purchase.
            op = await ledger.check_operation(agent_id, request.headers.get("x-mudrika-idempotency-key", ""))
            op_state = (op or {}).get("status", "").lower() or "unknown"
            return JSONResponse(
                status_code=402,
                content={
                    "error": "payment_required",
                    "cost": meta.cost,
                    "capability": meta.capability,
                    "nonce": nonce,
                },
                headers={
                    "X-Mudrika-Version": PROTOCOL_VERSION,
                    "X-Mudrika-Cost": str(meta.cost),
                    "X-Mudrika-Nonce": nonce,
                    "X-Mudrika-Capability": meta.capability,
                    "X-Mudrika-Seller-ID": seller_id,
                    "X-Mudrika-Op-State": op_state,
                },
            )

    return MudrikaRoute


logger = logging.getLogger("mudrika.server")

# Cached (replayed) responses are bounded; larger bodies settle fine but are not cached.
MAX_CACHED_RESPONSE_BYTES = 1_000_000
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}


def _fail(
    status_code: int,
    error: str,
    detail: str,
    extra_headers: Optional[dict] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "detail": detail},
        headers={"X-Mudrika-Error": error, **(extra_headers or {})},
    )
