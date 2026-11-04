"""MudrikaClient: a budget-aware buyer that negotiates HTTP 402 handshakes.

Flow per purchase:
1. Send the request with an idempotency key (no payment headers).
2. On 402, evaluate the quoted cost:
   - deterministic guards first (valid quote, per-call limit, local remaining
     budget) — enforced in code, never by the model;
   - then an optional async decision callback (e.g. Muse Spark Open reasoning
     about whether the spend is worth it for the mission);
3. Sign the canonical voucher with Ed25519, store it on the operation record,
   and send it.
4. Settle: commit the local reservation on authenticated success (including a
   cached replay of an operation whose charge succeeded but whose response was
   lost); restore it exactly once on a confirmed refund or a definitive
   no-charge rejection; keep it on ambiguous outcomes (needs reconciliation).

Core safety invariant: **one operation owns one voucher, forever.** Every
subsequent attempt of the same operation resends the *original* signed voucher —
the client NEVER signs a second challenge for an operation that already has a
voucher, not even at the same price, and not even when the nonce simply
expired. A replacement challenge for an UNRESOLVED operation (expired nonce
or changed quote) never gets a second signature and never releases the
reservation — the op stays exactly as it is pending reconciliation.
Definitive no-charge rejections (insufficient funds, rejected signature) and
confirmed refunds retire the operation: the reservation is restored exactly
once and the record is kept as a terminal tombstone (FAILED/REFUNDED) bound
to the original fingerprint, so the key can never be re-signed or re-purchased
— retrying the work requires a new idempotency key. If the seller no longer
recognizes an operation that was charged (terminal record expired), the
resend gets a fresh challenge and the client reports "replay unavailable,
reconcile" instead of signing a new purchase. Budget authority is code, not
the model.

The client signs the exact wire target (percent-encoded path + query, as httpx
transmits it) and the exact body bytes. Absolute URLs are rejected unless they
match the configured seller origin (checked on the prepared request, so
protocol-relative and unusual forms are caught too). Same-key requests with
different content are rejected locally without touching the operation's books.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

from .canonical import PROTOCOL_VERSION, build_auth_message, sha256_hex, sign_message

DecisionCallback = Callable[["PurchaseContext"], Awaitable["Decision"]]

OP_RESERVED = "reserved"
OP_SETTLED = "settled"
OP_REFUNDED = "refunded"
OP_FAILED = "failed"
OP_TERMINAL = (OP_SETTLED, OP_REFUNDED, OP_FAILED)


@dataclass
class Decision:
    """A purchase decision. Malformed decisions are treated as declines."""

    approve: bool
    summary: str


@dataclass
class PurchaseContext:
    capability: str
    cost: int
    local_remaining: int
    mission: str
    endpoint: str


@dataclass
class MudrikaResponse:
    """Outcome of one client.post() call, including the negotiation trace."""

    status_code: int
    headers: httpx.Headers
    body: bytes
    charged: bool = False
    refunded: bool = False
    declined: bool = False
    decision_summary: str = ""
    cost: int = 0
    trace: list[dict[str, Any]] = field(default_factory=list)

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


@dataclass
class _Voucher:
    """A signed payment voucher for one operation. Immutable once used."""

    nonce: str
    signature: str
    headers: dict  # complete headers to send (incl. agent id, idem key, sig)
    body: bytes
    target: str
    cost: int


@dataclass
class _Op:
    """Client-side operation record. One operation owns one reservation."""

    state: str  # OP_RESERVED | OP_SETTLED | OP_REFUNDED | OP_FAILED
    cost: int
    reserved: int  # outstanding local budget held for this operation
    fingerprint: tuple  # (wire target, body sha256)
    voucher: Optional[_Voucher] = None
    charged_ever: bool = False  # any evidence the seller processed a charge
    ambiguous: bool = False  # a paid send's response was lost at least once


class MudrikaClient:
    def __init__(
        self,
        *,
        agent_id: str,
        secret_key_hex: str,
        base_url: str,
        budget: int,
        per_call_max: Optional[int] = None,
        decider: Optional[DecisionCallback] = None,
        mission: str = "",
        timeout: float = 30.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.agent_id = agent_id
        self.secret_key_hex = secret_key_hex
        self.base_url = base_url.rstrip("/")
        self.per_call_max = per_call_max
        self.decider = decider
        self.mission = mission
        self._remaining = budget
        self._lock = asyncio.Lock()
        self._ops: dict[str, _Op] = {}
        self._op_locks: dict[str, asyncio.Lock] = {}
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            follow_redirects=False,  # never re-send a signed voucher to another origin
        )

    @property
    def remaining_budget(self) -> int:
        return self._remaining

    async def aclose(self) -> None:
        await self._http.aclose()

    # --- request preparation (origin enforcement + exact wire target) ---
    def _prepare(self, path: str, body: bytes, headers: dict) -> tuple[httpx.Request, str]:
        """Build (but do not send) the request; return it with the exact wire
        target that will be signed and transmitted.

        The origin check runs on the *prepared* request, so protocol-relative
        URLs and other unusual forms cannot slip a signed voucher to another
        origin.
        """
        request = self._http.build_request("POST", path, content=body, headers=headers)
        url, base = request.url, httpx.URL(self.base_url)
        if (url.scheme, url.host, url.port) != (base.scheme, base.host, base.port):
            raise ValueError(
                f"request target {str(url)} does not match the configured seller origin {self.base_url}"
            )
        return request, url.raw_path.decode("latin-1")

    async def _send_prepared(self, request: httpx.Request) -> httpx.Response:
        return await self._http.send(request)

    def _op_lock(self, idem: str) -> asyncio.Lock:
        lock = self._op_locks.get(idem)
        if lock is None:
            lock = asyncio.Lock()
            self._op_locks[idem] = lock
        return lock

    def _parse_challenge(self, resp: httpx.Response) -> dict:
        return {
            "cost": int(resp.headers["x-mudrika-cost"]),
            "nonce": resp.headers["x-mudrika-nonce"],
            "capability": resp.headers.get("x-mudrika-capability", ""),
            "seller_id": resp.headers.get("x-mudrika-seller-id", ""),
        }

    def _build_voucher(
        self,
        challenge: dict,
        body: bytes,
        target: str,
        idem: str,
        base_headers: dict,
    ) -> _Voucher:
        message = build_auth_message(
            agent_id=self.agent_id,
            seller_id=challenge["seller_id"],
            method="POST",
            request_target=target,
            body_sha256=sha256_hex(body),
            cost=challenge["cost"],
            nonce=challenge["nonce"],
            idempotency_key=idem,
        )
        signature = sign_message(message, self.secret_key_hex)
        headers = {
            **base_headers,
            "X-Mudrika-Nonce": challenge["nonce"],
            "X-Mudrika-Signature": signature,
        }
        return _Voucher(
            nonce=challenge["nonce"],
            signature=signature,
            headers=headers,
            body=body,
            target=target,
            cost=challenge["cost"],
        )

    async def _retire_op(self, idem: str, op: _Op, state: str) -> None:
        """Retire an operation WITHOUT deleting it.

        The reservation (if any) is restored exactly once and the record is
        kept as a terminal tombstone bound to the original fingerprint, so the
        idempotency key can never be re-signed or re-purchased. Retrying the
        work requires a new idempotency key (a new operation).
        """
        op.state = state
        if op.reserved > 0:
            async with self._lock:
                self._remaining += op.reserved
            op.reserved = 0

    # --- purchase flow ---
    async def post(
        self,
        path: str,
        *,
        json_body: Optional[dict] = None,
        headers: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> MudrikaResponse:
        idem = idempotency_key or uuid.uuid4().hex
        async with self._op_lock(idem):
            return await self._post_locked(path, json_body, headers, idem)

    async def _post_locked(
        self,
        path: str,
        json_body: Optional[dict],
        headers: Optional[dict],
        idem: str,
    ) -> MudrikaResponse:
        body = json.dumps(json_body, sort_keys=True).encode() if json_body is not None else b""
        trace: list[dict[str, Any]] = []
        base_headers = {
            "X-Mudrika-Agent-ID": self.agent_id,
            "X-Mudrika-Idempotency-Key": idem,
            "X-Mudrika-Version": PROTOCOL_VERSION,
            **({"Content-Type": "application/json"} if json_body is not None else {}),
            **(headers or {}),
        }
        unsigned_request, target = self._prepare(path, body, base_headers)
        fingerprint = (target, sha256_hex(body))

        op = self._ops.get(idem)
        if op is not None and op.state in (OP_REFUNDED, OP_FAILED):
            # Terminal no-charge tombstone: the key is burned for this content.
            trace.append({"event": "rejected", "error": f"operation_{op.state}", "local": True})
            return MudrikaResponse(
                status_code=409,
                headers=httpx.Headers(),
                body=b"",
                declined=True,
                decision_summary=f"operation already {op.state}; use a new idempotency key",
                cost=op.cost,
                trace=trace,
            )
        if op is not None and op.fingerprint != fingerprint:
            # Same key, different request: reject locally, never touching the
            # original operation's accounting.
            trace.append({"event": "rejected", "error": "idempotency-key-conflict", "local": True})
            return MudrikaResponse(
                status_code=409,
                headers=httpx.Headers(),
                body=b"",
                declined=True,
                decision_summary="idempotency key already used for a different request; use a new key",
                trace=trace,
            )

        if op is None:
            # ---- fresh purchase: unsigned request -> challenge -> authorize ----
            resp = await self._send_prepared(unsigned_request)
            if resp.status_code != 402:
                trace.append({"event": "response", "status": resp.status_code})
                return MudrikaResponse(
                    status_code=resp.status_code, headers=resp.headers, body=resp.content, trace=trace
                )
            challenge = self._parse_challenge(resp)
            trace.append({
                "event": "challenge",
                "cost": challenge["cost"],
                "nonce": challenge["nonce"],
                "capability": challenge["capability"],
                "seller": challenge["seller_id"],
            })
            decision = await self._authorize(challenge["cost"], challenge["capability"])
            trace.append({"event": "decision", "approve": decision.approve, "summary": decision.summary})
            if not decision.approve:
                return MudrikaResponse(
                    status_code=402,
                    headers=resp.headers,
                    body=resp.content,
                    declined=True,
                    decision_summary=decision.summary,
                    cost=challenge["cost"],
                    trace=trace,
                )
            op = _Op(
                state=OP_RESERVED,
                cost=challenge["cost"],
                reserved=challenge["cost"],
                fingerprint=fingerprint,
            )
            self._ops[idem] = op
            op.voucher = self._build_voucher(challenge, body, target, idem, base_headers)
            trace.append({"event": "signed_retry", "nonce": op.voucher.nonce, "cost": op.voucher.cost})
        else:
            trace.append({"event": "replay", "idempotency_key": idem, "state": op.state, "cost": op.cost})

        return await self._settle_with_voucher(idem, op, trace)

    async def _settle_with_voucher(self, idem: str, op: _Op, trace: list[dict[str, Any]]) -> MudrikaResponse:
        """Send (and resend) the operation's original voucher until settled.

        The voucher is NEVER re-signed — not for a new challenge, not at the
        same price, not after nonce expiry. One operation owns one voucher.
        """
        # Rebuild the exact request from the stored voucher: same target,
        # same body bytes, same signed headers.
        voucher_request = self._http.build_request(
            "POST", op.voucher.target, content=op.voucher.body, headers=op.voucher.headers
        )
        try:
            paid = await self._send_prepared(voucher_request)
        except httpx.HTTPError:
            # Ambiguous: the request may have been charged. Retry the exact
            # same signed voucher — the seller deduplicates by idempotency
            # key, so this cannot double-charge. (Rebuild the request: a
            # sent request's stream cannot be reused.)
            op.ambiguous = True
            trace.append({"event": "ambiguous_timeout", "action": "retry_same_voucher"})
            retry_request = self._http.build_request(
                "POST", op.voucher.target, content=op.voucher.body, headers=op.voucher.headers
            )
            try:
                paid = await self._send_prepared(retry_request)
            except httpx.HTTPError:
                # Reservation stays (op stays RESERVED) for reconciliation.
                trace.append({"event": "ambiguous_timeout", "action": "reservation_retained"})
                return MudrikaResponse(
                    status_code=0,
                    headers=httpx.Headers(),
                    body=b"",
                    charged=True,
                    cost=op.cost,
                    decision_summary="ambiguous outcome; local reservation retained, reconcile with ledger",
                    trace=trace,
                )

        # A confirmed refund is status-independent (a refunded handler can
        # surface as 402, 409, or 5xx): classify it BEFORE any status
        # dispatch so it can never be mistaken for a challenge, an
        # in-progress duplicate, or an ambiguous rejection. A refunded
        # response proves the charge path ran: restore exactly once,
        # tombstone the key, never re-sign.
        confirmed_refund = (
            paid.headers.get("x-mudrika-refunded") == "true"
            or (
                paid.status_code == 409
                and paid.headers.get("x-mudrika-error") == "operation-refunded"
            )
        )
        if confirmed_refund:
            op.charged_ever = True
            await self._retire_op(idem, op, OP_REFUNDED)
            return MudrikaResponse(
                status_code=paid.status_code,
                headers=paid.headers,
                body=paid.content,
                declined=True,
                refunded=True,
                cost=op.cost,
                decision_summary="operation refunded; reservation restored; use a new idempotency key",
                trace=trace,
            )

        if paid.status_code == 402:
            error = paid.headers.get("x-mudrika-error", "")
            if not error:
                # CHALLENGE_INVALID: this voucher's nonce was never consumed
                # by a charge (a consumed nonce always implies an operation
                # record, which answers differently). If we have any charge
                # evidence or a lost response in this op's history, the
                # seller's record expired — never sign a new purchase.
                if op.charged_ever or op.ambiguous:
                    return MudrikaResponse(
                        status_code=402,
                        headers=paid.headers,
                        body=paid.content,
                        declined=True,
                        cost=op.cost,
                        decision_summary=(
                            "replay unavailable: the seller no longer recognizes this operation; "
                            "reconciliation required (reservation retained)"
                        ),
                        trace=trace,
                    )
                # No charge evidence locally — but a replacement challenge
                # for an UNRESOLVED operation must never release its
                # reservation (a changed quote must not free the budget, and
                # the op may still be known to the seller). Decline with
                # reconciliation required; keep the voucher, cost, state and
                # reservation exactly as they are. Never sign the second
                # challenge, never recommend a new purchase on this key while
                # the operation remains unresolved.
                challenge = self._parse_challenge(paid)
                if challenge["cost"] != op.cost:
                    summary = (
                        "quote changed while the operation is unresolved; the client never "
                        "signs a second voucher — reservation retained, reconciliation required"
                    )
                else:
                    summary = (
                        "replacement challenge for an unresolved operation; the client never "
                        "signs a second voucher — reservation retained, reconciliation required"
                    )
                trace.append({"event": "challenge_invalid", "reason": "nonce_expired_or_requoted"})
                return MudrikaResponse(
                    status_code=402,
                    headers=paid.headers,
                    body=paid.content,
                    declined=True,
                    cost=op.cost,
                    decision_summary=summary,
                    trace=trace,
                )
            if error == "insufficient-funds":
                # Definitive no-charge for THIS attempt (an operation record
                # would have answered differently). But if an earlier send of
                # this voucher was lost (ambiguous), that send may still be
                # charged in flight — insufficient funds for the retry does
                # not prove the original will never land. Retain the
                # reservation pending reconciliation.
                if op.ambiguous or op.charged_ever:
                    return MudrikaResponse(
                        status_code=402,
                        headers=paid.headers,
                        body=paid.content,
                        declined=True,
                        cost=op.cost,
                        decision_summary=(
                            "insufficient funds reported for a resend of an ambiguous "
                            "operation; reservation retained, reconciliation required"
                        ),
                        trace=trace,
                    )
                await self._retire_op(idem, op, OP_FAILED)
                return MudrikaResponse(
                    status_code=402,
                    headers=paid.headers,
                    body=paid.content,
                    declined=True,
                    cost=op.cost,
                    decision_summary="declined: server reported insufficient funds; reservation restored; use a new idempotency key",
                    trace=trace,
                )
            if error in ("invalid-signature", "unknown-agent"):
                if op.charged_ever or op.ambiguous:
                    summary = f"rejected by seller: {error}; reservation retained for reconciliation"
                else:
                    await self._retire_op(idem, op, OP_FAILED)
                    summary = f"rejected by seller: {error}; reservation restored; use a new idempotency key"
                return MudrikaResponse(
                    status_code=402,
                    headers=paid.headers,
                    body=paid.content,
                    declined=True,
                    cost=op.cost,
                    decision_summary=summary,
                    trace=trace,
                )
            trace.append({"event": "rejected", "error": error})
            if not op.charged_ever and not op.ambiguous:
                await self._retire_op(idem, op, OP_FAILED)
                summary = f"rejected by seller: {error}; reservation restored; use a new idempotency key"
            else:
                summary = f"rejected by seller: {error}; reservation retained for reconciliation"
            return MudrikaResponse(
                status_code=402,
                headers=paid.headers,
                body=paid.content,
                declined=True,
                cost=op.cost,
                decision_summary=summary,
                trace=trace,
            )

        # Any non-402 response to a signed voucher proves the seller
        # processed this operation's charge path.
        op.charged_ever = True
        return await self._handle_outcome(idem, op, paid, trace)

    async def _handle_outcome(self, idem: str, op: _Op, paid: httpx.Response, trace: list) -> MudrikaResponse:
        if 200 <= paid.status_code < 300:
            cached = paid.headers.get("x-mudrika-cached") == "true"
            op.state = OP_SETTLED
            op.reserved = 0  # the reservation commits as the spend
            if cached:
                trace.append({"event": "cached_replay", "cost": op.cost})
                return MudrikaResponse(
                    status_code=paid.status_code,
                    headers=paid.headers,
                    body=paid.content,
                    charged=False,  # already paid on the original operation
                    cost=op.cost,
                    trace=trace,
                )
            trace.append({"event": "settled", "cost": op.cost, "status": paid.status_code})
            return MudrikaResponse(
                status_code=paid.status_code,
                headers=paid.headers,
                body=paid.content,
                charged=True,
                cost=op.cost,
                trace=trace,
            )

        if paid.status_code == 409:
            error = paid.headers.get("x-mudrika-error", "")
            if error == "idempotency-key-conflict":
                # Anomalous (the fingerprint is checked locally): retain the
                # reservation and report.
                return MudrikaResponse(
                    status_code=409,
                    headers=paid.headers,
                    body=paid.content,
                    declined=True,
                    cost=op.cost,
                    decision_summary="idempotency-key conflict; reservation retained for reconciliation",
                    trace=trace,
                )
            # operation-in-progress: ambiguous duplicate (e.g. our own lost
            # response). Retain the reservation until reconciled.
            trace.append({"event": "non_2xx", "status": 409, "refunded": False})
            return MudrikaResponse(
                status_code=409,
                headers=paid.headers,
                body=paid.content,
                cost=op.cost,
                decision_summary="operation in progress; local reservation retained",
                trace=trace,
            )

        trace.append({"event": "non_2xx", "status": paid.status_code, "refunded": False})
        return MudrikaResponse(
            status_code=paid.status_code,
            headers=paid.headers,
            body=paid.content,
            charged=True,
            cost=op.cost,
            trace=trace,
        )

    # --- budget accounting ---
    async def _authorize(self, cost: int, capability: str) -> Decision:
        if not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0:
            return Decision(approve=False, summary="invalid quote: cost must be a positive integer")
        if self.per_call_max is not None and cost > self.per_call_max:
            return Decision(approve=False, summary=f"cost {cost} exceeds per-call limit {self.per_call_max}")
        async with self._lock:
            if cost > self._remaining:
                return Decision(approve=False, summary=f"insufficient local budget ({self._remaining} < {cost})")
        decision = Decision(approve=True, summary="approved")
        if self.decider is not None:
            try:
                decision = await self.decider(PurchaseContext(
                    capability=capability,
                    cost=cost,
                    local_remaining=self._remaining,
                    mission=self.mission,
                    endpoint=self.base_url,
                ))
                if not isinstance(decision, Decision) or not isinstance(decision.approve, bool):
                    decision = Decision(approve=False, summary="malformed decision; declining by default")
            except Exception as exc:  # a broken decider must never auto-approve
                decision = Decision(approve=False, summary=f"decider error: {exc}")
            if not decision.approve:
                return decision
        async with self._lock:
            if cost > self._remaining:  # re-check after the (slow) decider ran
                return Decision(approve=False, summary="budget changed while deciding; declining")
            self._remaining -= cost
        summary = decision.summary if self.decider is not None and decision.summary else "approved"
        return Decision(approve=True, summary=summary)
