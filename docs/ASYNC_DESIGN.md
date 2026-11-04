# Mudrika Async Job Extension — Proposed Design

**Status: PROPOSED.** This document specifies the asynchronous job extension for
clinical workflow engine purchases (the Medaffin evaluation use case: a lab pays, the query is
matched to a domain expert, the verdict returns later). The verified synchronous
protocol in `mudrika/` is unchanged; nothing here is implemented yet. The design
reuses the existing atomic Lua transitions and the never-re-sign voucher model.

## 1. Problem

The current protocol settles a paid operation inside the request: charge → execute →
finalize → buffered response. Expert evaluation cannot fit that shape — a physician's
verdict takes minutes to hours. The extension must add asynchronous delivery without
weakening any existing guarantee: no double-charge, no re-execution, refund exactly
once, one voucher per operation, reservation held until a definitive outcome.

## 2. Protocol surface

### Seller

```python
@router.post("/api/v1/evaluate")
@mudrika(cost=15, capability="expert-medical-evaluation", async_result=True)
async def evaluate(payload: EvalRequest):
    # charge already happened; the handler records the job and returns ACCEPTED
    return JSONResponse(status_code=202, headers={"X-Mudrika-Job-ID": job_id})
```

- `async_result=True` opts the endpoint into async semantics.
- **Acceptance is explicit, not inferred:** only a `202 Accepted` response with
  `X-Mudrika-Async: true` and an `X-Mudrika-Job-ID` is an acceptance. Any other 2xx on
  an async endpoint is a seller bug and fails closed (refund).
- On acceptance the seller does **not** finalize. The operation record stays
  `IN_PROGRESS`; the debit stands (this is a hold on prepaid credits, **not escrow** —
  the credits are already the seller's to refund via the existing refund-once
  transition).

### Buyer

- On a `202` acceptance the client **holds** its local reservation (it does not
  commit): `MudrikaResponse(pending=True, charged=True)`.
- Polling is the existing replay: **resend the original signed voucher** on the same
  idempotency key. No new signature is ever created for the operation.
- Poll outcomes: pending (`409` + async marker), verdict (`2xx` cached replay — the
  reservation commits here), or confirmed refund (`409 operation-refunded` — the
  reservation restores exactly once, terminal tombstone).
- **Pending status is inferred from the authenticated server response**, never from a
  client-side flag set by the (possibly lost) acceptance. A client that never saw the
  `202` learns the operation is pending from the poll itself.

## 3. Server-side state

### Job intent is written atomically with the charge

The charge–enqueue sequence has a crash gap: if the process dies between the Lua
charge and the queue write, the buyer is charged for a job that does not exist. The
design closes it inside the existing script:

- `CHARGE_LUA` (async endpoints only) additionally writes a **job-intent record**
  `mudrika:{agent}:job:{idem}` with `state=DISPATCH_PENDING`, deadline, and target —
  in the same atomic script as the debit. There is no observable instant where the
  credits are gone but no job intent exists.
- A dispatcher worker (seller-side) atomically transitions
  `DISPATCH_PENDING → DISPATCHED` and enqueues to the expert queue. The transition is
  a compare-and-set, so a restarted dispatcher cannot double-dispatch.
- **Reconciliation path:** any `DISPATCH_PENDING` intent older than a bound is either
  dispatched or explicitly refunded by the reaper. Unresolved operations never expire
  by TTL (existing invariant); deadlines are enforced by explicit reconciliation, not
  record expiry.

### Job record

`mudrika:{agent}:job:{idem}` carries: state (`DISPATCH_PENDING | DISPATCHED |
COMPLETED | EXPIRED`), job id, assigned expert, deadline, and the op reference. The
job id returned in the `202` is stable: a same-voucher retry after a lost `202`
returns the **same** job id and pending state without re-enqueueing (the enqueue
happens once, guarded by the job record's state).

## 4. Completion and refund: first-wins

- Expert submission goes through an **authenticated, assignment-checked workflow**.
  Experts may only submit verdicts for jobs assigned to them; they can never finalize
  an arbitrary `(agent_id, idempotency_key)` pair supplied by a caller.
- `complete_async_operation(ledger, agent_id, idem, verdict, ...)` validates and
  serializes the bounded verdict, builds the existing cached-response JSON, and calls
  the existing `finalize(SUCCEEDED, ...)`.
- **First-wins is mandatory:** every caller must inspect the finalize result. A late
  expert submission after a timeout refund gets `ALREADY_FINALIZED` and is rejected —
  it must never overwrite a refund. A duplicate completion must never replace an
  existing verdict. The single `IN_PROGRESS → terminal` transition (existing Lua)
  provides this; the completion API surfaces `OK` vs `ALREADY_FINALIZED` to the
  caller and the expert UI.
- The deadline reaper refunds explicitly (`finalize(REFUNDED, ...)`), which restores
  the buyer's reservation exactly once through the existing centralized refund
  classification. Late completion after refund is recorded as evidence (the expert
  still gets paid out-of-band per contract) but cannot mutate the settled operation.

## 5. Response hygiene

- The verdict is validated, bounded (`MAX_CACHED_RESPONSE_BYTES`), and buffered —
  streaming responses and background tasks remain rejected, as in the synchronous
  protocol.
- Pending-only headers (`X-Mudrika-Async`, poll bookkeeping) are excluded from the
  cached verdict; the cached response preserves exactly the verdict's status,
  media type, body bytes, and relevant headers.
- Result retrieval requires the signed voucher, exactly as synchronous replays do —
  the signature is what proves the buyer's authorization.

## 6. Acceptance criteria

| # | Scenario | Criterion |
|---|---|---|
| 1 | Normal completion | One charge, one enqueue, one signature; poll returns pending; after completion the poll returns the cached verdict; client reservation commits exactly at verdict delivery; seller balance debited once. |
| 2 | Lost `202` | Buyer never saw the acceptance. Same-voucher retry returns pending state and the same job id; no re-enqueue; no new signature. |
| 3 | Repeated pending polls | Any number of polls: 409-pending each time, handler/enqueue never re-executed, reservation held, books unchanged. |
| 4 | Duplicate completion | Second completion attempt returns ALREADY_FINALIZED; cached verdict unchanged; no double settle. |
| 5 | Completion-vs-refund race | Exactly one of {verdict, refund} wins, atomically; the loser records evidence but cannot mutate the terminal state; buyer sees exactly one of {verdict, restored reservation}. |
| 6 | Charge–enqueue crash gap | Process death between charge and queue write leaves a DISPATCH_PENDING intent (never a charged-but-jobless operation); the reaper dispatches or refunds within the bound; the buyer is never left charged with no reconciliation path. |
| 7 | Abandonment refund | Deadline passes, reaper refunds; buyer poll gets operation-refunded; reservation restored exactly once; key tombstoned (existing semantics). |
| 8 | New-key retry after refund | Retrying the work requires a new idempotency key (existing tombstone semantics hold unchanged). |

## 7. What this design deliberately does not add

- No exactly-once guarantee on *external* expert payout (contractual, out-of-band).
- No streaming or unbounded verdicts.
- No change to the synchronous protocol's guarantees — the extension is additive and
  the 38-test suite must keep passing unchanged alongside new async tests.
