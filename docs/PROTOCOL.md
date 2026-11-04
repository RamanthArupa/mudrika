# Mudrika protocol reference — HTTP 402 prepaid-credit authorization for AI agents

Mudrika turns any FastAPI endpoint into a paid microservice and gives autonomous agents a
cryptographic wallet for buying from them. An agent hits a paid endpoint, receives
`402 Payment Required` with a price and a nonce, decides whether the spend is worth it,
signs an Ed25519 voucher, and retries. The seller verifies the signature, atomically
debits credits, runs the model call, and settles or refunds.

```
[ AUTONOMOUS BUYER ]                                [ MUDRIKA SELLER ]
                    1. POST (no payment headers)
MudrikaClient  ----------------------------------->  @mudrika(cost=15) route
   - deterministic budget guards                     |
   - optional Muse Spark Open decision       2. 402  | challenge: nonce + price
   - Ed25519 voucher over canonical JSON  <---------  | (60s TTL, request-bound)
   - local budget reservation                      |
                    3. POST (signed voucher)          |
   signed retry  --------------------------------->  | verify sig -> Lua CHARGE
                                                    |   (atomic: nonce + balance
                                                    |    + op state machine)
   200 OK + X-Mudrika-Remaining-Balance  <---------  | run handler -> finalize
                                                    |   SUCCEEDED | REFUNDED
```

## Quickstart

```bash
pip install -e ".[dev]"      # fastapi, redis, pynacl, httpx
redis-server                 # any Redis >= 6
python -m mudrika keygen      # print an Ed25519 agent keypair
python -m examples.run_demo  # full handshake + budget decline + idempotent replay
pytest                       # 38 integration tests against real Redis
```

## The handshake

**1 — Challenge.** Any request without a signature gets:

```
HTTP/1.1 402 Payment Required
X-Mudrika-Version: 1.0
X-Mudrika-Seller-ID: mudrika-seller
X-Mudrika-Cost: 15
X-Mudrika-Nonce: 9f86d081884c7d659a2feaa0c55ad015
X-Mudrika-Capability: sam-3.1+muse-spark-extraction
```

The nonce is stored in Redis bound to a **fingerprint** of the exact request
(method, path + query, SHA-256 of the body, cost, idempotency key) with a 60s TTL —
so a challenge can never be replayed against a different request or price.
Challenges also carry an `X-Mudrika-Op-State` hint (state only, never data) purely for
observability. The buyer's real protection against being re-signed into a fresh
purchase after the seller's terminal record expires is NOT a hint: the client
resends the original voucher, whose nonce is already consumed, and — critically —
never signs a second challenge for an operation that has a voucher. Once the
seller's record has expired the charge script has no memory of the operation, so
the client declines with "replay unavailable, reconciliation required" rather than
signing. This protection lasts as long as the buyer retains its operation state
(in-memory per `MudrikaClient` instance); a restarted client that did not persist
its vouchers must reconcile with the ledger instead of retrying blindly.

**2 — Voucher.** The buyer signs canonical JSON (`mudrika/canonical.py`) binding
`version, agent_id, seller_id, method, request_target, body_sha256, cost, nonce,
idempotency_key` with its Ed25519 private key and retries:

```
X-Mudrika-Agent-ID: agent_medaffin_01
X-Mudrika-Idempotency-Key: 3f2a...
X-Mudrika-Nonce: 9f86d081884c7d659a2feaa0c55ad015
X-Mudrika-Signature: 4a8b9c41d2e6...  (plain hex, Ed25519 detached signature)
```

**3 — Atomic charge.** One Redis Lua script validates the challenge, checks the
balance, consumes the nonce, debits the credits and flips the operation record to
`IN_PROGRESS` — all or nothing, race-free:

```
(absent) --CHARGE--> IN_PROGRESS --finalize--> SUCCEEDED | REFUNDED
```

**4 — Settle.** The handler runs. 2xx → `SUCCEEDED` (response cached for replays,
`X-Mudrika-Remaining-Balance` returned). Any failure or non-2xx → `REFUNDED`
(exactly once — the refund is the single `IN_PROGRESS -> REFUNDED` transition, so
repeated finalization or a crashing worker can never double-refund).

## Guarantees

| Property | How |
|---|---|
| Tamper-proof pricing | The voucher binds body hash, method, target, cost, nonce, agent, seller. The seller recomputes it from received bytes. |
| No double charge | Nonce consumption, balance debit and op creation happen in one atomic Lua script. |
| No negative balances | Balance check and debit are in the same script — concurrent purchases can't overdraw. |
| Idempotent retries | `X-Mudrika-Idempotency-Key`: duplicates of a settled operation return the cached response free; duplicates in flight get `409`; same key with different content gets `409` without charging. |
| Refund-once | Refunds happen only on the `IN_PROGRESS -> REFUNDED` transition. |
| Budget authority is code, not the model | Deterministic guards (per-call limit, local budget under a lock) run before any LLM decision callback; malformed LLM output declines by default. |

**Not guaranteed (documented honestly):** exactly-once *external* execution. A crash
between the model call and `finalize` leaves the operation `IN_PROGRESS` and needs
reconciliation — exactly-once *charging* holds while operation records are retained
(unresolved `IN_PROGRESS` records never expire; terminal records are retained for
idempotent replays, then expire). Streaming responses and background tasks are rejected (and refunded) rather
than settled, because they execute after settlement; only bounded, buffered
responses are supported (cached replays are capped at 1 MB; larger bodies settle
but are not cached). The client signs the exact wire target — percent-encoded
path plus query string as transmitted — and a cached replay preserves the exact
response bytes and relevant headers. Scope is a prepaid-credit authorization gateway between
registered agents and sellers — it is not external financial settlement and has no
payouts. Agent registration is a trusted-admin operation: registration is atomic (the
public key is immutable once set; concurrent different-key registrations cannot
overwrite each other), and in production registration/funding must sit behind
authenticated administration (`MUDRIKA_ADMIN_TOKEN` in `examples/seller_app.py`,
which fails closed — admin routes stay disabled until a token is configured).

## Positioning: Mudrika vs x402 vs MPP

All three protocols activate the same dormant HTTP 402 "Payment Required" code with
the same handshake shape — request → 402 challenge with price and payment details →
client authorizes and retries with a signed payment credential → server verifies,
executes, settles. Where they differ is the settlement rail and, crucially, the layer
they own.

| Dimension | x402 (Coinbase) | MPP (Stripe + Tempo) | Mudrika |
|---|---|---|---|
| Status | Open standard, v2 headers live | Open standard, launched Mar 2026 | Hackathon prototype |
| Settlement | On-chain stablecoins (USDC on Base/Polygon/Solana), gasless EIP-3009; facilitator verifies/settles per request | Payment-method agnostic: stablecoins (Tempo/Solana), cards/BNPL via Shared Payment Tokens, Lightning; settles into a Stripe balance via PaymentIntents | None — prepaid-credit authorization ledger (Redis); no money movement |
| Wire format | `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` headers; MCP envelope | Formal HTTP auth scheme (`WWW-Authenticate: Payment` → `Authorization: Payment` → receipt), proposed to the IETF | `X-Mudrika-*` headers + canonical-JSON Ed25519 vouchers |
| Cost model | One blockchain transaction per request | Sessions with pre-authorized limits; streaming micropayments | Per-operation charge/refund with an atomic Lua state machine |
| Buyer-side spend guards | SDK spend controls (per-payment and cumulative caps, allowlists) | Session-level pre-authorized spending | Deterministic budget guards **before** an LLM decision callback |
| Failure semantics | Rail-level (on-chain finality) | Stripe payment semantics (capture/void/refund) | Explicit lost-response recovery: original-voucher resend, refund-once tombstones, reconciliation states |
| Decision layer | None — payment only | None — payment only | **Model-driven buyer-side economics** (Muse Spark Open decides whether the spend is worth it), code-guarded |

Sources: [x402 docs](https://docs.x402.org/core-concepts/http-402),
[CDP facilitator flow](https://docs.cdp.coinbase.com/x402/how-it-works),
[Stripe MPP announcement](https://stripe.com/blog/machine-payments-protocol),
[Stripe MPP docs](https://docs.stripe.com/payments/machine/mpp),
[MPP auth scheme (Cloudflare)](https://developers.cloudflare.com/agents/agentic-payments/mpp/index.md),
[x402 vs MPP comparison (WorkOS)](https://workos.com/blog/x402-vs-stripe-mpp-how-to-choose-payment-infrastructure-for-ai-agents-and-mcp-tools-in-2026).

**The honest framing:** x402 and MPP are *settlement rails*; Mudrika is a *decision and
policy layer* that sits above any such rail. Neither x402 nor MPP specifies whether
an agent should buy — they transport the payment once someone has decided. Mudrika's
contribution is that the decision itself is model-driven but code-guarded (deterministic
budget checks before the LLM callback, decline-on-malformed), plus a stricter operation
lifecycle than either protocol specifies at the HTTP layer: idempotency-key-bound
vouchers, ambiguous-outcome recovery, and exactly-once refunds.

**Migration path:** the Redis credit ledger is a pluggable backend. The same `@mudrika`
middleware and client flow could settle through x402's facilitator or MPP's
PaymentIntents while keeping the buyer-side Muse decision layer — which is where the
agentic story lives.

**Validation from the card networks:** Mastercard's Agent Pay program is complementary
infrastructure — card-network trust (Agentic Tokens, Payment Passkeys, Verifiable
Intent, issuer visibility) rather than per-request API pricing. Notably, its June 2026
*Agent Pay for Machines* (AP4M) extension converged on the same pattern Mudrika
implements: a business gives an agent a job and a spending limit, the service
responds with `402 Payment Required`, and the agent pays with a digitally signed
voucher within its approved limit — settled through Mastercard's network and BVNK
wallets instead of an internal credit ledger ([Mastercard AP4M](https://www.mastercard.com/us/en/news-and-trends/press/2026/october/Mastercard-Agent-Pay-for-Machines-in-action.html),
[launch release](https://www.mastercard.com/us/en/news-and-trends/press/2026/june/mastercard-launches-agent-pay-for-machines.html)).
Mudrika deliberately targets the other half of the problem: **off-chain, prepaid
credits inside a permissioned boundary** — an enterprise registers agent public keys,
loads a budget, and gets signed, auditable, per-call spend authorization with
deterministic policy enforcement and refunds. No wallets, no on-chain fees,
single-round-trip settlement in-process, and the buyer's *reasoning* about the purchase
is a first-class part of the protocol. Complements, not competitors.

## Use cases

Mudrika fits wherever an autonomous agent must repeatedly buy small units of work
from a trusted provider, under a budget, with an auditable trail — especially inside a
permissioned boundary where real-money rails are unnecessary or unwanted.

### 1. Healthcare credential and document forensics (the demo's domain)

A licensing platform's agent verifies physician credentials by paying per document:
SAM 3.1 segments the scanned license, Muse Spark extracts the fields, and the agent
pays 15 credits per verification — declining automatically when the remaining budget
can't justify the spend. Each voucher is a signed, tamper-proof record of *what*
was bought, *for how much*, and *on whose behalf* — the audit trail a compliance
officer needs without a card network in sight. The same pattern covers claims
triage, prior-authorization document checks, and HL7/FHIR enrichment steps bought
per message.

### 2. Medical education and exam-prep marketplaces

An exam-prep agent assembling a personalized study plan buys exactly what it needs:
one mock-exam analysis here, a weak-topic question bundle there. Students (or
universities) pre-load credit budgets; the Muse Spark decision callback weighs each
purchase against the remaining budget and the learner's goal, and deterministic
guards make sure the model can never overspend. Content creators get metered,
per-call revenue without subscriptions or checkout flows.

### 3. Enterprise agent procurement with budget governance

The AP4M pattern, off-chain: a business gives an agent a job ("source these
suppliers, verify these credentials, draft these reports") and a spending limit.
Every paid tool call goes through the guards — per-call caps, cumulative budget,
approve/decline reasoning — and finance gets one signed audit trail per operation
instead of a pile of card statements. Refund-once semantics mean a failed vendor
call costs the agent nothing.

### 4. Paid MCP servers and agentic tool markets

Model Context Protocol servers are the natural sellers: each tool call is a clean,
idempotent-shaped operation that deserves a price. `@mudrika` annotates the tool
handler; agents discover the price in the 402 challenge and decide. The lost-response
recovery matters here most — agents retry tool calls constantly, and Mudrika
guarantees a retry can never double-charge or re-execute.

### 5. Agent-to-agent commerce inside a walled garden

A fleet of cooperating agents (research agent buying extraction from an imaging
agent, a routing agent paying a transcription agent) can settle in credits with
single-round-trip latency and no transaction fees — the economics x402 solves with
on-chain micropayments, applied where a company already controls both endpoints.

### 6. Model-inference resale and metered AI gateways

A team hosting open-weight models (Muse Glimmer, Muse Voice) sells inference per
request to other teams' agents: transcription at 5 credits, badge generation at 20.
The seller never manages subscriptions; the buyers never commit to contracts; usage
is priced at the call.

### What these share

Every use case above needs (a) per-call pricing, (b) an autonomous buyer with a
budget, (c) a signed audit trail, and (d) failure handling that never double-charges.
That is exactly the protocol surface Mudrika implements. What it does *not* cover:
real-money settlement, payouts, streaming responses, and exactly-once external side
effects — see the guarantees table above.

## Seller usage

```python
from mudrika import MudrikaRouter, mudrika

router = MudrikaRouter(ledger=ledger, seller_id="mudrika-seller")

@router.post("/api/v1/forensics/verify")
@mudrika(cost=15, capability="sam-3.1+muse-spark-extraction")
async def verify(body: VerifyRequest):
    # credits are already deducted; a failure here auto-refunds
    ...
```

The decorator only annotates; a custom `APIRoute` does the negotiation, so dependency
injection, validation and OpenAPI keep working. Plug Meta Model API calls (SAM 3.1 via
`POST /v1/responses`, Muse Spark) inside the handler — see `examples/seller_app.py`.

## Buyer usage

```python
from mudrika import MudrikaClient
from examples.baseten_decider import make_baseten_decider   # Muse Spark Open on Baseten

client = MudrikaClient(
    agent_id="agent_medaffin_01",
    secret_key_hex=AGENT_SECRET,
    base_url="https://seller.example.com",
    budget=100,
    per_call_max=25,
    decider=make_baseten_decider(),          # optional: model reasons, code enforces
    mission="Verify the physician's credential",
)
result = await client.post("/api/v1/forensics/verify", json_body={...})
print(result.trace)      # challenge -> decision -> signed_retry -> settled
```

The client keeps a **local** budget under a lock (concurrent approvals can't jointly
exceed it) and runs a per-operation state machine (`RESERVED → SETTLED | REFUNDED`)
guarded by a per-operation lock: same-key concurrent calls are serialized to a single
charge, and **the client stores and resends the original signed voucher** for every
subsequent attempt of the same operation — after a lost response (ambiguous outcome),
on idempotent replay, and after concurrent calls. It never signs a second nonce for
an operation that already has a voucher, so it can never purchase the same operation
twice. A replacement challenge for an unresolved operation (expired nonce or
changed quote) never gets a second signature and never releases the
reservation — the op stays pending reconciliation. Definitive no-charge
rejections (insufficient funds, rejected signature) and confirmed refunds
retire the operation: the reservation is restored exactly once and the record
is kept as a terminal tombstone bound to the
original fingerprint, so that idempotency key can never be re-signed — retrying the
work requires a new key. If a charged operation's seller-side terminal record has
expired, the client declines with "replay unavailable, reconciliation required" and
keeps the reservation rather than re-purchasing. Operation state is in-memory per
client instance: a restarted buyer loses its vouchers and must reconcile (or persist
op state before restarting). The optional `openai` package (for the Baseten Muse Spark
Open decider) is a separate dependency: `pip install openai`.

## Related documents

- [ASYNC_DESIGN.md](ASYNC_DESIGN.md) — **proposed** async job extension (charge on acceptance, result on a later same-voucher replay, deadline refunds). Not implemented.

## Repo layout

```
mudrika/
  canonical.py   canonical voucher JSON + Ed25519 sign/verify (PyNaCl)
  ledger.py      Redis Lua scripts: atomic charge + finalize-or-refund state machine
  server.py      @mudrika decorator + MudrikaRouter (custom APIRoute)
  client.py      MudrikaClient: budget-aware 402 negotiation, traces, reservations
examples/
  seller_app.py        runnable seller node (where Meta Model API calls plug in)
  baseten_decider.py   Muse Spark Open (meta-models/muse-spark-open) decision callback
  run_demo.py          end-to-end demo incl. the budget-decline moment
tests/test_protocol.py 38 integration tests against real Redis
ASYNC_DESIGN.md          proposed async job extension (clinical workflow engine)
```
