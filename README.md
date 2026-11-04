# Mudrika (मुद्रिका)

**Signed credits for autonomous agents.** In Sanskrit, a *mudrika* is a signet ring: the seal that authorises a payment and the seal that proves a document is genuine. Mudrika does both jobs for AI agents.

- **Payments:** an open-source HTTP 402 protocol for agents. Agents get prepaid credits and per-case budgets. They sign each purchase with Ed25519, and the seller charges atomically and refunds exactly once.
- **Verification:** a reference service that uses **SAM 3.1 on both sides** to match a healthcare expert's certificate against the issuer's own records.

> Built for the Meta AI Developer Hackathon (Oct 26 – Nov 4, 2026). Theme: *Build for Your World*. Uses SAM 3.1 and Muse Spark via Meta Model API, and Muse Spark Open via Baseten. **Built with Muse Spark Open.**

## The problem

Medaffin is a professional network for healthcare experts. Every expert who joins has to prove they're registered. Today that means a human emails a medical council, waits days, and compares a scanned PDF by eye. The council does the work for free, so there's no incentive to answer quickly. There's also no audit trail of who checked what.

## What Mudrika does

```
 Medaffin (buyer agent)                                Certificate issuer (seller)
 ─────────────────────                                 ───────────────────────────
 1  expert uploads certificate                         0  every issued certificate is
 2  SAM 3.1 segments seal, signature, photo               segmented once with SAM 3.1
 3  Muse Spark reads name, reg no, issuer, dates          → reference index (crops + metadata)
 4  POST /api/v1/credentials/match ─────────────────▶
                        ◀──────────── 402 Payment Required (cost 15, nonce, 60 s)
 5  budget guards in code, then Muse Spark Open
    decides whether the lookup is worth it
 6  Ed25519-signed voucher retry ───────────────────▶  7  verify signature, atomic Lua charge
                                                       8  near-match: metadata + SAM-crop
                                                          fingerprints; Muse adjudicates close calls
                        ◀──────────── 200 + issuer-signed match result
 9  verify issuer signature → verified / review / reject
```

- **Only the crops and the metadata leave Medaffin.** The full certificate never does.
- **The issuer gets paid per lookup.** A completed lookup is charged whatever the verdict. If the issuer fails to produce a result, the credits are refunded exactly once.
- **The model advises, the code decides.** Muse Spark Open can only approve what the deterministic budget guards already allow. A malformed or failed decision counts as a decline.
- **Every step is signed.** The buyer's voucher binds the method, path, body hash, price, nonce and idempotency key. The issuer signs its result with its own key, published at `/.well-known/mudrika`.

## Live demo

Two services on Render, plus a Redis-compatible ledger:

| Service | Role |
|---|---|
| `mudrika-medaffin` | Buyer agent + dashboard. Open it in a browser. |
| `mudrika-issuer` | "Demo Medical Council" seller node (`/.well-known/mudrika`, `/status`, `/docs`) |

The dashboard runs four cases:

1. **Genuine certificate** (rescanned copy) → `MATCH` → **Verified**
2. **Altered certificate** (real name and number, wrong seal and signature) → `NEAR_MATCH`, Muse explains the difference → **Credentialing review**
3. **Unknown registrant** → `NO_MATCH` → **Not verified**
4. **Budget 10 or issuer outage** → declined before signing, or charged then **refunded exactly once**

All certificates, councils and people in the demo are fictional.

## Run locally

```bash
pip install -r requirements.txt
redis-server &
export META_API_KEY=...        # Meta Model API: SAM 3.1 + Muse Spark
export BASETEN_API_KEY=...     # Baseten: Muse Spark Open (purchase decisions)
export MUDRIKA_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_hex(16))")
uvicorn credentials.issuer_app:app --port 8000 &
ISSUER_URL=http://localhost:8000 uvicorn credentials.medaffin_app:app --port 8001
# open http://localhost:8001
```

Set `MUDRIKA_OFFLINE=1` to run without model calls. Regions then come from the known template layout, and the dashboard labels them `layout`.

## Use the protocol in your own service

```python
from mudrika import MudrikaLedger
from mudrika.server import MudrikaRouter, mudrika

router = MudrikaRouter(ledger=ledger, seller_id="my-seller")

@router.post("/api/v1/thing")
@mudrika(cost=15, capability="my-capability")
async def thing(body: ThingRequest):
    ...  # credits already deducted; raising refunds them exactly once
```

```python
from mudrika import MudrikaClient

client = MudrikaClient(agent_id="agent-01", secret_key_hex=SECRET, base_url=SELLER,
                       budget=40, per_call_max=25, decider=my_decider)
result = await client.post("/api/v1/thing", json_body={...})
print(result.trace)   # challenge → decision → signed_retry → settled
```

Full protocol semantics and guarantees: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Repo layout

```
mudrika/            protocol library: canonical vouchers, atomic Redis ledger, FastAPI router, budget-aware client
credentials/        reference service: SAM 3.1 segmentation, fingerprints, near-matching, issuer + Medaffin apps
  meta_client.py    Meta Model API (sam-3.1, muse-spark-1.3) + Baseten (muse-spark-open) over httpx
  segment.py        seal / signature / photo regions via SAM 3.1
  matching.py       metadata + visual near-match, verdict thresholds
  issuer_app.py     seller node: SAM-segmented reference index, paid /api/v1/credentials/match
  medaffin_app.py   buyer agent + dashboard
  certs.py          fictional certificates for the demo
tests/              protocol tests (real Redis) + credential-matching tests (offline)
docs/               protocol reference, proposed async extension
```

## What was built during the hackathon

- Renamed and extended the earlier `pay402` protocol prototype into **Mudrika**. The core 402 handshake, ledger and client existed before. Changes this week:
  - the buyer's decision summary is now kept on approval
  - admin top-ups
  - packaging
  - MIT licence
- **New this week:** the whole `credentials/` service:
  - SAM 3.1 segmentation on both buyer and issuer
  - Muse Spark metadata extraction and crop adjudication
  - Muse Spark Open purchase decisions on Baseten
  - fingerprint near-matching
  - an issuer-signed result
  - the dashboard
  - the Render deployment
  - offline tests

## Honest scope

- The issuer is simulated. Real medical councils would run the issuer package against their own records.
- Credits are prepaid authorisation, not money movement. A real payment rail (cards, x402, MPP) could top up the ledger later.
- Matching is a strong signal for a credentialing team, not a legal determination. `NEAR_MATCH` always goes to a human reviewer.

## Licence

MIT © 2026 Arupa AI Private Limited
