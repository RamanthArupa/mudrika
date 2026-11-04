"""Budget-reasoning purchase decision via Muse Spark Open on Baseten.

This is the "Smart Buyer" half of the Mudrika demo: when the client hits an
HTTP 402 challenge, this callback asks Muse Spark Open whether the purchase is
worth it for the mission, given the remaining budget.

Security model (important): the model only *advises*. The deterministic guards
in MudrikaClient (per-call limit, local budget check under a lock) run first and
are enforced in code — a hallucinating or manipulated model can approve at most
what the deterministic budget allows, and a malformed response declines by
default.

Usage:
    export BASETEN_API_KEY=...
    decider = make_baseten_decider()
    client = MudrikaClient(..., decider=decider, mission="Verify the physician credential")
"""
from __future__ import annotations

import json
import os
from typing import Optional

from mudrika import Decision, PurchaseContext

MODEL = "meta-models/muse-spark-open"  # Muse Spark Open on Baseten
BASE_URL = "https://inference.baseten.co/v1"

SYSTEM_PROMPT = (
    "You are the budget officer of an autonomous AI agent. Given the mission, "
    "the remaining credit budget, the cost and the capability of a paid API "
    "call, decide whether to approve the purchase. Reply with ONLY a JSON "
    "object: {\"approve\": <bool>, \"summary\": \"<one sentence>\"}. Be frugal: "
    "decline optional purchases when the budget is low or the capability is "
    "not needed for the mission."
)


def make_baseten_decider(api_key: Optional[str] = None):
    """Return an async DecisionCallback backed by Muse Spark Open on Baseten."""
    from openai import AsyncOpenAI  # imported lazily; optional dependency

    client = AsyncOpenAI(
        api_key=api_key or os.environ["BASETEN_API_KEY"],
        base_url=BASE_URL,
    )

    async def decider(ctx: PurchaseContext) -> Decision:
        user_prompt = json.dumps(
            {
                "mission": ctx.mission,
                "remaining_credits": ctx.local_remaining,
                "call_cost": ctx.cost,
                "capability": ctx.capability,
            }
        )
        try:
            response = await client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0,
            )
            data = json.loads(response.choices[0].message.content)
            approve = data.get("approve")
            summary = str(data.get("summary", ""))[:280]
            if not isinstance(approve, bool):
                return Decision(approve=False, summary="malformed decision; declining by default")
            return Decision(approve=approve, summary=summary)
        except Exception as exc:
            # A failing decider must never auto-approve.
            return Decision(approve=False, summary=f"decider error: {exc}")

    return decider
