"""Atomic Redis credit ledger for Mudrika.

State machine per paid operation (idempotency key):

    (absent) --CHARGE--> IN_PROGRESS --finalize--> SUCCEEDED | REFUNDED

- CHARGE is a single Lua script: validates the challenge, checks the balance,
  consumes the challenge, debits the credits and marks the operation IN_PROGRESS.
  No partial state is observable because Redis executes scripts atomically.
- finalize() is the *only* code path that may move credits back (refund), and it
  only fires on the IN_PROGRESS -> REFUNDED transition, so repeated finalization
  can never double-refund.
- A replay of a SUCCEEDED operation returns the cached response without
  re-executing or re-charging; an IN_PROGRESS duplicate returns a conflict.
- Keys share the {agent_id} hash tag so the whole state machine stays on one
  Redis Cluster slot.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional

from redis.asyncio import Redis

CHARGE_LUA = """
-- KEYS[1] challenge key   KEYS[2] operation key   KEYS[3] balance key
-- ARGV[1] fingerprint  ARGV[2] cost  ARGV[3] now
local status = redis.call('HGET', KEYS[2], 'status')
if status then
  local fp = redis.call('HGET', KEYS[2], 'fingerprint')
  if fp ~= ARGV[1] then
    return {'CONFLICT', 'idempotency key reused with a different request', ''}
  end
  if status == 'SUCCEEDED' then
    return {'SUCCEEDED',
            redis.call('HGET', KEYS[2], 'remaining_after_debit') or '',
            redis.call('HGET', KEYS[2], 'response') or ''}
  end
  -- IN_PROGRESS or REFUNDED duplicates are terminal/pending outcomes:
  -- the caller must never re-execute or re-charge for them.
  return {status, 'duplicate of a ' .. string.lower(status) .. ' operation', ''}
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'CHALLENGE_INVALID', 'challenge missing, expired or already used', ''}
end
if redis.call('HGET', KEYS[1], 'fingerprint') ~= ARGV[1] then
  return {'CHALLENGE_INVALID', 'challenge does not match this request', ''}
end
local cost = tonumber(ARGV[2])
local balance = tonumber(redis.call('GET', KEYS[3]) or '0')
if balance < cost then
  return {'INSUFFICIENT_FUNDS', tostring(balance), ''}
end
redis.call('DEL', KEYS[1])
local remaining = redis.call('DECRBY', KEYS[3], cost)
redis.call('HSET', KEYS[2],
  'status', 'IN_PROGRESS',
  'fingerprint', ARGV[1],
  'cost', cost,
  'started_at', ARGV[3],
  'remaining_after_debit', remaining)
-- Deliberately NO expiry: an unresolved (IN_PROGRESS) operation record must
-- persist until finalized so retries cannot re-execute/re-charge it.
return {'CHARGED', tostring(remaining), ''}
"""

FINALIZE_LUA = """
-- KEYS[1] operation key   KEYS[2] balance key
-- ARGV[1] outcome SUCCEEDED|REFUNDED  ARGV[2] cost  ARGV[3] response JSON  ARGV[4] now
-- ARGV[5] terminal retention TTL
local status = redis.call('HGET', KEYS[1], 'status')
if status ~= 'IN_PROGRESS' then
  return {'ALREADY_FINALIZED', status or 'missing', ''}
end
if ARGV[1] == 'REFUNDED' then
  redis.call('INCRBY', KEYS[2], tonumber(ARGV[2]))
end
redis.call('HSET', KEYS[1], 'status', ARGV[1], 'finalized_at', ARGV[4], 'response', ARGV[3])
-- Terminal records are retained (for idempotent replays), then expire.
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
return {'OK', ARGV[1], ''}
"""


REGISTER_LUA = """
-- KEYS[1] public-key key   KEYS[2] balance key
-- ARGV[1] public_key_hex   ARGV[2] initial_credits
-- Atomic registration: an agent's key is immutable once set, and the initial
-- funding happens exactly once (check-then-write races are impossible).
local existing = redis.call('GET', KEYS[1])
if existing and existing ~= ARGV[1] then
  return {'REJECTED', 'agent already registered with a different public key'}
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SETNX', KEYS[2], ARGV[2])
return {'OK', ''}
"""


@dataclass
class ChargeResult:
    status: str  # CHARGED | SUCCEEDED | IN_PROGRESS | CONFLICT | CHALLENGE_INVALID | INSUFFICIENT_FUNDS
    remaining: Optional[int] = None
    cached_response: Optional[str] = None
    detail: str = ""


@dataclass
class FinalizeResult:
    status: str  # OK | ALREADY_FINALIZED
    detail: str = ""


class MudrikaLedger:
    def __init__(
        self,
        redis: Redis,
        *,
        challenge_ttl: int = 60,
        operation_ttl: int = 86400,
    ):
        self.redis = redis
        self.challenge_ttl = challenge_ttl
        self.operation_ttl = operation_ttl
        self._charge = redis.register_script(CHARGE_LUA)
        self._finalize = redis.register_script(FINALIZE_LUA)
        self._register = redis.register_script(REGISTER_LUA)

    # --- keys (shared {agent_id} hash tag => single cluster slot) ---
    @staticmethod
    def _k_balance(agent_id: str) -> str:
        return f"mudrika:{{{agent_id}}}:balance"

    @staticmethod
    def _k_pubkey(agent_id: str) -> str:
        return f"mudrika:{{{agent_id}}}:pubkey"

    @staticmethod
    def _k_challenge(agent_id: str, nonce: str) -> str:
        return f"mudrika:{{{agent_id}}}:challenge:{nonce}"

    @staticmethod
    def _k_op(agent_id: str, idempotency_key: str) -> str:
        return f"mudrika:{{{agent_id}}}:op:{idempotency_key}"

    # --- administration ---
    async def register_agent(self, agent_id: str, public_key_hex: str, initial_credits: int) -> None:
        """Atomically register an agent. The public key is immutable once set —
        a different-key re-registration (wallet takeover) is rejected."""
        if not isinstance(initial_credits, int) or isinstance(initial_credits, bool) or initial_credits < 0:
            raise ValueError("initial_credits must be a non-negative integer")
        res = await self._register(
            keys=[self._k_pubkey(agent_id), self._k_balance(agent_id)],
            args=[public_key_hex, initial_credits],
        )
        if res[0] == "REJECTED":
            raise ValueError(f"agent '{agent_id}': {res[1]}")

    async def top_up(self, agent_id: str, amount: int) -> int:
        return await self.redis.incrby(self._k_balance(agent_id), amount)

    async def get_balance(self, agent_id: str) -> int:
        value = await self.redis.get(self._k_balance(agent_id))
        return int(value) if value is not None else 0

    async def get_public_key(self, agent_id: str) -> Optional[str]:
        return await self.redis.get(self._k_pubkey(agent_id))

    async def check_operation(self, agent_id: str, idempotency_key: str) -> Optional[dict]:
        """Return the operation record (status, fingerprint, response, ...) or None."""
        data = await self.redis.hgetall(self._k_op(agent_id, idempotency_key))
        return data or None

    # --- protocol ---
    async def issue_challenge(
        self,
        agent_id: str,
        fingerprint: str,
        cost: int,
        capability: str,
    ) -> str:
        nonce = secrets.token_hex(16)
        key = self._k_challenge(agent_id, nonce)
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping={
                "fingerprint": fingerprint,
                "cost": cost,
                "capability": capability,
                "created_at": str(int(time.time())),
            })
            pipe.expire(key, self.challenge_ttl)
            await pipe.execute()
        return nonce

    async def charge(
        self,
        agent_id: str,
        idempotency_key: str,
        nonce: str,
        fingerprint: str,
        cost: int,
    ) -> ChargeResult:
        res = await self._charge(
            keys=[
                self._k_challenge(agent_id, nonce),
                self._k_op(agent_id, idempotency_key),
                self._k_balance(agent_id),
            ],
            args=[fingerprint, cost, int(time.time())],
        )
        status, second, third = res[0], res[1], res[2]
        result = ChargeResult(status=status)
        if status == "CHARGED":
            result.remaining = int(second)
        elif status == "SUCCEEDED":
            result.remaining = int(second) if second else None
            result.cached_response = third or None
        elif status == "INSUFFICIENT_FUNDS":
            result.remaining = int(second)
        else:
            result.detail = second
        return result

    async def finalize(
        self,
        agent_id: str,
        idempotency_key: str,
        outcome: str,  # "SUCCEEDED" | "REFUNDED"
        response_json: Optional[str],
    ) -> FinalizeResult:
        cost = await self.redis.hget(self._k_op(agent_id, idempotency_key), "cost")
        if cost is None:
            return FinalizeResult(status="ALREADY_FINALIZED", detail="no operation record")
        res = await self._finalize(
            keys=[self._k_op(agent_id, idempotency_key), self._k_balance(agent_id)],
            args=[outcome, int(cost), response_json or "", int(time.time()), self.operation_ttl],
        )
        return FinalizeResult(status=res[0], detail=res[1])
