"""Canonical message construction and Ed25519 signing for the Mudrika protocol.

Every voucher signs the *exact* request the seller will execute:
deterministic JSON over {version, agent_id, seller_id, method, request_target,
body_sha256, cost, nonce, idempotency_key}. The seller recomputes the message
from the bytes it actually received, so any tampering (body, query, price,
agent, endpoint) invalidates the signature or the challenge fingerprint.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey, VerifyKey

PROTOCOL_VERSION = "1.0"


@dataclass(frozen=True)
class AgentKeys:
    """An Ed25519 keypair. Keep secret_hex private; register public_hex with the seller."""

    secret_hex: str
    public_hex: str


def generate_keypair() -> AgentKeys:
    sk = SigningKey.generate()
    return AgentKeys(secret_hex=sk.encode().hex(), public_hex=sk.verify_key.encode().hex())


def _dumps(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_fingerprint(
    *,
    method: str,
    request_target: str,
    body_sha256: str,
    cost: int,
    idempotency_key: str,
) -> str:
    """Request binding stored in the challenge. Binds a nonce to one exact request."""
    return _dumps(
        {
            "body_sha256": body_sha256,
            "cost": cost,
            "idempotency_key": idempotency_key,
            "method": method,
            "request_target": request_target,
        }
    ).decode("utf-8")


def build_auth_message(
    *,
    agent_id: str,
    seller_id: str,
    method: str,
    request_target: str,
    body_sha256: str,
    cost: int,
    nonce: str,
    idempotency_key: str,
    version: str = PROTOCOL_VERSION,
) -> bytes:
    """The message the buyer signs with its Ed25519 private key."""
    return _dumps(
        {
            "agent_id": agent_id,
            "body_sha256": body_sha256,
            "cost": cost,
            "idempotency_key": idempotency_key,
            "method": method,
            "nonce": nonce,
            "request_target": request_target,
            "seller_id": seller_id,
            "version": version,
        }
    )


def sign_message(message: bytes, secret_key_hex: str) -> str:
    return SigningKey(bytes.fromhex(secret_key_hex)).sign(message).signature.hex()


def verify_message(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(message, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


def load_public_key(secret_key_hex: str) -> str:
    """Derive the public key hex from a secret key hex (convenience for tests/demos)."""
    return SigningKey(bytes.fromhex(secret_key_hex)).verify_key.encode().hex()
