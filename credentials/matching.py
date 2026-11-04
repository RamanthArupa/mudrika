"""Near-match a submitted certificate against the issuer's reference index.

Score = 0.55 * metadata similarity + 0.45 * visual similarity of SAM regions.

Verdicts (returned by the issuer, interpreted by the buyer):
- MATCH       total >= 0.85, metadata >= 0.90, visual >= 0.75 and every compared region >= 0.85
- NEAR_MATCH  total >= 0.65 (something is close but not right: route to review)
- NO_MATCH    otherwise
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Optional

from .vision import region_similarity

REGIONS = ("seal", "signature", "photo")
META_WEIGHTS = {"registration_number": 0.45, "name": 0.35, "issue_date": 0.10, "qualification": 0.10}


def _norm(value: Optional[str]) -> str:
    value = (value or "").upper()
    value = re.sub(r"\b(DR|DOCTOR)\b\.?", " ", value)
    return re.sub(r"[^A-Z0-9]+", " ", value).strip()


def _ratio(a: Optional[str], b: Optional[str]) -> float:
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return 0.0
    tokens = SequenceMatcher(None, " ".join(sorted(a.split())), " ".join(sorted(b.split()))).ratio()
    return max(SequenceMatcher(None, a, b).ratio(), tokens)


def _reg_ratio(a: Optional[str], b: Optional[str]) -> float:
    a, b = re.sub(r"[^A-Z0-9]", "", (a or "").upper()), re.sub(r"[^A-Z0-9]", "", (b or "").upper())
    if not a or not b:
        return 0.0
    return 1.0 if a == b else SequenceMatcher(None, a, b).ratio() * 0.8


def metadata_score(submitted: dict, reference: dict) -> tuple[float, dict]:
    parts = {
        "registration_number": _reg_ratio(submitted.get("registration_number"), reference.get("registration_number")),
        "name": _ratio(submitted.get("name"), reference.get("name")),
        "issue_date": _ratio(submitted.get("issue_date"), reference.get("issue_date")),
        "qualification": _ratio(submitted.get("qualification"), reference.get("qualification")),
    }
    total = sum(META_WEIGHTS[k] * v for k, v in parts.items())
    return round(total, 4), {k: round(v, 3) for k, v in parts.items()}


def visual_score(submitted_regions: dict, reference_regions: dict) -> tuple[Optional[float], dict]:
    parts = {}
    for region in REGIONS:
        a, b = submitted_regions.get(region), reference_regions.get(region)
        if a and b:
            parts[region] = region_similarity(a, b)
    if not parts:
        return None, {}
    return round(sum(parts.values()) / len(parts), 4), parts


def match(submitted_meta: dict, submitted_regions: dict, index: list[dict], top_k: int = 3) -> dict:
    """Return the best candidate with scores and a verdict."""
    if not index:
        raise ValueError("issuer reference index is empty")
    ranked = sorted(
        ((metadata_score(submitted_meta, rec["metadata"]), rec) for rec in index),
        key=lambda item: item[0][0],
        reverse=True,
    )[:top_k]
    best: Optional[dict] = None
    for (meta, meta_parts), rec in ranked:
        visual, visual_parts = visual_score(submitted_regions, rec.get("regions", {}))
        total = 0.55 * meta + 0.45 * visual if visual is not None else 0.8 * meta
        candidate = {
            "cert_id": rec["cert_id"],
            "metadata": rec["metadata"],
            "metadata_score": meta,
            "metadata_detail": meta_parts,
            "visual_score": visual,
            "visual_detail": visual_parts,
            "total_score": round(total, 4),
        }
        if best is None or candidate["total_score"] > best["total_score"]:
            best = candidate
    assert best is not None
    meta, visual, total = best["metadata_score"], best["visual_score"] or 0.0, best["total_score"]
    min_region = min(best["visual_detail"].values()) if best["visual_detail"] else 0.0
    if total >= 0.85 and meta >= 0.90 and visual >= 0.75 and min_region >= 0.85:
        verdict = "MATCH"
    elif total >= 0.65:
        verdict = "NEAR_MATCH"
    else:
        verdict = "NO_MATCH"
    flags = []
    if meta >= 0.90 and (visual < 0.75 or min_region < 0.85):
        weak = [r for r, s in best["visual_detail"].items() if s < 0.85]
        weak = weak or ["regions"]
        verb = "does" if len(weak) == 1 else "do"
        flags.append(f"text matches an issued record but the {' and '.join(weak)} {verb} not match")
    if verdict == "NO_MATCH":
        flags.append("no issued record is close to the submitted metadata")
    return {"verdict": verdict, "best": best, "flags": flags}
