"""Segment a certificate into seal / signature / photo regions with SAM 3.1.

Used on both sides of the protocol:
- the issuer segments every certificate it issued once, to build its index;
- Medaffin segments each applicant's upload before buying a match.

If SAM 3.1 returns nothing for a region (or MUDRIKA_OFFLINE=1), the region is
reported as missing (applicant uploads) or falls back to the known layout
(the issuer's own templates). The trace always says which source was used.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Optional

from PIL import Image

from . import certs, vision
from .meta_client import ModelError, sam_segment

PROMPTS: dict[str, list[str]] = {
    "seal": ["official seal", "stamp"],
    "signature": ["handwritten signature", "signature"],
    "photo": ["passport photo", "photo of a person"],
}


def offline() -> bool:
    return os.environ.get("MUDRIKA_OFFLINE") == "1"


def _pick(boxes, region: str, img: Image.Image):
    """Choose the most plausible box for a region when SAM returns several."""
    if not boxes:
        return None
    if region == "signature":  # signatures are wide
        return max(boxes, key=lambda b: (b.x2 - b.x1) / max(1, b.y2 - b.y1))
    return max(boxes, key=lambda b: (b.x2 - b.x1) * (b.y2 - b.y1))


async def _segment_region(img: Image.Image, png: bytes, region: str) -> dict:
    started = time.perf_counter()
    errors: list[str] = []
    for prompt in PROMPTS[region]:
        try:
            boxes, raw = await sam_segment(png, prompt, img.width, img.height)
        except ModelError as exc:
            errors.append(str(exc)[:200])
            continue
        box = _pick(boxes, region, img)
        if box is not None:
            return {
                "region": region,
                "source": "sam-3.1",
                "prompt": prompt,
                "box": [box.x1, box.y1, box.x2, box.y2],
                "matches": len(boxes),
                "ms": int((time.perf_counter() - started) * 1000),
            }
    return {"region": region, "source": "none", "box": None, "errors": errors,
            "ms": int((time.perf_counter() - started) * 1000)}


async def segment(img: Image.Image, *, layout_fallback: bool = False) -> dict[str, dict]:
    """Return {region: {box, source, ...}} for seal, signature and photo."""
    if offline():
        results = {r: {"region": r, "source": "none", "box": None} for r in PROMPTS}
    else:
        png = certs.to_png(img)
        found = await asyncio.gather(*(_segment_region(img, png, r) for r in PROMPTS))
        results = {item["region"]: item for item in found}
    if layout_fallback:
        layout = certs.layout_boxes(img.width, img.height)
        for region, item in results.items():
            if item["box"] is None:
                item["box"] = list(layout[region])
                item["source"] = "layout"
    return results


def fingerprints(img: Image.Image, segments: dict[str, dict], with_png: bool = True) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for region, item in segments.items():
        if not item.get("box"):
            continue
        crop = vision.crop(img, tuple(item["box"]))
        fp = vision.fingerprint(crop)
        if with_png:
            fp["png_b64"] = vision.png_b64(crop)
        out[region] = fp
    return out


def boxes_only(segments: dict[str, dict]) -> dict[str, Optional[list[int]]]:
    return {r: s.get("box") for r, s in segments.items()}
