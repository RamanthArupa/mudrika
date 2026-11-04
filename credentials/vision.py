"""Region crops and perceptual fingerprints for SAM 3.1 segments.

Fingerprints are deliberately simple and dependency-free (Pillow only):
- dHash (144-bit difference hash, 12x12) captures the region's structure and survives
  rescans, small rotations and JPEG noise;
- mean colour captures ink colour (a red council seal vs a blue forgery).
"""
from __future__ import annotations

import base64
import io
from typing import Optional

from PIL import Image

CROP_MAX = 256


def crop(img: Image.Image, box: tuple[int, int, int, int], pad: int = 4) -> Image.Image:
    x1, y1, x2, y2 = box
    x1, y1 = max(0, x1 - pad), max(0, y1 - pad)
    x2, y2 = min(img.width, x2 + pad), min(img.height, y2 + pad)
    region = img.crop((x1, y1, x2, y2))
    region.thumbnail((CROP_MAX, CROP_MAX))
    return region


def dhash(img: Image.Image, size: int = 12) -> str:
    gray = img.convert("L").resize((size + 1, size), Image.LANCZOS)
    px = list(gray.getdata())
    bits = 0
    for row in range(size):
        for col in range(size):
            left = px[row * (size + 1) + col]
            right = px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{(size * size + 3) // 4}x}"


def mean_color(img: Image.Image) -> list[int]:
    """Mean colour of the 'ink' pixels (darker than the paper)."""
    rgb = img.convert("RGB").resize((48, 48))
    ink = [p for p in rgb.getdata() if sum(p) < 600]
    if not ink:
        ink = list(rgb.getdata())
    n = len(ink)
    return [sum(p[i] for p in ink) // n for i in range(3)]


def fingerprint(region: Image.Image) -> dict:
    return {"dhash": dhash(region), "color": mean_color(region), "size": [region.width, region.height]}


def hash_similarity(a: str, b: str) -> float:
    """1.0 = identical, ~0.5 = unrelated images."""
    if len(a) != len(b):  # fingerprints from different versions: treat as unrelated
        return 0.5
    bits = len(a) * 4
    return 1.0 - bin(int(a, 16) ^ int(b, 16)).count("1") / bits


def color_similarity(a: list[int], b: list[int]) -> float:
    dist = sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5
    return max(0.0, 1.0 - dist / 255.0)


def region_similarity(a: dict, b: dict) -> float:
    """Combined visual similarity normalised to 0..1 (0 = unrelated, 1 = same)."""
    h = hash_similarity(a["dhash"], b["dhash"])
    h_norm = max(0.0, min(1.0, (h - 0.5) / 0.5))
    c = color_similarity(a["color"], b["color"])
    score = 0.6 * h_norm + 0.4 * c
    # Ink colour is a strong forgery cue (a blue stamp on a red-seal council's
    # certificate): a clear colour mismatch caps the score, however similar the shape.
    if c < 0.8:
        score = min(score, c)
    return round(score, 4)


def png_b64(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def from_b64(data: str) -> Optional[Image.Image]:
    try:
        return Image.open(io.BytesIO(base64.b64decode(data))).convert("RGB")
    except Exception:
        return None
