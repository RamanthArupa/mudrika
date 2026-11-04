"""Synthetic medical registration certificates for the demo.

Everything here is fictional: the "Demo Medical Council", the doctors and the
registration numbers. Real certificates contain personal data and must never
be used in the public demo.

Each certificate has three regions SAM 3.1 is asked to find: an official seal,
a handwritten signature and a passport photo. The seal design, signature
stroke and photo tone are derived from a per-certificate seed, so a forged copy
(same text, different seal) is visually distinguishable.
"""
from __future__ import annotations

import io
import math
import random
from dataclasses import asdict, dataclass, field
from typing import Optional

from PIL import Image, ImageDraw, ImageFont

W, H = 1000, 700
ISSUER = "Demo Medical Council"


@dataclass
class CertRecord:
    cert_id: str
    name: str
    registration_number: str
    qualification: str
    issue_date: str
    issuer: str = ISSUER
    seal_seed: int = 0
    signature_seed: int = 0
    photo_seed: int = 0

    def metadata(self) -> dict:
        return {
            "name": self.name,
            "registration_number": self.registration_number,
            "qualification": self.qualification,
            "issue_date": self.issue_date,
            "issuer": self.issuer,
        }


REGISTRY: list[CertRecord] = [
    CertRecord("dmc-0001", "Dr. Ananya Rao", "DMC-2019-04417", "MBBS, MD (Internal Medicine)", "12 March 2019", seal_seed=11, signature_seed=101, photo_seed=1),
    CertRecord("dmc-0002", "Dr. Farhan Siddiqui", "DMC-2017-01182", "MBBS, MS (General Surgery)", "03 July 2017", seal_seed=11, signature_seed=202, photo_seed=2),
    CertRecord("dmc-0003", "Dr. Meera Iyer", "DMC-2021-07730", "MBBS, DNB (Paediatrics)", "21 January 2021", seal_seed=11, signature_seed=303, photo_seed=3),
    CertRecord("dmc-0004", "Dr. Vikram Nair", "DMC-2015-00968", "MBBS, DM (Cardiology)", "09 October 2015", seal_seed=11, signature_seed=404, photo_seed=4),
    CertRecord("dmc-0005", "Dr. Sara Thomas", "DMC-2022-09154", "MBBS", "30 May 2022", seal_seed=11, signature_seed=505, photo_seed=5),
]

# Layout boxes (x1, y1, x2, y2) on the unperturbed 1000x700 certificate.
LAYOUT = {
    "seal": (90, 470, 290, 670),
    "signature": (640, 520, 920, 610),
    "photo": (800, 120, 940, 300),
}


def _font(size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # Pillow < 10.1
        return ImageFont.load_default()


def _center_text(draw: ImageDraw.ImageDraw, y: int, text: str, size: int, fill=(30, 30, 30)) -> None:
    font = _font(size)
    left, _, right, _ = draw.textbbox((0, 0), text, font=font)
    draw.text(((W - (right - left)) / 2, y), text, font=font, fill=fill)


def _draw_seal(draw: ImageDraw.ImageDraw, seed: int, label: str) -> None:
    rng = random.Random(seed)
    cx, cy, r = 190, 570, 92
    if seed >= 20:  # non-council ink (used by the altered sample)
        color = (40 + rng.randint(0, 30), 70 + rng.randint(0, 30), 150 + rng.randint(0, 40))
    else:
        color = (170 + rng.randint(-20, 20), 30 + rng.randint(0, 30), 40 + rng.randint(0, 30))
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=color, width=6)
    draw.ellipse((cx - r + 16, cy - r + 16, cx + r - 16, cy + r - 16), outline=color, width=3)
    points = 5 + (seed % 5)
    inner, outer = 18, 44
    star = []
    for i in range(points * 2):
        ang = math.pi / points * i - math.pi / 2 + (seed % 7) * 0.2
        rad = outer if i % 2 == 0 else inner
        star.append((cx + rad * math.cos(ang), cy + rad * math.sin(ang)))
    draw.polygon(star, outline=color, fill=color)
    for i in range(24):
        ang = 2 * math.pi * i / 24
        x = cx + (r - 8) * math.cos(ang)
        y = cy + (r - 8) * math.sin(ang)
        draw.ellipse((x - 2, y - 2, x + 2, y + 2), fill=color)
    font = _font(16)
    left, _, right, _ = draw.textbbox((0, 0), label, font=font)
    draw.text((cx - (right - left) / 2, cy + 50), label, font=font, fill=color)


def _draw_signature(draw: ImageDraw.ImageDraw, seed: int) -> None:
    rng = random.Random(seed)
    x, y = 660.0, 565.0
    pts = [(x, y)]
    for i in range(60):
        x += rng.uniform(2.5, 6.0)
        y = 565 + 20 * math.sin(i * 0.32 + seed) + 8 * math.sin(i * rng.uniform(0.8, 1.2)) + rng.uniform(-2, 2)
        pts.append((x, y))
    draw.line(pts, fill=(20, 40, 120), width=4, joint="curve")
    draw.line((650, 600, 910, 600), fill=(80, 80, 80), width=1)
    draw.text((735, 606), "Registrar", font=_font(16), fill=(60, 60, 60))


def _draw_photo(img: Image.Image, seed: int) -> None:
    rng = random.Random(seed)
    x1, y1, x2, y2 = LAYOUT["photo"]
    pw, ph = x2 - x1, y2 - y1
    bg = (200 + rng.randint(-25, 25), 210 + rng.randint(-25, 25), 225 + rng.randint(-25, 20))
    photo = Image.new("RGB", (pw, ph), bg)
    d = ImageDraw.Draw(photo)
    skin = (150 + rng.randint(-40, 60), 110 + rng.randint(-30, 50), 80 + rng.randint(-30, 40))
    hair = (rng.randint(10, 80),) * 3
    cx = pw // 2
    d.ellipse((cx - 55, ph - 65, cx + 55, ph + 60), fill=(rng.randint(30, 120), rng.randint(30, 120), rng.randint(60, 160)))
    d.ellipse((cx - 32, 30, cx + 32, 105), fill=skin)
    d.chord((cx - 34, 24, cx + 34, 80), 180, 360, fill=hair)
    img.paste(photo, (x1, y1))
    ImageDraw.Draw(img).rectangle((x1, y1, x2, y2), outline=(90, 90, 90), width=2)


def render(record: CertRecord, *, seal_label: Optional[str] = None) -> Image.Image:
    img = Image.new("RGB", (W, H), (252, 249, 240))
    d = ImageDraw.Draw(img)
    d.rectangle((14, 14, W - 14, H - 14), outline=(120, 100, 60), width=4)
    d.rectangle((26, 26, W - 26, H - 26), outline=(170, 150, 100), width=1)
    _center_text(d, 50, record.issuer.upper(), 40, fill=(90, 60, 20))
    _center_text(d, 104, "Certificate of Registration", 26, fill=(60, 60, 60))
    d.text((90, 190), "This is to certify that", font=_font(22), fill=(50, 50, 50))
    d.text((90, 228), record.name, font=_font(40), fill=(10, 10, 10))
    d.text((90, 300), f"Qualification: {record.qualification}", font=_font(22), fill=(30, 30, 30))
    d.text((90, 340), f"Registration No: {record.registration_number}", font=_font(22), fill=(30, 30, 30))
    d.text((90, 380), f"Date of registration: {record.issue_date}", font=_font(22), fill=(30, 30, 30))
    d.text((90, 420), "is registered as a medical practitioner.", font=_font(20), fill=(50, 50, 50))
    _draw_seal(d, record.seal_seed, seal_label or "DMC")
    _draw_signature(d, record.signature_seed)
    _draw_photo(img, record.photo_seed)
    return img


def perturb(img: Image.Image, seed: int = 7) -> Image.Image:
    """Simulate a phone photo / rescan: slight rotation, rescale, JPEG artefacts."""
    rng = random.Random(seed)
    out = img.rotate(rng.uniform(-1.0, 1.0), resample=Image.BICUBIC, fillcolor=(245, 245, 240))
    scale = rng.uniform(0.85, 0.95)
    out = out.resize((int(W * scale), int(H * scale)), Image.LANCZOS)
    buf = io.BytesIO()
    out.save(buf, format="JPEG", quality=70)
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def to_png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class Sample:
    key: str
    title: str
    description: str
    image: Image.Image
    truth: dict = field(default_factory=dict)  # metadata ground truth (offline mode only)


def applicant_samples() -> dict[str, Sample]:
    """The three demo applicants Medaffin receives."""
    genuine = REGISTRY[0]
    forged = CertRecord(
        "forged", genuine.name, genuine.registration_number, genuine.qualification, genuine.issue_date,
        seal_seed=29, signature_seed=909, photo_seed=9,
    )
    unknown = CertRecord(
        "unknown", "Dr. Rohan Kapoor", "DMC-2020-05521", "MBBS, MD (Dermatology)", "17 August 2020",
        seal_seed=11, signature_seed=777, photo_seed=7,
    )
    return {
        "genuine": Sample("genuine", "Genuine certificate", "A rescanned copy of a certificate the council issued.",
                          perturb(render(genuine), seed=3), genuine.metadata()),
        "forged": Sample("forged", "Altered certificate", "Same name and number as a real doctor, different seal and signature.",
                         perturb(render(forged), seed=5), forged.metadata()),
        "unknown": Sample("unknown", "Unknown registrant", "Looks right, but the council never issued it.",
                          perturb(render(unknown), seed=8), unknown.metadata()),
    }


def layout_boxes(img_w: int, img_h: int) -> dict[str, tuple[int, int, int, int]]:
    """Layout boxes scaled to an image size (offline fallback when SAM is unavailable)."""
    sx, sy = img_w / W, img_h / H
    return {k: (int(a * sx), int(b * sy), int(c * sx), int(d * sy)) for k, (a, b, c, d) in LAYOUT.items()}


__all__ = ["CertRecord", "REGISTRY", "ISSUER", "render", "perturb", "to_png", "applicant_samples", "layout_boxes", "asdict"]
