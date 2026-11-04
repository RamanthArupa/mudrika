"""Thin async clients for Meta Model API (SAM 3.1, Muse Spark) and Baseten (Muse Spark Open).

Only httpx is used, so there is no SDK dependency. Every call has a timeout and
raises ModelError on failure; callers decide whether that means a refund
(seller side) or a declined onboarding step (buyer side).

Docs used:
- Meta Model API base URL https://api.meta.ai/v1, Bearer MODEL_API_KEY.
- SAM 3.1: POST /v1/responses, model "sam-3.1", input_text concept + input_image,
  streamed special-token output: <Nf>id<|box;x1=..;y1=..;x2=..;y2=..;w=W;h=H|><|mask;...|>,...
- Muse Spark: OpenAI-compatible chat completions, model "muse-spark-1.3".
- Baseten Model APIs: https://inference.baseten.co/v1, model "meta-models/muse-spark-open".
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

import httpx

META_BASE_URL = os.environ.get("META_BASE_URL", "https://api.meta.ai/v1")
META_SAM_MODEL = os.environ.get("META_SAM_MODEL", "sam-3.1")
META_MUSE_MODEL = os.environ.get("META_MUSE_MODEL", "muse-spark-1.3")
BASETEN_BASE_URL = os.environ.get("BASETEN_BASE_URL", "https://inference.baseten.co/v1")
BASETEN_MODEL = os.environ.get("BASETEN_MODEL", "meta-models/muse-spark-open")

_BOX_RE = re.compile(r"(\d+)\s*<\|box;([^|>]*)\|>")


class ModelError(RuntimeError):
    pass


@dataclass
class Box:
    """A SAM 3.1 detection, in pixel coordinates of the original image."""

    label: str
    object_id: int
    x1: int
    y1: int
    x2: int
    y2: int

    def as_dict(self) -> dict:
        return {"label": self.label, "id": self.object_id, "x1": self.x1, "y1": self.y1, "x2": self.x2, "y2": self.y2}


def _meta_key() -> str:
    key = os.environ.get("META_API_KEY") or os.environ.get("MODEL_API_KEY")
    if not key:
        raise ModelError("META_API_KEY is not set")
    return key


def data_url(png_bytes: bytes, mime: str = "image/png") -> str:
    return f"data:{mime};base64,{base64.b64encode(png_bytes).decode('ascii')}"


def parse_sam_boxes(output_text: str, label: str, img_w: int, img_h: int) -> list[Box]:
    """Parse box records from SAM 3.1 special-token text and scale them to the image.

    Box coordinates are relative to the frame size reported in the record
    (w=, h=), which may differ from the uploaded image size.
    """
    boxes: list[Box] = []
    for match in _BOX_RE.finditer(output_text):
        obj_id = int(match.group(1))
        fields: dict[str, float] = {}
        for part in match.group(2).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                try:
                    fields[k.strip()] = float(v)
                except ValueError:
                    pass
        if not all(k in fields for k in ("x1", "y1", "x2", "y2")):
            continue
        fw = fields.get("w") or img_w
        fh = fields.get("h") or img_h
        sx, sy = img_w / fw, img_h / fh
        boxes.append(Box(
            label=label,
            object_id=obj_id,
            x1=max(0, int(fields["x1"] * sx)),
            y1=max(0, int(fields["y1"] * sy)),
            x2=min(img_w, int(fields["x2"] * sx)),
            y2=min(img_h, int(fields["y2"] * sy)),
        ))
    return boxes


async def sam_segment(png_bytes: bytes, concept: str, img_w: int, img_h: int, timeout: float = 60.0) -> tuple[list[Box], str]:
    """Run SAM 3.1 on one image for one concept. Returns (boxes, raw output text)."""
    payload = {
        "model": META_SAM_MODEL,
        "stream": True,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": concept},
                    {"type": "input_image", "image_url": data_url(png_bytes)},
                ],
            }
        ],
    }
    headers = {
        "Authorization": f"Bearer {_meta_key()}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    deltas: list[str] = []
    final_text: Optional[str] = None
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            async with http.stream("POST", f"{META_BASE_URL}/responses", json=payload, headers=headers) as resp:
                if resp.status_code >= 400:
                    body = (await resp.aread()).decode("utf-8", "replace")[:500]
                    raise ModelError(f"SAM 3.1 HTTP {resp.status_code}: {body}")
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data or data == "[DONE]":
                        continue
                    try:
                        event = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    etype = event.get("type", "")
                    if etype == "response.output_text.delta":
                        deltas.append(event.get("delta", ""))
                    elif etype == "response.output_text.done":
                        final_text = event.get("text")
                    elif etype == "response.completed" and final_text is None:
                        final_text = _output_text_from_response(event.get("response") or {})
                    elif etype in ("response.failed", "error"):
                        raise ModelError(f"SAM 3.1 stream error: {json.dumps(event)[:500]}")
    except httpx.HTTPError as exc:
        raise ModelError(f"SAM 3.1 transport error: {exc}") from exc
    text = final_text if final_text else "".join(deltas)
    return parse_sam_boxes(text, concept, img_w, img_h), text


def _output_text_from_response(response: dict) -> str:
    chunks: list[str] = []
    for item in response.get("output") or []:
        for part in item.get("content") or []:
            if part.get("type") == "output_text":
                chunks.append(part.get("text", ""))
    return "".join(chunks)


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply (tolerates fences and reasoning)."""
    if not text:
        raise ModelError("empty model reply")
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if fenced:
        return json.loads(fenced.group(1))
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise ModelError(f"no JSON object in model reply: {text[:200]}")


async def _chat(base_url: str, api_key: str, model: str, messages: list[dict], timeout: float, auth_scheme: str = "Bearer") -> str:
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            resp = await http.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"{auth_scheme} {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "temperature": 0},
            )
    except httpx.HTTPError as exc:
        raise ModelError(f"{model} transport error: {exc}") from exc
    if resp.status_code >= 400:
        raise ModelError(f"{model} HTTP {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError) as exc:
        raise ModelError(f"{model}: unexpected reply shape") from exc
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


async def muse_json(prompt: str, images: Optional[list[bytes]] = None, system: str = "", timeout: float = 90.0) -> dict:
    """Ask Muse Spark (Meta Model API) for a JSON object, optionally with images."""
    content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    for img in images or []:
        content.append({"type": "image_url", "image_url": {"url": data_url(img)}})
    messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": content}]
    text = await _chat(META_BASE_URL, _meta_key(), META_MUSE_MODEL, messages, timeout)
    return extract_json(text)


async def muse_open_json(system: str, user: str, timeout: float = 60.0) -> dict:
    """Ask Muse Spark Open on Baseten for a JSON object."""
    key = os.environ.get("BASETEN_API_KEY")
    if not key:
        raise ModelError("BASETEN_API_KEY is not set")
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = await _chat(BASETEN_BASE_URL, key, BASETEN_MODEL, messages, timeout)
    return extract_json(text)
