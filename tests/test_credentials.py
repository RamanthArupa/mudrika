"""Offline tests for the credential-matching reference service (no network, no Redis)."""
from credentials import certs, matching, vision
from credentials.meta_client import extract_json, parse_sam_boxes


def _index():
    out = []
    for record in certs.REGISTRY:
        img = certs.render(record)
        boxes = certs.layout_boxes(img.width, img.height)
        out.append({"cert_id": record.cert_id, "metadata": record.metadata(),
                    "regions": {k: vision.fingerprint(vision.crop(img, v)) for k, v in boxes.items()}})
    return out


def _submit(sample):
    boxes = certs.layout_boxes(sample.image.width, sample.image.height)
    return {k: vision.fingerprint(vision.crop(sample.image, v)) for k, v in boxes.items()}


def test_three_demo_verdicts():
    index, samples = _index(), certs.applicant_samples()
    assert matching.match(samples["genuine"].truth, _submit(samples["genuine"]), index)["verdict"] == "MATCH"
    forged = matching.match(samples["forged"].truth, _submit(samples["forged"]), index)
    assert forged["verdict"] == "NEAR_MATCH" and forged["best"]["cert_id"] == "dmc-0001"
    assert matching.match(samples["unknown"].truth, _submit(samples["unknown"]), index)["verdict"] == "NO_MATCH"


def test_metadata_only_still_ranks():
    index, samples = _index(), certs.applicant_samples()
    result = matching.match(samples["genuine"].truth, {}, index)
    assert result["best"]["cert_id"] == "dmc-0001" and result["verdict"] != "MATCH"


def test_parse_sam_wire_format_scales_to_image():
    text = ("<0f>0<|box;x1=211;y1=228;x2=270;y2=254;w=320;h=334|><|mask;x=0;y=0;data=27,60,~abc|>"
            ",1<|box;x1=155;y1=228;x2=202;y2=254;w=320;h=334|><|mask;x=0;y=0;data=27,48,~def|>\n")
    boxes = parse_sam_boxes(text, "seal", 640, 668)
    assert [(b.object_id, b.x1, b.y1, b.x2, b.y2) for b in boxes] == [(0, 422, 456, 540, 508), (1, 310, 456, 404, 508)]


def test_extract_json_tolerates_fences_and_reasoning():
    assert extract_json('<think>hmm</think>```json\n{"approve": true, "summary": "ok"}\n```')["approve"] is True
    assert extract_json('Sure: {"name": "Dr. A", "x": {"y": 1}} done')["x"] == {"y": 1}
