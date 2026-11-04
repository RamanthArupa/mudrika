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


def test_seal_only_forgery_is_not_a_match():
    """With only the seal compared (what SAM finds today), a wrong seal must not pass."""
    index, samples = _index(), certs.applicant_samples()
    regs = {k: v for k, v in _submit(samples["forged"]).items() if k == "seal"}
    assert matching.match(samples["forged"].truth, regs, index)["verdict"] == "NEAR_MATCH"
    regs = {k: v for k, v in _submit(samples["genuine"]).items() if k == "seal"}
    assert matching.match(samples["genuine"].truth, regs, index)["verdict"] == "MATCH"


def test_live_sam_boxes_separate_genuine_and_altered_seal():
    """Regression: the boxes SAM 3.1 returned in production for the demo seals."""
    ref = vision.fingerprint(vision.crop(certs.render(certs.REGISTRY[0]), (98, 478, 281, 662)))
    samples = certs.applicant_samples()
    genuine = vision.fingerprint(vision.crop(samples["genuine"].image, (87, 430, 252, 595)))
    forged = vision.fingerprint(vision.crop(samples["forged"].image, (91, 442, 261, 612)))
    assert vision.region_similarity(ref, genuine) >= 0.9
    assert vision.region_similarity(ref, forged) < 0.7
    index = [{"cert_id": "dmc-0001", "metadata": certs.REGISTRY[0].metadata(), "regions": {"seal": ref}}]
    assert matching.match(samples["genuine"].truth, {"seal": genuine}, index)["verdict"] == "MATCH"
    assert matching.match(samples["forged"].truth, {"seal": forged}, index)["verdict"] == "NEAR_MATCH"


def test_real_seal_alone_does_not_lift_an_unknown_registrant():
    index, samples = _index(), certs.applicant_samples()
    regs = {k: v for k, v in _submit(samples["unknown"]).items() if k == "seal"}
    assert matching.match(samples["unknown"].truth, regs, index)["verdict"] == "NO_MATCH"
