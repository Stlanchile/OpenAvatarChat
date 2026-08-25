from __future__ import annotations

import dataclasses
import math

import pytest

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.contracts.ocr import (
    MAX_OCR_AGGREGATE_CHARACTERS_V1,
    MAX_OCR_CHARACTERS_PER_SPAN_V1,
    MAX_OCR_JSON_NESTING_DEPTH_V1,
    MAX_OCR_SPANS_PER_PAGE_V1,
    OCR_PAGE_RESULT_SCHEMA_VERSION_V1,
    OcrPageResultV1,
    OcrPointV1,
    OcrSpanV1,
    decode_strict_ocr_json_object_v1,
    ocr_page_result_from_canonical_json_v1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.ocr.protocol import (
    MAX_OCR_REQUEST_METADATA_BYTES_V1,
    MAX_OCR_RESPONSE_BYTES_V1,
    OCR_FRAME_PREFIX_V1,
    OCR_REQUEST_MAGIC_V1,
    OCR_RESPONSE_SCHEMA_VERSION_V1,
    OcrFailureReasonV1,
    OcrRequestV1,
    OcrServiceErrorV1,
    encode_ocr_response_frame_v1,
    parse_ocr_request_metadata_v1,
    parse_ocr_response_payload_v1,
    unpack_frame_prefix_v1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from tests.chat_engine.milestone_5a.conftest import (
    SYNTHETIC_SHA256_V1,
    synthetic_inference_identity_v1,
)


@pytest.fixture
def capture_epoch_v1():
    controller = SessionWorkControllerV1._create_for_test_v1()
    epoch = CaptureEpochV1(
        session_epoch=controller.current_epoch_v1(),
        capture_id=new_uuid7_v1(),
        capture_seq=1,
    )
    yield epoch
    assert controller.shutdown()


def _span(
    *,
    text: str = "录取 Notice 2026-08-25",
    score: float | None = 0.75,
) -> OcrSpanV1:
    return OcrSpanV1(
        span_id=new_uuid7_v1(),
        text=text,
        polygon=(
            OcrPointV1(0.1, 0.1),
            OcrPointV1(0.9, 0.1),
            OcrPointV1(0.9, 0.2),
            OcrPointV1(0.1, 0.2),
        ),
        raw_engine_score=score,
    )


def _page(capture_epoch, *, frame_id=None, identity=None):
    identity = identity or synthetic_inference_identity_v1()
    return OcrPageResultV1(
        result_id=new_uuid7_v1(),
        capture_epoch=capture_epoch,
        frame_id=frame_id or new_uuid7_v1(),
        inference_identity_sha256=identity.inference_identity_sha256,
        preprocessing_identity=identity.preprocessing,
        spans=(_span(),),
    )


def _request(capture_epoch, page):
    return OcrRequestV1(
        request_id=new_uuid7_v1(),
        frame_id=page.frame_id,
        capture_epoch=capture_epoch,
        operation_id=new_uuid7_v1(),
        inference_identity_expected=page.inference_identity_sha256,
        preprocessing_identity_sha256_expected=(page.preprocessing_identity_sha256),
        canonical_width=1920,
        canonical_height=1080,
        jpeg_length=1024,
    )


def _response_payload(request, page) -> bytes:
    frame = encode_ocr_response_frame_v1(
        request=request,
        result=page,
    )
    return frame[OCR_FRAME_PREFIX_V1.size :]


def test_ocr_result_round_trip_is_canonical_and_semantics_free(
    capture_epoch_v1,
):
    page = _page(capture_epoch_v1)
    payload = page.canonical_json_v1()
    restored = ocr_page_result_from_canonical_json_v1(
        payload,
        expected_capture_epoch=capture_epoch_v1,
    )

    assert restored == page
    assert restored.spans[0].raw_engine_score == 0.75
    assert "confidence" not in payload.decode()
    assert (
        not {
            "name",
            "source_province",
            "college",
            "major",
            "issuer",
            "document_type",
            "assertions",
        }
        & restored.canonical_object_v1().keys()
    )
    assert "录取 Notice 2026-08-25" not in repr(restored)
    assert "录取 Notice 2026-08-25" not in repr(restored.spans[0])


@pytest.mark.parametrize(
    ("point", "score"),
    [
        ((math.nan, 0.1), 0.5),
        ((math.inf, 0.1), 0.5),
        ((-0.1, 0.1), 0.5),
        ((1.1, 0.1), 0.5),
        ((0.1, 0.1), math.nan),
        ((0.1, 0.1), math.inf),
        ((0.1, 0.1), -0.1),
        ((0.1, 0.1), 1.1),
    ],
)
def test_polygon_and_engine_score_reject_nonfinite_or_out_of_range(
    point,
    score,
):
    with pytest.raises(ValueError):
        first = OcrPointV1(*point)
        OcrSpanV1(
            span_id=new_uuid7_v1(),
            text="bounded",
            polygon=(
                first,
                OcrPointV1(0.2, 0.1),
                OcrPointV1(0.2, 0.2),
                OcrPointV1(0.1, 0.2),
            ),
            raw_engine_score=score,
        )


def test_text_polygon_span_and_ordering_bounds(capture_epoch_v1):
    with pytest.raises(ValueError):
        _span(text="x" * (MAX_OCR_CHARACTERS_PER_SPAN_V1 + 1))
    with pytest.raises(ValueError):
        OcrSpanV1(
            span_id=new_uuid7_v1(),
            text="x",
            polygon=(OcrPointV1(0.0, 0.0),),
        )
    with pytest.raises(ValueError):
        _span(text="line\nbreak")

    identity = synthetic_inference_identity_v1()
    later = OcrSpanV1(
        span_id=new_uuid7_v1(),
        text="later",
        polygon=(
            OcrPointV1(0.1, 0.8),
            OcrPointV1(0.9, 0.8),
            OcrPointV1(0.9, 0.9),
            OcrPointV1(0.1, 0.9),
        ),
    )
    earlier = _span(text="earlier")
    with pytest.raises(ValueError, match="deterministic"):
        OcrPageResultV1(
            result_id=new_uuid7_v1(),
            capture_epoch=capture_epoch_v1,
            frame_id=new_uuid7_v1(),
            inference_identity_sha256=identity.inference_identity_sha256,
            preprocessing_identity=identity.preprocessing,
            spans=(later, earlier),
        )

    duplicate_region_low_score = _span(text="duplicate", score=0.1)
    duplicate_region_high_score = _span(text="duplicate", score=0.9)
    ordered_duplicates = OcrPageResultV1(
        result_id=new_uuid7_v1(),
        capture_epoch=capture_epoch_v1,
        frame_id=new_uuid7_v1(),
        inference_identity_sha256=identity.inference_identity_sha256,
        preprocessing_identity=identity.preprocessing,
        spans=(
            duplicate_region_low_score,
            duplicate_region_high_score,
        ),
    )
    assert tuple(span.raw_engine_score for span in ordered_duplicates.spans) == (
        0.1,
        0.9,
    )
    with pytest.raises(ValueError, match="deterministic"):
        dataclasses.replace(
            ordered_duplicates,
            spans=tuple(reversed(ordered_duplicates.spans)),
        )


def test_aggregate_and_span_count_are_bounded(capture_epoch_v1):
    identity = synthetic_inference_identity_v1()
    shared = _span(text="x")
    with pytest.raises(ValueError):
        OcrPageResultV1(
            result_id=new_uuid7_v1(),
            capture_epoch=capture_epoch_v1,
            frame_id=new_uuid7_v1(),
            inference_identity_sha256=identity.inference_identity_sha256,
            preprocessing_identity=identity.preprocessing,
            spans=tuple(
                _span(text=f"{index:03d}")
                for index in range(MAX_OCR_SPANS_PER_PAGE_V1 + 1)
            ),
        )
    with pytest.raises(ValueError):
        OcrPageResultV1(
            result_id=new_uuid7_v1(),
            capture_epoch=capture_epoch_v1,
            frame_id=new_uuid7_v1(),
            inference_identity_sha256=identity.inference_identity_sha256,
            preprocessing_identity=identity.preprocessing,
            spans=tuple(
                OcrSpanV1(
                    span_id=new_uuid7_v1(),
                    text="x" * MAX_OCR_CHARACTERS_PER_SPAN_V1,
                    polygon=(
                        OcrPointV1(0.0, index / 128),
                        OcrPointV1(1.0, index / 128),
                        OcrPointV1(1.0, (index + 0.5) / 128),
                        OcrPointV1(0.0, (index + 0.5) / 128),
                    ),
                )
                for index in range(
                    MAX_OCR_AGGREGATE_CHARACTERS_V1 // MAX_OCR_CHARACTERS_PER_SPAN_V1
                    + 1
                )
            ),
        )
    assert shared.text == "x"


def test_strict_json_rejects_duplicate_nan_depth_and_non_object():
    with pytest.raises(ValueError):
        decode_strict_ocr_json_object_v1(
            b'{"a":1,"a":2}',
            maximum_bytes=128,
        )
    with pytest.raises(ValueError):
        decode_strict_ocr_json_object_v1(
            b'{"a":NaN}',
            maximum_bytes=128,
        )
    nested = b"[" * (MAX_OCR_JSON_NESTING_DEPTH_V1 + 1) + b"]" * (
        MAX_OCR_JSON_NESTING_DEPTH_V1 + 1
    )
    with pytest.raises(ValueError):
        decode_strict_ocr_json_object_v1(nested, maximum_bytes=128)
    with pytest.raises(TypeError):
        decode_strict_ocr_json_object_v1(b"[]", maximum_bytes=128)


def test_request_framing_is_exact_and_bounded(capture_epoch_v1):
    page = _page(capture_epoch_v1)
    request = _request(capture_epoch_v1, page)
    framed = request.frame_prefix_and_metadata_v1()
    prefix = framed[: OCR_FRAME_PREFIX_V1.size]
    metadata_length, jpeg_length = unpack_frame_prefix_v1(
        prefix,
        expected_magic=OCR_REQUEST_MAGIC_V1,
        maximum_metadata_bytes=MAX_OCR_REQUEST_METADATA_BYTES_V1,
        maximum_payload_bytes=2 * 1024 * 1024,
    )
    metadata = framed[OCR_FRAME_PREFIX_V1.size :]

    assert metadata_length == len(metadata)
    assert jpeg_length == request.jpeg_length
    parsed = parse_ocr_request_metadata_v1(
        metadata,
        declared_jpeg_length=jpeg_length,
        expected_capture_epoch=capture_epoch_v1,
    )
    assert parsed["frame_id"] == str(page.frame_id)
    assert {
        "access_token",
        "capture_capability",
        "principal",
        "session_capability",
        "work_fence",
    }.isdisjoint(parsed)


@pytest.mark.parametrize(
    "prefix",
    [
        b"",
        OCR_FRAME_PREFIX_V1.pack(b"BADMAGIC", 1, 1),
        OCR_FRAME_PREFIX_V1.pack(
            OCR_REQUEST_MAGIC_V1,
            MAX_OCR_REQUEST_METADATA_BYTES_V1 + 1,
            1,
        ),
        OCR_FRAME_PREFIX_V1.pack(
            OCR_REQUEST_MAGIC_V1,
            1,
            2 * 1024 * 1024 + 1,
        ),
    ],
)
def test_malformed_or_oversized_header_is_rejected(prefix):
    with pytest.raises(OcrServiceErrorV1) as failure:
        unpack_frame_prefix_v1(
            prefix,
            expected_magic=OCR_REQUEST_MAGIC_V1,
            maximum_metadata_bytes=MAX_OCR_REQUEST_METADATA_BYTES_V1,
            maximum_payload_bytes=2 * 1024 * 1024,
        )
    assert failure.value.reason is OcrFailureReasonV1.PROTOCOL_REJECTED


def test_request_declared_length_version_and_unknown_fields_fail(
    capture_epoch_v1,
):
    page = _page(capture_epoch_v1)
    request = _request(capture_epoch_v1, page)
    value = request.canonical_metadata_object_v1()
    for mutation in (
        {"jpeg_length": request.jpeg_length + 1},
        {"protocol_version": "unsupported"},
        {"unexpected": True},
    ):
        changed = dict(value)
        changed.update(mutation)
        with pytest.raises(OcrServiceErrorV1):
            parse_ocr_request_metadata_v1(
                canonical_json_bytes_v1(changed),
                declared_jpeg_length=request.jpeg_length,
                expected_capture_epoch=capture_epoch_v1,
            )


def test_response_correlation_identity_and_unknown_fields_fail(
    capture_epoch_v1,
):
    page = _page(capture_epoch_v1)
    request = _request(capture_epoch_v1, page)
    valid = {
        "operation": "OCR",
        "operation_id": str(request.operation_id),
        "protocol_version": request.protocol_version,
        "request_id": str(request.request_id),
        "result": page.canonical_object_v1(),
        "schema_version": OCR_RESPONSE_SCHEMA_VERSION_V1,
    }
    assert (
        parse_ocr_response_payload_v1(
            canonical_json_bytes_v1(valid),
            request=request,
        )
        == page
    )

    mutations = (
        ("request_id", str(new_uuid7_v1()), OcrFailureReasonV1.CORRELATION_MISMATCH),
        ("operation_id", str(new_uuid7_v1()), OcrFailureReasonV1.CORRELATION_MISMATCH),
        ("unexpected", True, OcrFailureReasonV1.MALFORMED_RESPONSE),
    )
    for key, value, expected_reason in mutations:
        changed = dict(valid)
        changed[key] = value
        with pytest.raises(OcrServiceErrorV1) as failure:
            parse_ocr_response_payload_v1(
                canonical_json_bytes_v1(changed),
                request=request,
            )
        assert failure.value.reason is expected_reason

    wrong_identity = dict(page.canonical_object_v1())
    wrong_identity["inference_identity_sha256"] = SYNTHETIC_SHA256_V1
    changed = dict(valid)
    changed["result"] = wrong_identity
    with pytest.raises(OcrServiceErrorV1) as failure:
        parse_ocr_response_payload_v1(
            canonical_json_bytes_v1(changed),
            request=request,
        )
    assert failure.value.reason is OcrFailureReasonV1.IDENTITY_MISMATCH


def test_response_wrong_frame_invalid_polygon_and_oversize_fail(
    capture_epoch_v1,
):
    page = _page(capture_epoch_v1)
    request = _request(capture_epoch_v1, page)
    base = {
        "operation": "OCR",
        "operation_id": str(request.operation_id),
        "protocol_version": request.protocol_version,
        "request_id": str(request.request_id),
        "result": page.canonical_object_v1(),
        "schema_version": OCR_RESPONSE_SCHEMA_VERSION_V1,
    }
    wrong_frame = dict(page.canonical_object_v1())
    wrong_frame["frame_id"] = str(new_uuid7_v1())
    changed = dict(base)
    changed["result"] = wrong_frame
    with pytest.raises(OcrServiceErrorV1) as failure:
        parse_ocr_response_payload_v1(
            canonical_json_bytes_v1(changed),
            request=request,
        )
    assert failure.value.reason is OcrFailureReasonV1.CORRELATION_MISMATCH

    invalid_polygon = dict(page.canonical_object_v1())
    spans = [dict(invalid_polygon["spans"][0])]
    spans[0]["polygon"] = [[math.nan, 0.0]] * 4
    invalid_polygon["spans"] = spans
    changed = dict(base)
    changed["result"] = invalid_polygon
    with pytest.raises(ValueError):
        canonical_json_bytes_v1(changed)

    with pytest.raises(OcrServiceErrorV1) as failure:
        parse_ocr_response_payload_v1(
            b"{" + b"x" * MAX_OCR_RESPONSE_BYTES_V1,
            request=request,
        )
    assert failure.value.reason is OcrFailureReasonV1.MALFORMED_RESPONSE


def test_result_unknown_field_and_schema_version_fail(capture_epoch_v1):
    page = _page(capture_epoch_v1)
    value = page.canonical_object_v1()
    value["unexpected"] = "rejected"
    with pytest.raises(ValueError):
        ocr_page_result_from_canonical_json_v1(
            canonical_json_bytes_v1(value),
            expected_capture_epoch=capture_epoch_v1,
        )

    value = page.canonical_object_v1()
    value["schema_version"] = "unsupported"
    with pytest.raises(ValueError):
        ocr_page_result_from_canonical_json_v1(
            canonical_json_bytes_v1(value),
            expected_capture_epoch=capture_epoch_v1,
        )
    assert page.schema_version == OCR_PAGE_RESULT_SCHEMA_VERSION_V1
