from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import admission_notice_lite_l3_qualify as integration_qualify
from scripts.admission_notice_lite_l3_source_projection import (
    APPROVED_MODEL_MANIFEST_SHA256_LITE_V1,
    HISTORICAL_L3_COMMIT,
    HISTORICAL_L3_QUALIFICATION_SOURCE_SHA256,
    L3_MAIN_SOURCE_PATHS,
    L3_QUALIFICATION_SOURCE_PATHS,
    L3_SIDECAR_SOURCE_PATHS,
    L4_DOWNSTREAM_SOURCE_PATHS,
    L5_DOWNSTREAM_SOURCE_PATHS,
    L3SourceProjectionError,
    L3SourceProjectionMismatch,
    historical_l3_qualification_source_sha256,
    l3_projection_sha256,
    reconstruct_historical_l3_qualified_sources,
)


@pytest.fixture(scope="module")
def current_sources() -> dict[str, bytes]:
    return {
        path: (PROJECT_ROOT / path).read_bytes()
        for path in L3_QUALIFICATION_SOURCE_PATHS
    }


@pytest.fixture(scope="module")
def historical_sources() -> dict[str, bytes]:
    return {
        path: subprocess.check_output(
            ("git", "show", f"{HISTORICAL_L3_COMMIT}:{path}"),
            cwd=PROJECT_ROOT,
        )
        for path in L3_QUALIFICATION_SOURCE_PATHS
    }


def _replace_once(
    sources: dict[str, bytes],
    path: str,
    old: bytes,
    new: bytes,
) -> dict[str, bytes]:
    mutated = dict(sources)
    assert mutated[path].count(old) == 1
    mutated[path] = mutated[path].replace(old, new, 1)
    return mutated


def _assert_invalid(
    mutated: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    with pytest.raises((L3SourceProjectionError, L3SourceProjectionMismatch)):
        reconstruct_historical_l3_qualified_sources(
            current_sources=mutated,
            historical_sources=historical_sources,
        )


def test_positive_projection_reconstructs_exact_historical_source_identity(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    assert L3_SIDECAR_SOURCE_PATHS == integration_qualify._SIDECAR_SOURCE_PATHS
    assert L3_MAIN_SOURCE_PATHS == integration_qualify._MAIN_SOURCE_PATHS
    reconstructed = reconstruct_historical_l3_qualified_sources(
        current_sources=current_sources,
        historical_sources=historical_sources,
    )
    assert historical_l3_qualification_source_sha256(reconstructed) == (
        HISTORICAL_L3_QUALIFICATION_SOURCE_SHA256
    )
    assert l3_projection_sha256(current_sources) == l3_projection_sha256(
        historical_sources
    )


def test_historical_artifact_sidecar_manifest_and_tuple_remain_independent(
    current_sources: dict[str, bytes],
) -> None:
    report = json.loads(
        (
            PROJECT_ROOT
            / "services/admission_notice_ocr/qualification/qualification.json"
        ).read_text(encoding="utf-8")
    )
    assert report["result"] == "PASS"
    assert report["qualification_source_sha256"] == (
        HISTORICAL_L3_QUALIFICATION_SOURCE_SHA256
    )
    assert report["sidecar_source_sha256"] == (
        integration_qualify._sidecar_source_sha256()
    )
    assert report["model_manifest_sha256"] == (APPROVED_MODEL_MANIFEST_SHA256_LITE_V1)
    assert report["backend"] == "paddle_static"
    assert report["device"] == "cpu"
    assert report["selected_thread_count"] == 2
    assert report["package_versions"] == {
        "paddleocr": "3.7.0",
        "paddlepaddle": "3.3.0",
        "paddlex": "3.7.2",
    }
    assert (
        APPROVED_MODEL_MANIFEST_SHA256_LITE_V1.encode()
        in current_sources["src/service/admission_notice_lite_ocr_qualification.py"]
    )


@pytest.mark.parametrize(
    ("path", "old", "new"),
    (
        (
            "src/service/admission_notice_lite_contracts.py",
            b"MAX_OCR_SPANS_PER_FRAME_LITE_V1 = 128",
            b"MAX_OCR_SPANS_PER_FRAME_LITE_V1 = 127",
        ),
        (
            "src/service/admission_notice_lite_contracts.py",
            b"len(self.polygon) != 4",
            b"len(self.polygon) != 3",
        ),
        (
            "src/service/admission_notice_lite_contracts.py",
            b"not 0.0 <= self.score <= 1.0",
            b"not 0.0 < self.score <= 1.0",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b'OCR_REQUEST_MAGIC_LITE_V1 = b"ANLQ"',
            b'OCR_REQUEST_MAGIC_LITE_V1 = b"BADQ"',
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"timeout_seconds=min(self.timeout_seconds, 2.0)",
            b"timeout_seconds=min(self.timeout_seconds, 3.0)",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"QUALIFIED_OCR_THREAD_COUNT_LITE_V1 = 2",
            b"QUALIFIED_OCR_THREAD_COUNT_LITE_V1 = 4",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b'QUALIFIED_PADDLE_VERSION_LITE_V1 = "3.3.0"',
            b'QUALIFIED_PADDLE_VERSION_LITE_V1 = "3.4.0"',
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b'QUALIFIED_OCR_DEVICE_LITE_V1 = "cpu"',
            b'QUALIFIED_OCR_DEVICE_LITE_V1 = "gpu"',
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"expected_manifest is not None and identity ==",
            b"expected_manifest is not None or identity ==",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"batch = await self.client.recognize(",
            b"batch = await self.client.ping(",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"if remaining <= 0:",
            b"if remaining < 0:",
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b'len(value["frames"]) != expected_frame_count',
            b'len(value["frames"]) < expected_frame_count',
        ),
        (
            "src/service/admission_notice_lite_ocr.py",
            b"OcrFailureCodeLiteV1.OCR_TIMEOUT,\n",
            b"OcrFailureCodeLiteV1.OCR_RUNTIME_ERROR,\n",
        ),
        (
            "src/service/admission_notice_lite_service.py",
            b"await self._finish_failed(job, RecognitionErrorReasonLiteV1.INTERNAL_ERROR)",
            b"await self._finish_failed(job, RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE)",
        ),
        (
            "services/admission_notice_ocr/src/admission_notice_ocr/protocol.py",
            b"SCHEMA_VERSION = 1",
            b"SCHEMA_VERSION = 2",
        ),
        (
            "services/admission_notice_ocr/model_manifest.json",
            b'  "thread_count": 2',
            b'  "thread_count": 4',
        ),
        (
            "src/service/admission_notice_lite_ocr_qualification.py",
            APPROVED_MODEL_MANIFEST_SHA256_LITE_V1.encode(),
            b"0" * 64,
        ),
    ),
)
def test_each_l3_owned_mutation_invalidates_historical_compatibility(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
    path: str,
    old: bytes,
    new: bytes,
) -> None:
    _assert_invalid(
        _replace_once(current_sources, path, old, new),
        historical_sources,
    )


def test_l3_processor_wrapper_cannot_bypass_the_projected_ocr_stage(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    mutated = _replace_once(
        current_sources,
        "src/service/admission_notice_lite_ocr.py",
        b"batch = await self.recognize_batch(context, frames)",
        b"batch = OcrBatchLiteV1(frames=())",
    )
    _assert_invalid(mutated, historical_sources)


def test_l3_error_cannot_be_hidden_as_a_semantic_failure(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    mutated = _replace_once(
        current_sources,
        "src/service/admission_notice_lite_service.py",
        b"        RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE,\n",
        b"        RecognitionErrorReasonLiteV1.INTERNAL_ERROR,\n",
    )
    _assert_invalid(mutated, historical_sources)


def test_only_exact_reviewed_l4_semantic_failure_mapping_is_downstream(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    baseline = l3_projection_sha256(current_sources)
    assert baseline == l3_projection_sha256(historical_sources)

    changed_handler = _replace_once(
        current_sources,
        "src/service/admission_notice_lite_service.py",
        b'"Admission Notice Lite processor failed "\n'
        b'                        "recognition_id={} reason={}",',
        b'"Admission Notice Lite semantic processing failed "\n'
        b'                        "recognition_id={} reason={}",',
    )
    _assert_invalid(changed_handler, historical_sources)

    fifth_reason = _replace_once(
        current_sources,
        "src/service/admission_notice_lite_contracts.py",
        b'    INTERNAL_ERROR = "INTERNAL_ERROR"',
        b'    FUTURE_SEMANTIC_REASON = "FUTURE_SEMANTIC_REASON"\n'
        b'    INTERNAL_ERROR = "INTERNAL_ERROR"',
    )
    fifth_reason = _replace_once(
        fifth_reason,
        "src/service/admission_notice_lite_service.py",
        b"        RecognitionErrorReasonLiteV1.AMBIGUOUS_NOTICE,\n",
        b"        RecognitionErrorReasonLiteV1.AMBIGUOUS_NOTICE,\n"
        b"        RecognitionErrorReasonLiteV1.FUTURE_SEMANTIC_REASON,\n",
    )
    _assert_invalid(fifth_reason, historical_sources)


def test_l4_result_matcher_and_extractors_are_outside_the_l3_path_inventory(
    current_sources: dict[str, bytes],
) -> None:
    assert set(L4_DOWNSTREAM_SOURCE_PATHS).isdisjoint(L3_QUALIFICATION_SOURCE_PATHS)
    baseline = l3_projection_sha256(current_sources)
    downstream = {
        path: (PROJECT_ROOT / path).read_bytes() for path in L4_DOWNSTREAM_SOURCE_PATHS
    }
    downstream["src/service/admission_notice_lite_semantics.py"] += (
        b"\n# downstream matcher/name/province/major test-only mutation\n"
    )
    downstream["src/service/admission_notice_lite_major_catalog.py"] += (
        b"\n# downstream result/catalog test-only mutation\n"
    )
    assert downstream
    assert l3_projection_sha256(current_sources) == baseline


def test_removed_l5_bridge_and_l6r_dto_remain_outside_l3_inventory() -> None:
    assert set(L5_DOWNSTREAM_SOURCE_PATHS).isdisjoint(L3_QUALIFICATION_SOURCE_PATHS)
    assert set(L5_DOWNSTREAM_SOURCE_PATHS) == {
        "src/demo.py",
        "src/handlers/agent/chat_agent_handler.py",
        "src/handlers/agent/prompt/prompt_compiler.py",
        "src/service/admission_notice_lite_chat_context.py",
        "src/service/admission_notice_lite_personalization.py",
    }
    assert not (
        PROJECT_ROOT / "src/service/admission_notice_lite_personalization.py"
    ).exists()
    assert (
        PROJECT_ROOT / "src/service/admission_notice_lite_chat_context.py"
    ).is_file()


def test_projection_rejects_unknown_shared_top_level_code(
    current_sources: dict[str, bytes],
    historical_sources: dict[str, bytes],
) -> None:
    mutated = dict(current_sources)
    mutated["src/service/admission_notice_lite_ocr.py"] += (
        b"\nUNREVIEWED_SHARED_BEHAVIOR = object()\n"
    )
    _assert_invalid(mutated, historical_sources)
