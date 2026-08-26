from __future__ import annotations

import json
import time

import pytest

from certificate_capture.contracts.admission_notice_release import (
    SanitizedAdmissionContextV1,
)
from certificate_capture.release.service import (
    AdmissionNoticeSafeReleaseServiceV1,
)
from handlers.agent.prompt.prompt_compiler import (
    PromptCompiler,
    PromptInput,
)
from handlers.agent.turn_context import ChatAgentTurnContextV1


@pytest.mark.asyncio
async def test_m7_non_normative_local_performance_smoke(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    coordinator._admission_notice_release_service_v1 = None
    total_started = time.perf_counter()
    grant, receipts, extraction_receipt = await harness.prepare_standard()
    coordinator._admission_notice_release_service_v1 = release_service
    extraction = harness.extraction.read_extraction(
        grant,
        extraction_receipt,
    )

    sanitize_started = time.perf_counter()
    for _ in range(1000):
        values = AdmissionNoticeSafeReleaseServiceV1._sanitize_candidate_values_v1(
            extraction,
            expected_capture_epoch=grant.capture_epoch,
        )
    sanitize_elapsed = time.perf_counter() - sanitize_started
    assert len(values) == 4

    parent = harness.extraction.register_parent(grant)
    try:
        release_service.stage_extraction_v1(
            capture_epoch=grant.capture_epoch,
            receipt=extraction_receipt,
            parent_work=parent,
        )
    finally:
        harness.protocol.controller.release_work_v1(parent.lease)
    prepare_started = time.perf_counter()
    release_service.prepare_for_end_v1(
        capture_epoch=grant.capture_epoch,
    )
    prepare_elapsed = time.perf_counter() - prepare_started

    candidate = release_service._candidate
    assert candidate is not None
    safe_context = dict(candidate.values)

    turn_context = ChatAgentTurnContextV1(
        sanitized_admission_notice=SanitizedAdmissionContextV1(
            institution_name="湖北交通职业技术学院",
            name=safe_context.get("name"),
            source_province=safe_context.get("source_province"),
            college=safe_context.get("college"),
            major=safe_context.get("major"),
        )
    )
    compiler = PromptCompiler()
    prompt_started = time.perf_counter()
    for _ in range(1000):
        compiled = compiler.compile(
            PromptInput(
                trigger_type=("admission_notice_personalization"),
                turn_context_v1=turn_context,
            )
        )
    prompt_elapsed = time.perf_counter() - prompt_started
    assert compiled.message_count >= 2

    commit_started = time.perf_counter()
    await harness.end_and_wait(grant)
    commit_elapsed = time.perf_counter() - commit_started
    total_elapsed = time.perf_counter() - total_started
    del receipts

    measurements = {
        "complete_synthetic_release_to_fake_generation_ms": (total_elapsed * 1000.0),
        "fake_chatagent_context_1000_ms": (prompt_elapsed * 1000.0),
        "post_cleanup_commit_and_dispatch_ms": (commit_elapsed * 1000.0),
        "prepare_release_candidate_ms": (prepare_elapsed * 1000.0),
        "sanitize_four_fields_1000_ms": (sanitize_elapsed * 1000.0),
    }
    print("M7_PERF_NON_NORMATIVE " + json.dumps(measurements, sort_keys=True))

    assert sanitize_elapsed < 1.0
    assert prompt_elapsed < 1.0
    assert prepare_elapsed < 1.0
    assert commit_elapsed < 2.0
