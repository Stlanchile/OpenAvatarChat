from __future__ import annotations

import asyncio
import hashlib
import importlib
import sys
import time
import uuid
from dataclasses import fields
from types import ModuleType

import pytest
from loguru import logger

from certificate_capture.frame_ingress import validate_private_jpeg_v1
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.state import CaptureStateV1
from chat_engine.contexts.session_history import SessionHistory
from chat_engine.core.signal_manager import SignalManager
from chat_engine.core.stream_manager import StreamManager
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from handlers.agent.chat_agent_handler import ChatAgentHandler
from handlers.agent.memory.working_memory import WorkingMemory
from handlers.agent.perception.perception_handler import PerceptionHandler
from handlers.client.ws_client.ws_client_handler import WsClientHandler
from handlers.manager.handler_data_tool import HandlerDataTool
from service.rtc_service.rtc_stream import RtcStream
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1
from tests.chat_engine.milestone_4b.test_protocol_lifecycle import (
    ImmediateMockProcessorV1,
)

if "edge_tts" not in sys.modules:
    edge_tts_stub = ModuleType("edge_tts")
    edge_tts_stub.Communicate = object
    sys.modules["edge_tts"] = edge_tts_stub
HandlerTTS = importlib.import_module(
    "handlers.tts.edgetts.tts_handler_edgetts"
).HandlerTTS


def _jpeg_with_comment_canary_v1(canary: bytes) -> bytearray:
    encoded = synthetic_jpeg_v1()
    if len(canary) > 65_533:
        raise ValueError
    segment = (
        b"\xff\xfe"
        + (len(canary) + 2).to_bytes(2, "big")
        + canary
    )
    return encoded[:2] + segment + encoded[2:]


@pytest.mark.asyncio
async def test_private_frame_never_calls_any_instrumented_generic_seam(
    capture_protocol_harness_factory,
    monkeypatch,
):
    calls: list[str] = []

    def deny(name):
        def denied(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"private frame reached {name}")

        return denied

    instrumented = (
        (ChatData, "__init__", "ChatData"),
        (StreamManager, "create_streamer", "StreamManager"),
        (SignalManager, "enqueue_signal_v1", "SignalManager"),
        (PerceptionHandler, "handle", "Perception"),
        (ChatAgentHandler, "handle", "ChatAgent"),
        (HandlerDataTool, "handle", "HandlerDataTool"),
        (SessionHistory, "add_event", "SessionHistory"),
        (SessionHistory, "accumulate_stream_data", "SessionHistoryAccumulator"),
        (WorkingMemory, "add_turn", "WorkingMemory"),
        (HandlerTTS, "handle", "generic TTS"),
        (WsClientHandler, "handle", "WS generic output"),
        (RtcStream, "emit", "RTC audio output"),
        (RtcStream, "video_emit", "RTC video output"),
    )
    for owner, method, name in instrumented:
        monkeypatch.setattr(owner, method, deny(name))

    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1(color=(17, 34, 51))
    result = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )

    assert result.accepted_frame_count == 1
    assert calls == []


@pytest.mark.asyncio
async def test_payload_metadata_and_digest_never_enter_logs(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    canary = b"M4B_PRIVATE_JPEG_CANARY_7f2b1e"
    encoded = _jpeg_with_comment_canary_v1(canary)
    digest_hex = hashlib.sha256(encoded).hexdigest()
    captured_logs: list[str] = []
    sink = logger.add(lambda message: captured_logs.append(str(message)))
    try:
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=encoded,
        )
    finally:
        logger.remove(sink)

    joined = "\n".join(captured_logs)
    assert canary.decode("ascii") not in joined
    assert digest_hex not in joined
    assert grant.capture_capability not in joined
    assert harness.owner_subject not in joined


@pytest.mark.asyncio
async def test_retained_frame_record_is_bounded_metadata_only(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )
    record = harness.coordinator._frame_records_v1[1]

    assert {field.name for field in fields(record)} == {
        "frame_seq",
        "encoded_size",
        "decoded_width",
        "decoded_height",
        "sha256_digest",
        "accepted_at_monotonic",
        "result",
    }
    assert all(
        "image" not in field.name
        and "pixel" not in field.name
        and "jpeg" not in field.name
        for field in fields(record)
    )
    assert len(record.sha256_digest) == 32
    assert not any(
        isinstance(getattr(record, field.name), bytearray)
        for field in fields(record)
    )


@pytest.mark.asyncio
async def test_third_concurrent_upload_is_rejected_by_fixed_bound(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    permits = []
    for frame_seq in (1, 2):
        permits.append(
            await harness.coordinator.admit_frame_upload_v1(
                capture_id=grant.capture_epoch.capture_id,
                frame_seq=frame_seq,
                capture_capability=grant.capture_capability,
                session_id=harness.session_id,
                owner_issuer=harness.owner_issuer,
                owner_subject=harness.owner_subject,
            )
        )
    try:
        with pytest.raises(CaptureProtocolErrorV1) as busy:
            await harness.coordinator.admit_frame_upload_v1(
                capture_id=grant.capture_epoch.capture_id,
                frame_seq=3,
                capture_capability=grant.capture_capability,
                session_id=harness.session_id,
                owner_issuer=harness.owner_issuer,
                owner_subject=harness.owner_subject,
            )
        assert busy.value.reason is CaptureProtocolReasonV1.UPLOAD_BUSY
    finally:
        for permit in permits:
            harness.coordinator.release_frame_upload_permit_v1(permit)


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_kind", ("failure", "shutdown"))
async def test_failure_and_shutdown_delete_all_capture_private_state(
    capture_protocol_harness_factory,
    cleanup_kind,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )

    if cleanup_kind == "failure":
        harness.coordinator._fail_closed_for_test_v1()
        expected = CaptureStateV1.FAILED_CLOSED
    else:
        await harness.coordinator.shutdown_async_v1()
        expected = CaptureStateV1.FAILED_CLOSED
    await asyncio.sleep(0)

    assert harness.coordinator.snapshot_v1().state is expected
    assert harness.coordinator._private_capture_is_clear_locked_v1()
    assert harness.coordinator._active_capture_capability_v1 is None
    assert harness.coordinator._frame_records_v1 == {}
    assert harness.coordinator._unique_frame_digests_v1 == set()
    assert harness.coordinator._inactivity_task_v1 is None
    assert harness.coordinator._processor_task_v1 is None


@pytest.mark.asyncio
async def test_non_normative_local_route_operation_smoke(
    capture_protocol_harness_factory,
):
    processor = ImmediateMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    timings: dict[str, float] = {}

    started = time.perf_counter()
    grant = await harness.begin()
    timings["begin_to_armed"] = time.perf_counter() - started

    frames = [
        synthetic_jpeg_v1(
            width=1920,
            height=1080,
            color=(index * 20, index * 20 + 1, index * 20 + 2),
            quality=80,
        )
        for index in range(8)
    ]
    started = time.perf_counter()
    validated = validate_private_jpeg_v1(frames[0])
    timings["validate_1080p"] = time.perf_counter() - started
    assert validated.decoded_width == 1920

    started = time.perf_counter()
    for frame_seq, encoded in enumerate(frames, start=1):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=encoded,
        )
    timings["eight_uploads"] = time.perf_counter() - started

    started = time.perf_counter()
    status = await harness.coordinator.capture_public_status_v1(
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    timings["status"] = time.perf_counter() - started
    assert status.accepted_frame_count == 8

    started = time.perf_counter()
    await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    timings["mock_seal"] = time.perf_counter() - started

    for _ in range(100):
        if harness.coordinator.snapshot_v1().state is CaptureStateV1.READY:
            break
        await asyncio.sleep(0.001)
    started = time.perf_counter()
    await harness.coordinator.end_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=3,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    timings["end"] = time.perf_counter() - started

    assert all(duration >= 0.0 for duration in timings.values())
    assert all(duration < 10.0 for duration in timings.values())
