from __future__ import annotations

import json
import time

from conftest import (
    RecordingHandlerV1,
    make_text_chat_data,
    prepare_handler,
)

from chat_engine.core.stream_manager import StreamManager
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.internal.handler_definition_data import (
    HandlerDataInfo,
)


def _drain_handler_queues(session) -> None:
    for record in session.handlers.values():
        queue = record.env.input_queue
        while not queue.empty():
            queue.get_nowait()


def test_public_dispatch_and_isolation_performance_smoke(
    secure_session,
    legacy_session,
):
    secure, harness = secure_session
    legacy = legacy_session
    for index in range(4):
        prepare_handler(
            secure,
            f"secure-sink-{index}",
            RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,)),
        )
        prepare_handler(
            legacy,
            f"legacy-sink-{index}",
            RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,)),
        )
    secure.sort_sinks()
    legacy.sort_sinks()

    data_info = HandlerDataInfo(type=ChatDataType.HUMAN_TEXT)
    secure_one = harness.create_public_streamer(
        data_info=data_info,
        data_sinks={
            ChatDataType.HUMAN_TEXT: secure.data_sinks[ChatDataType.HUMAN_TEXT][:1]
        },
        producer_name="secure-perf-one",
    )
    secure_four = harness.create_public_streamer(
        data_info=data_info,
        data_sinks=secure.data_sinks,
        producer_name="secure-perf-four",
    )
    legacy_four = legacy.stream_manager.create_streamer(
        data_info=data_info,
        data_sinks=legacy.data_sinks,
        producer_name="legacy-perf-four",
    )
    packet = make_text_chat_data(
        "public-performance-smoke",
        metadata={"nested": {"value": "public"}},
    )
    iterations = 300
    debug_was_enabled = StreamManager.is_debug_logging_enabled()
    StreamManager.enable_debug_logging(False)

    try:
        start = time.perf_counter()
        for _ in range(iterations):
            secure_one.stream_data(
                packet,
                finish_stream=True,
            )
        secure_one_seconds = time.perf_counter() - start
        _drain_handler_queues(secure)

        start = time.perf_counter()
        for _ in range(iterations):
            secure_four.stream_data(
                packet,
                finish_stream=True,
            )
        secure_four_seconds = time.perf_counter() - start
        _drain_handler_queues(secure)

        start = time.perf_counter()
        for _ in range(iterations):
            legacy_four.stream_data(packet, finish_stream=True)
        legacy_four_seconds = time.perf_counter() - start
        _drain_handler_queues(legacy)
    finally:
        StreamManager.enable_debug_logging(debug_was_enabled)

    observations = {
        "iterations": iterations,
        "secure_public_dispatch_per_second_four_sinks": round(
            iterations / secure_four_seconds,
            2,
        ),
        "secure_seconds_one_sink": round(secure_one_seconds, 6),
        "secure_seconds_four_sinks": round(secure_four_seconds, 6),
        "legacy_seconds_four_sinks": round(legacy_four_seconds, 6),
        "incremental_isolation_microseconds_per_extra_sink": round(
            max(0.0, secure_four_seconds - secure_one_seconds)
            * 1_000_000
            / (iterations * 3),
            2,
        ),
    }
    print("SECURITY_DISPATCH_PERF_SMOKE " + json.dumps(observations))

    assert secure_one_seconds > 0
    assert secure_four_seconds > 0
    assert legacy_four_seconds > 0
