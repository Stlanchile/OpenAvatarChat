from __future__ import annotations

import resource
import time

import pytest

from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1


@pytest.mark.asyncio
async def test_non_normative_private_pipeline_performance_smoke(
    milestone_6a_harness_factory,
):
    """Measure decrypt/IPC seam/validation/encrypt with a synthetic sidecar.

    This is not an OCR-backend qualification result.
    """

    harness = milestone_6a_harness_factory()
    await harness.install()
    grant = await harness.protocol.begin()
    for frame_seq in range(1, 7):
        await harness.protocol.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(
                width=1920,
                height=1080,
                color=(20 * frame_seq, 30, 40),
                quality=90,
            ),
        )

    started_cpu = time.process_time()
    started = time.perf_counter()
    one = await harness.process(grant, 1)
    one_seconds = time.perf_counter() - started

    started = time.perf_counter()
    two = await harness.process(grant, 2, 3)
    two_seconds = time.perf_counter() - started

    started = time.perf_counter()
    three = await harness.process(grant, 4, 5, 6)
    three_seconds = time.perf_counter() - started
    cpu_seconds = time.process_time() - started_cpu
    maximum_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    assert len(one) == 1
    assert len(two) == 2
    assert len(three) == 3
    assert one_seconds < 2.0
    assert two_seconds < 2.0
    assert three_seconds < 2.0
    assert maximum_rss_kib > 0
    print(
        {
            "backend": "synthetic-test-sidecar",
            "cpu_seconds": cpu_seconds,
            "maximum_rss_kib": maximum_rss_kib,
            "one_frame_seconds": one_seconds,
            "three_frame_seconds": three_seconds,
            "two_frame_seconds": two_seconds,
        }
    )
