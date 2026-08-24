"""Constructor-only post-seal processor contract for Milestone 4B tests."""

from __future__ import annotations

from typing import Protocol

from certificate_capture.protocol import MockProcessingInputV1


class CaptureProcessorV1(Protocol):
    """No production implementation exists in Milestone 4B."""

    async def process_capture_v1(
        self,
        processing_input: MockProcessingInputV1,
    ) -> None:
        """Exercise lifecycle timing without receiving image or certificate data."""


__all__ = ["CaptureProcessorV1"]
