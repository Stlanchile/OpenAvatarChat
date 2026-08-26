from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest_asyncio

from certificate_capture.contracts.admission_notice_release import (
    SanitizedAdmissionContextV1,
)
from certificate_capture.release.service import (
    AdmissionNoticeSafeReleaseServiceV1,
)
from chat_engine.security.dispatch import SecurityEnvelopeReferenceV1
from chat_engine.security.envelope import SecurityEnvelopeV1
from chat_engine.security.work_fence import RegisteredWorkV1
from tests.chat_engine.milestone_6b.conftest import (
    Milestone6BHarnessV1,
    standard_admission_spans_v1,
)


@dataclass
class Milestone7HarnessV1:
    extraction: Milestone6BHarnessV1 = field(default_factory=Milestone6BHarnessV1)

    def __post_init__(self) -> None:
        protocol = self.extraction.protocol
        coordinator = protocol.coordinator
        release_authority = (
            protocol.security_authority._issue_admission_notice_release_authority_v1(
                protocol.security_registrar
            )
        )
        assert release_authority is not None
        self.callback_gate = asyncio.Event()
        self.callback_gate.set()
        self.callback_started = asyncio.Event()
        self.callback_finished = asyncio.Event()
        self.callback_invocations = 0
        self.released_contexts: list[SanitizedAdmissionContextV1] = []
        self.release_envelopes: list[SecurityEnvelopeReferenceV1] = []
        self.release_envelope_snapshots: list[SecurityEnvelopeV1] = []
        self.registered_work: list[RegisteredWorkV1] = []
        self.second_consumptions: list[object] = []
        self.store_clear_at_callback: list[bool] = []

        async def personalize(continuation, registered_work) -> None:
            self.callback_invocations += 1
            self.registered_work.append(registered_work)
            self.store_clear_at_callback.append(
                coordinator._private_evidence_store_v1.is_capture_clear_v1()
            )
            first = continuation._consume_for_core_v1(
                expected_successor_epoch=(registered_work.fence.session_epoch)
            )
            second = continuation._consume_for_core_v1(
                expected_successor_epoch=(registered_work.fence.session_epoch)
            )
            self.second_consumptions.append(second)
            if first is not None:
                context, envelope_ref = first
                self.released_contexts.append(context)
                self.release_envelopes.append(envelope_ref)
                envelope = protocol.security_authority.envelope_v1(envelope_ref)
                assert envelope is not None
                self.release_envelope_snapshots.append(envelope)
            self.callback_started.set()
            try:
                await self.callback_gate.wait()
            finally:
                self.callback_finished.set()

        coordinator._post_capture_personalization_v1 = personalize
        coordinator._admission_notice_release_service_v1 = (
            AdmissionNoticeSafeReleaseServiceV1._create_for_coordinator_v1(
                security_authority=protocol.security_authority,
                release_authority=release_authority,
                private_authority=(protocol.private_evidence_authority),
                store=coordinator._private_evidence_store_v1,
                read_access=coordinator._private_store_read_access_v1,
                work_controller=protocol.controller,
                capture_is_live_v1=(
                    coordinator._private_admission_extraction_operation_is_live_v1
                ),
                fatal_failure_v1=(coordinator._fail_protocol_runtime_v1),
                monotonic_clock_v1=protocol.clock.monotonic,
            )
        )

    @property
    def protocol(self):
        return self.extraction.protocol

    async def prepare_standard(self, **field_values):
        await self.extraction.install()
        grant, _ = await self.extraction.begin_with_frames(1)
        receipts = await self.extraction.process_pages(
            grant,
            {
                1: standard_admission_spans_v1(
                    **field_values,
                )
            },
        )
        extraction_receipt = await self.extraction.extract(
            grant,
            receipts,
        )
        return grant, receipts, extraction_receipt

    async def end_and_wait(self, grant) -> None:
        await self.protocol.coordinator.end_capture_v1(grant.capture_epoch)
        task = self.protocol.coordinator._admission_personalization_task_v1
        if task is not None:
            await asyncio.shield(task)

    async def close(self) -> None:
        self.callback_gate.set()
        await self.extraction.close()


@pytest_asyncio.fixture
async def milestone_7_harness_factory():
    created: list[Milestone7HarnessV1] = []

    def create() -> Milestone7HarnessV1:
        harness = Milestone7HarnessV1()
        created.append(harness)
        return harness

    yield create

    for harness in created:
        await harness.close()


__all__ = ["Milestone7HarnessV1"]
