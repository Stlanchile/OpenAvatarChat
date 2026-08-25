from __future__ import annotations

from dataclasses import dataclass, field

import pytest_asyncio

from certificate_capture.contracts.inference import (
    AcceleratorPolicyV1,
    CpuRuntimeIdentityV1,
    ExecutionIdentityV1,
    HostProvenanceV1,
    InferenceIdentityV1,
    ModelConversionIdentityV1,
    ModelIdentityV1,
    PipelineIdentityV1,
    ProcessingIdentityV1,
    ServiceIdentityV1,
    SoftwareIdentityV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from tests.chat_engine.milestone_4b.conftest import (
    CaptureProtocolHarnessV1,
    synthetic_jpeg_v1,
)

SYNTHETIC_SHA256_V1 = "11" * 32
SYNTHETIC_SHA256_B_V1 = "22" * 32
SYNTHETIC_SHA256_C_V1 = "33" * 32


@dataclass
class Milestone5AHarnessV1:
    protocol: CaptureProtocolHarnessV1 = field(
        default_factory=CaptureProtocolHarnessV1
    )

    async def begin(self, **kwargs):
        return await self.protocol.begin(**kwargs)

    async def upload(self, grant, *, frame_seq: int, encoded_frame: bytearray):
        return await self.protocol.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=encoded_frame,
        )

    def register_read(self, capture_epoch):
        return self.protocol.controller.register_work_v1(
            WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
            self.protocol.clock.monotonic() + 30.0,
            _admission_guard_v1=(
                lambda: self.protocol.coordinator
                ._private_store_operation_is_live_v1(capture_epoch)
            ),
        )

    def register_auxiliary(self, capture_epoch):
        return self.protocol.controller.register_work_v1(
            WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY,
            self.protocol.clock.monotonic() + 30.0,
            _admission_guard_v1=(
                lambda: self.protocol.coordinator
                ._private_store_operation_is_live_v1(capture_epoch)
            ),
        )

    def read_frame(self, grant, frame_seq: int, work=None) -> bytes:
        coordinator = self.protocol.coordinator
        registered = work or self.register_read(grant.capture_epoch)
        release = work is None
        try:
            record = coordinator._frame_records_v1[frame_seq]
            return coordinator._read_private_frame_for_test_v1(
                capture_epoch=grant.capture_epoch,
                frame_id=record.evidence_frame.frame_id,
                registered_work=registered,
                access=coordinator._private_store_read_access_v1,
            )
        finally:
            if release:
                self.protocol.controller.release_work_v1(
                    registered.lease
                )

    async def close(self) -> None:
        await self.protocol.close()


@pytest_asyncio.fixture
async def milestone_5a_harness_factory():
    created: list[Milestone5AHarnessV1] = []

    def create(**kwargs) -> Milestone5AHarnessV1:
        harness = Milestone5AHarnessV1(
            protocol=CaptureProtocolHarnessV1(**kwargs)
        )
        created.append(harness)
        return harness

    yield create

    for harness in created:
        await harness.close()


def synthetic_inference_identity_v1() -> InferenceIdentityV1:
    """Synthetic model-only identity; no production OCR runtime is created."""

    software = SoftwareIdentityV1(
        python_abi="cp311",
        paddleocr_version="synthetic-3.7.0",
        paddlepaddle_version="synthetic-3.2.0",
        paddlepaddle_distribution="paddlepaddle",
        paddlex_version="synthetic-3.7.0",
        cpu_runtime_packages=(
            "synthetic-openmp==1",
            "synthetic-blas==1",
        ),
        locked_wheel_hashes=(
            f"synthetic-paddle:{SYNTHETIC_SHA256_V1}",
            f"synthetic-ocr:{SYNTHETIC_SHA256_B_V1}",
        ),
    )
    cpu_runtime = CpuRuntimeIdentityV1(
        cpu_qualification_class_sha256=SYNTHETIC_SHA256_V1,
        cpu_architecture="synthetic-x86_64",
        cpu_isa_policy="synthetic-baseline",
        inference_thread_count=2,
        inter_op_thread_count=1,
        intra_op_thread_count=2,
        process_thread_cap=4,
        thread_affinity_policy="synthetic-fixed",
        thread_environment_sha256=SYNTHETIC_SHA256_B_V1,
        runtime_library_versions=(
            "synthetic-libgomp==1",
            "synthetic-openblas==1",
        ),
        runtime_configuration_sha256=SYNTHETIC_SHA256_C_V1,
    )
    execution = ExecutionIdentityV1(
        device="cpu",
        automatic_device_selection=False,
        engine="synthetic-paddle-inference",
        engine_version="synthetic-1",
        engine_configuration_sha256=SYNTHETIC_SHA256_V1,
        execution_backend="synthetic-cpu-backend",
        execution_backend_version="synthetic-1",
        execution_backend_configuration_sha256=(
            SYNTHETIC_SHA256_B_V1
        ),
        automatic_backend_selection=False,
        automatic_backend_fallback=False,
        precision="fp32",
        deterministic_algorithms=True,
        hpi_enabled=False,
        hpi_auto_config=False,
        batch_policy="single-capture",
        cpu_runtime=cpu_runtime,
        accelerator_policy=AcceleratorPolicyV1(
            gpu_allowed=False,
            cuda_initialization_allowed=False,
            cuda_allocation_allowed=False,
        ),
    )
    models = (
        ModelIdentityV1(
            role="recognizer",
            model_name="synthetic-recognizer",
            source_artifact_sha256=SYNTHETIC_SHA256_V1,
            executable_artifact_sha256=SYNTHETIC_SHA256_B_V1,
            configuration_sha256=SYNTHETIC_SHA256_C_V1,
        ),
        ModelIdentityV1(
            role="detector",
            model_name="synthetic-detector",
            source_artifact_sha256=SYNTHETIC_SHA256_B_V1,
            executable_artifact_sha256=SYNTHETIC_SHA256_C_V1,
            configuration_sha256=SYNTHETIC_SHA256_V1,
        ),
    )
    return InferenceIdentityV1(
        service=ServiceIdentityV1(
            protocol_version="synthetic-v1",
            source_revision="synthetic-revision",
            container_image_digest=(
                f"sha256:{SYNTHETIC_SHA256_V1}"
            ),
        ),
        software=software,
        execution=execution,
        host_provenance=HostProvenanceV1(
            os_release="synthetic-os",
            kernel_version="synthetic-kernel",
            cpu_vendor="synthetic-vendor",
            cpu_model="synthetic-model",
            cpu_features_sha256=SYNTHETIC_SHA256_C_V1,
            microcode_version="synthetic-microcode",
            logical_cpu_count=8,
        ),
        models=models,
        model_conversion=ModelConversionIdentityV1(
            enabled=False,
            tool=None,
            tool_version=None,
            configuration_sha256=None,
        ),
        pipeline=PipelineIdentityV1(
            canonical_configuration_sha256=SYNTHETIC_SHA256_V1,
            character_dictionary_sha256=SYNTHETIC_SHA256_B_V1,
        ),
        preprocessing=ProcessingIdentityV1(
            implementation_version="synthetic-pre-v1",
            source_sha256=SYNTHETIC_SHA256_B_V1,
            configuration_sha256=SYNTHETIC_SHA256_C_V1,
        ),
        postprocessing=ProcessingIdentityV1(
            implementation_version="synthetic-post-v1",
            source_sha256=SYNTHETIC_SHA256_C_V1,
            configuration_sha256=SYNTHETIC_SHA256_V1,
        ),
    )


__all__ = [
    "SYNTHETIC_SHA256_B_V1",
    "SYNTHETIC_SHA256_C_V1",
    "SYNTHETIC_SHA256_V1",
    "Milestone5AHarnessV1",
    "synthetic_inference_identity_v1",
    "synthetic_jpeg_v1",
]
