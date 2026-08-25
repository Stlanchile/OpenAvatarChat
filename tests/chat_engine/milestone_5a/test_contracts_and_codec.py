from __future__ import annotations

import hashlib
from dataclasses import fields, replace

import pytest

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.contracts.inference import (
    AcceleratorPolicyV1,
    CalibrationDependencyV1,
    ExecutionIdentityV1,
    SoftwareIdentityV1,
)
from certificate_capture.private_codec import (
    PRIVATE_CODEC_OVERHEAD_BYTES_V1,
    PrivateCodecErrorV1,
    PrivateEvidenceRecordTypeV1,
    decode_private_record_v1,
    encode_private_record_v1,
)
from tests.chat_engine.milestone_5a.conftest import (
    SYNTHETIC_SHA256_B_V1,
    synthetic_inference_identity_v1,
)


def test_private_codec_round_trips_exact_jpeg_without_transcoding():
    jpeg = bytearray(b"\xff\xd8synthetic-private-jpeg\xff\xd9")

    encoded = encode_private_record_v1(
        PrivateEvidenceRecordTypeV1.FRAME_JPEG,
        jpeg,
    )
    decoded = decode_private_record_v1(
        PrivateEvidenceRecordTypeV1.FRAME_JPEG,
        encoded,
    )

    assert decoded == bytes(jpeg)
    assert len(encoded) == len(jpeg) + PRIVATE_CODEC_OVERHEAD_BYTES_V1
    assert encoded != bytes(jpeg)


def test_auxiliary_codec_requires_bounded_canonical_unique_key_json():
    payload = canonical_json_bytes_v1(
        {
            "schema_version": "synthetic-private-record.v1",
            "value": 1,
        }
    )
    encoded = encode_private_record_v1(
        PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
        payload,
    )

    assert (
        decode_private_record_v1(
            PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
            encoded,
        )
        == payload
    )
    with pytest.raises(PrivateCodecErrorV1):
        encode_private_record_v1(
            PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
            b'{"value":1, "schema_version":"synthetic-private-record.v1"}',
        )
    with pytest.raises(PrivateCodecErrorV1):
        encode_private_record_v1(
            PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
            b'{"value":1,"value":2}',
        )
    with pytest.raises(PrivateCodecErrorV1):
        decode_private_record_v1(
            PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
            encoded[:-1],
        )
    with pytest.raises(PrivateCodecErrorV1):
        decode_private_record_v1(
            PrivateEvidenceRecordTypeV1.FRAME_JPEG,
            encoded,
        )


def test_inference_identity_is_typed_deterministic_and_set_arrays_are_sorted():
    identity = synthetic_inference_identity_v1()
    reordered = replace(
        identity,
        software=replace(
            identity.software,
            cpu_runtime_packages=tuple(
                reversed(identity.software.cpu_runtime_packages)
            ),
            locked_wheel_hashes=tuple(
                reversed(identity.software.locked_wheel_hashes)
            ),
        ),
        models=tuple(reversed(identity.models)),
        execution=replace(
            identity.execution,
            cpu_runtime=replace(
                identity.execution.cpu_runtime,
                runtime_library_versions=tuple(
                    reversed(
                        identity.execution.cpu_runtime
                        .runtime_library_versions
                    )
                ),
            ),
        ),
    )

    assert identity.canonical_json_v1() == reordered.canonical_json_v1()
    assert (
        identity.inference_identity_sha256
        == reordered.inference_identity_sha256
    )
    assert identity.inference_identity_sha256 == hashlib.sha256(
        identity.canonical_json_v1()
    ).hexdigest()
    assert {field.name for field in fields(identity)} == {
        "service",
        "software",
        "execution",
        "host_provenance",
        "models",
        "model_conversion",
        "pipeline",
        "preprocessing",
        "postprocessing",
        "schema_version",
    }


def test_calibration_dependency_is_exact_and_excludes_provenance_only_fields():
    identity = synthetic_inference_identity_v1()
    dependency = identity.calibration_dependency_v1()
    provenance_changed = replace(
        identity,
        service=replace(
            identity.service,
            source_revision="synthetic-other-revision",
        ),
        host_provenance=replace(
            identity.host_provenance,
            kernel_version="synthetic-other-kernel",
        ),
    )
    accuracy_changed = replace(
        identity,
        execution=replace(
            identity.execution,
            engine_configuration_sha256=SYNTHETIC_SHA256_B_V1,
        ),
    )

    assert isinstance(dependency, CalibrationDependencyV1)
    assert (
        provenance_changed.calibration_dependency_v1() == dependency
    )
    assert (
        provenance_changed.calibration_dependency_v1()
        .calibration_dependency_sha256
        == dependency.calibration_dependency_sha256
    )
    assert (
        accuracy_changed.calibration_dependency_v1() != dependency
    )
    assert (
        accuracy_changed.calibration_dependency_v1()
        .calibration_dependency_sha256
        != dependency.calibration_dependency_sha256
    )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("device", "gpu"),
        ("automatic_device_selection", True),
        ("automatic_backend_selection", True),
        ("automatic_backend_fallback", True),
        ("hpi_auto_config", True),
        ("engine", "auto"),
        ("engine", "cuda-engine"),
        ("execution_backend", "default"),
        ("execution_backend", "tensorrt"),
    ),
)
def test_cpu_only_execution_rejects_gpu_and_automatic_paths(
    field_name,
    invalid_value,
):
    execution = synthetic_inference_identity_v1().execution

    with pytest.raises(ValueError):
        replace(execution, **{field_name: invalid_value})


@pytest.mark.parametrize(
    "invalid_policy",
    (
        {
            "gpu_allowed": True,
            "cuda_initialization_allowed": False,
            "cuda_allocation_allowed": False,
        },
        {
            "gpu_allowed": False,
            "cuda_initialization_allowed": True,
            "cuda_allocation_allowed": False,
        },
        {
            "gpu_allowed": False,
            "cuda_initialization_allowed": False,
            "cuda_allocation_allowed": True,
        },
    ),
)
def test_cpu_only_accelerator_policy_rejects_every_gpu_cuda_permission(
    invalid_policy,
):
    with pytest.raises(ValueError):
        AcceleratorPolicyV1(**invalid_policy)


def test_cpu_distribution_and_typed_nested_contracts_are_strict():
    identity = synthetic_inference_identity_v1()

    with pytest.raises(ValueError):
        replace(
            identity.software,
            paddlepaddle_distribution="paddlepaddle-gpu",
        )
    with pytest.raises(ValueError):
        replace(
            identity.software,
            cpu_runtime_packages=("synthetic-cuda-runtime==1",),
        )
    with pytest.raises(ValueError):
        replace(
            identity.execution.cpu_runtime,
            runtime_library_versions=("synthetic-gpu-runtime==1",),
        )
    with pytest.raises(TypeError):
        replace(identity, execution={"device": "cpu"})
    with pytest.raises(TypeError):
        ExecutionIdentityV1(
            **{
                **{
                    field.name: getattr(identity.execution, field.name)
                    for field in fields(identity.execution)
                },
                "cpu_runtime": {},
            }
        )
    with pytest.raises(TypeError):
        SoftwareIdentityV1(
            python_abi="cp311",
            paddleocr_version="synthetic",
            paddlepaddle_version="synthetic",
            paddlepaddle_distribution="paddlepaddle",
            paddlex_version="synthetic",
            cpu_runtime_packages=["mutable"],
            locked_wheel_hashes=(),
        )
