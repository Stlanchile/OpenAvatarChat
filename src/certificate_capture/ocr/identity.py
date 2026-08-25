"""Strict parsers for sidecar-reported M5A inference identity."""

from __future__ import annotations

from typing import Any

from certificate_capture.contracts.common import canonical_json_bytes_v1
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
from certificate_capture.contracts.ocr import (
    decode_strict_ocr_json_object_v1,
)

MAX_INFERENCE_IDENTITY_JSON_BYTES_V1 = 48 * 1024


def _exact_object_v1(
    value: object,
    fields: frozenset[str],
    name: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{name} has an invalid schema")
    return value


def _text_tuple_v1(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a text array")
    return tuple(value)


def processing_identity_from_object_v1(
    value: object,
    *,
    name: str,
) -> ProcessingIdentityV1:
    item = _exact_object_v1(
        value,
        frozenset(
            {
                "configuration_sha256",
                "implementation_version",
                "source_sha256",
            }
        ),
        name,
    )
    return ProcessingIdentityV1(
        implementation_version=item["implementation_version"],
        source_sha256=item["source_sha256"],
        configuration_sha256=item["configuration_sha256"],
    )


def inference_identity_from_object_v1(value: object) -> InferenceIdentityV1:
    root = _exact_object_v1(
        value,
        frozenset(
            {
                "execution",
                "host_provenance",
                "model_conversion",
                "models",
                "pipeline",
                "postprocessing",
                "preprocessing",
                "schema_version",
                "service",
                "software",
            }
        ),
        "inference identity",
    )
    service_value = _exact_object_v1(
        root["service"],
        frozenset(
            {
                "container_image_digest",
                "protocol_version",
                "source_revision",
            }
        ),
        "service identity",
    )
    software_value = _exact_object_v1(
        root["software"],
        frozenset(
            {
                "cpu_runtime_packages",
                "locked_wheel_hashes",
                "paddleocr_version",
                "paddlepaddle_distribution",
                "paddlepaddle_version",
                "paddlex_version",
                "python_abi",
            }
        ),
        "software identity",
    )
    execution_value = _exact_object_v1(
        root["execution"],
        frozenset(
            {
                "accelerator_policy",
                "automatic_backend_fallback",
                "automatic_backend_selection",
                "automatic_device_selection",
                "batch_policy",
                "cpu_runtime",
                "deterministic_algorithms",
                "device",
                "engine",
                "engine_configuration_sha256",
                "engine_version",
                "execution_backend",
                "execution_backend_configuration_sha256",
                "execution_backend_version",
                "hpi_auto_config",
                "hpi_enabled",
                "precision",
            }
        ),
        "execution identity",
    )
    cpu_value = _exact_object_v1(
        execution_value["cpu_runtime"],
        frozenset(
            {
                "cpu_architecture",
                "cpu_isa_policy",
                "cpu_qualification_class_sha256",
                "inference_thread_count",
                "inter_op_thread_count",
                "intra_op_thread_count",
                "process_thread_cap",
                "runtime_configuration_sha256",
                "runtime_library_versions",
                "thread_affinity_policy",
                "thread_environment_sha256",
            }
        ),
        "CPU runtime identity",
    )
    accelerator_value = _exact_object_v1(
        execution_value["accelerator_policy"],
        frozenset(
            {
                "cuda_allocation_allowed",
                "cuda_initialization_allowed",
                "gpu_allowed",
            }
        ),
        "accelerator policy",
    )
    host_value = _exact_object_v1(
        root["host_provenance"],
        frozenset(
            {
                "cpu_features_sha256",
                "cpu_model",
                "cpu_vendor",
                "kernel_version",
                "logical_cpu_count",
                "microcode_version",
                "os_release",
            }
        ),
        "host provenance",
    )
    conversion_value = _exact_object_v1(
        root["model_conversion"],
        frozenset(
            {
                "configuration_sha256",
                "enabled",
                "tool",
                "tool_version",
            }
        ),
        "model conversion identity",
    )
    pipeline_value = _exact_object_v1(
        root["pipeline"],
        frozenset(
            {
                "canonical_configuration_sha256",
                "character_dictionary_sha256",
            }
        ),
        "pipeline identity",
    )
    models_value = root["models"]
    if not isinstance(models_value, list):
        raise TypeError("models must be an array")
    models: list[ModelIdentityV1] = []
    for value_item in models_value:
        item = _exact_object_v1(
            value_item,
            frozenset(
                {
                    "configuration_sha256",
                    "executable_artifact_sha256",
                    "model_name",
                    "role",
                    "source_artifact_sha256",
                }
            ),
            "model identity",
        )
        models.append(
            ModelIdentityV1(
                role=item["role"],
                model_name=item["model_name"],
                source_artifact_sha256=item["source_artifact_sha256"],
                executable_artifact_sha256=(item["executable_artifact_sha256"]),
                configuration_sha256=item["configuration_sha256"],
            )
        )
    return InferenceIdentityV1(
        schema_version=root["schema_version"],
        service=ServiceIdentityV1(
            protocol_version=service_value["protocol_version"],
            source_revision=service_value["source_revision"],
            container_image_digest=service_value["container_image_digest"],
        ),
        software=SoftwareIdentityV1(
            python_abi=software_value["python_abi"],
            paddleocr_version=software_value["paddleocr_version"],
            paddlepaddle_version=software_value["paddlepaddle_version"],
            paddlepaddle_distribution=(software_value["paddlepaddle_distribution"]),
            paddlex_version=software_value["paddlex_version"],
            cpu_runtime_packages=_text_tuple_v1(
                software_value["cpu_runtime_packages"],
                "cpu_runtime_packages",
            ),
            locked_wheel_hashes=_text_tuple_v1(
                software_value["locked_wheel_hashes"],
                "locked_wheel_hashes",
            ),
        ),
        execution=ExecutionIdentityV1(
            device=execution_value["device"],
            automatic_device_selection=(execution_value["automatic_device_selection"]),
            engine=execution_value["engine"],
            engine_version=execution_value["engine_version"],
            engine_configuration_sha256=(
                execution_value["engine_configuration_sha256"]
            ),
            execution_backend=execution_value["execution_backend"],
            execution_backend_version=(execution_value["execution_backend_version"]),
            execution_backend_configuration_sha256=(
                execution_value["execution_backend_configuration_sha256"]
            ),
            automatic_backend_selection=(
                execution_value["automatic_backend_selection"]
            ),
            automatic_backend_fallback=(execution_value["automatic_backend_fallback"]),
            precision=execution_value["precision"],
            deterministic_algorithms=(execution_value["deterministic_algorithms"]),
            hpi_enabled=execution_value["hpi_enabled"],
            hpi_auto_config=execution_value["hpi_auto_config"],
            batch_policy=execution_value["batch_policy"],
            cpu_runtime=CpuRuntimeIdentityV1(
                cpu_qualification_class_sha256=(
                    cpu_value["cpu_qualification_class_sha256"]
                ),
                cpu_architecture=cpu_value["cpu_architecture"],
                cpu_isa_policy=cpu_value["cpu_isa_policy"],
                inference_thread_count=cpu_value["inference_thread_count"],
                inter_op_thread_count=cpu_value["inter_op_thread_count"],
                intra_op_thread_count=cpu_value["intra_op_thread_count"],
                process_thread_cap=cpu_value["process_thread_cap"],
                thread_affinity_policy=(cpu_value["thread_affinity_policy"]),
                thread_environment_sha256=(cpu_value["thread_environment_sha256"]),
                runtime_library_versions=_text_tuple_v1(
                    cpu_value["runtime_library_versions"],
                    "runtime_library_versions",
                ),
                runtime_configuration_sha256=(
                    cpu_value["runtime_configuration_sha256"]
                ),
            ),
            accelerator_policy=AcceleratorPolicyV1(
                gpu_allowed=accelerator_value["gpu_allowed"],
                cuda_initialization_allowed=(
                    accelerator_value["cuda_initialization_allowed"]
                ),
                cuda_allocation_allowed=(accelerator_value["cuda_allocation_allowed"]),
            ),
        ),
        host_provenance=HostProvenanceV1(
            os_release=host_value["os_release"],
            kernel_version=host_value["kernel_version"],
            cpu_vendor=host_value["cpu_vendor"],
            cpu_model=host_value["cpu_model"],
            cpu_features_sha256=host_value["cpu_features_sha256"],
            microcode_version=host_value["microcode_version"],
            logical_cpu_count=host_value["logical_cpu_count"],
        ),
        models=tuple(models),
        model_conversion=ModelConversionIdentityV1(
            enabled=conversion_value["enabled"],
            tool=conversion_value["tool"],
            tool_version=conversion_value["tool_version"],
            configuration_sha256=conversion_value["configuration_sha256"],
        ),
        pipeline=PipelineIdentityV1(
            canonical_configuration_sha256=(
                pipeline_value["canonical_configuration_sha256"]
            ),
            character_dictionary_sha256=(pipeline_value["character_dictionary_sha256"]),
        ),
        preprocessing=processing_identity_from_object_v1(
            root["preprocessing"],
            name="preprocessing identity",
        ),
        postprocessing=processing_identity_from_object_v1(
            root["postprocessing"],
            name="postprocessing identity",
        ),
    )


def inference_identity_from_canonical_json_v1(
    payload: bytes,
) -> InferenceIdentityV1:
    decoded = decode_strict_ocr_json_object_v1(
        payload,
        maximum_bytes=MAX_INFERENCE_IDENTITY_JSON_BYTES_V1,
    )
    if canonical_json_bytes_v1(decoded) != payload:
        raise ValueError("inference identity must use canonical JSON")
    return inference_identity_from_object_v1(decoded)


__all__ = [
    "MAX_INFERENCE_IDENTITY_JSON_BYTES_V1",
    "inference_identity_from_canonical_json_v1",
    "inference_identity_from_object_v1",
    "processing_identity_from_object_v1",
]
