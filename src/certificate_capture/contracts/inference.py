"""Typed CPU-only inference and calibration provenance contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    require_sha256_hex_v1,
    require_text_v1,
    sorted_unique_text_v1,
)

INFERENCE_IDENTITY_SCHEMA_VERSION_V1 = "oac.inference-identity.v1"
CALIBRATION_DEPENDENCY_SCHEMA_VERSION_V1 = (
    "oac.calibration-dependency.v1"
)
_DISALLOWED_AUTOMATIC_NAME_V1 = {
    "auto",
    "automatic",
    "default",
    "none",
    "null",
    "unset",
}
_PROHIBITED_ACCELERATOR_NAME_PARTS_V1 = (
    "cuda",
    "cudnn",
    "gpu",
    "tensorrt",
)


def _bool_v1(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be boolean")
    return value


def _positive_int_v1(name: str, value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > 65_536
    ):
        raise ValueError(f"{name} must be a bounded positive integer")
    return value


def _concrete_name_v1(name: str, value: object) -> str:
    normalized = require_text_v1(name, value, maximum_utf8_bytes=128)
    folded = normalized.casefold()
    if folded in _DISALLOWED_AUTOMATIC_NAME_V1:
        raise ValueError(f"{name} must name one concrete implementation")
    if any(part in folded for part in _PROHIBITED_ACCELERATOR_NAME_PARTS_V1):
        raise ValueError(f"{name} must be a CPU-only implementation")
    return normalized


@dataclass(frozen=True, slots=True)
class ServiceIdentityV1:
    protocol_version: str
    source_revision: str
    container_image_digest: str

    def __post_init__(self) -> None:
        require_text_v1("protocol_version", self.protocol_version)
        require_text_v1("source_revision", self.source_revision)
        require_text_v1(
            "container_image_digest",
            self.container_image_digest,
        )

    def canonical_object_v1(self) -> dict[str, str]:
        return {
            "container_image_digest": self.container_image_digest,
            "protocol_version": self.protocol_version,
            "source_revision": self.source_revision,
        }


@dataclass(frozen=True, slots=True)
class SoftwareIdentityV1:
    python_abi: str
    paddleocr_version: str
    paddlepaddle_version: str
    paddlepaddle_distribution: str
    paddlex_version: str
    cpu_runtime_packages: tuple[str, ...]
    locked_wheel_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "python_abi",
            "paddleocr_version",
            "paddlepaddle_version",
            "paddlex_version",
        ):
            require_text_v1(name, getattr(self, name))
        if self.paddlepaddle_distribution != "paddlepaddle":
            raise ValueError(
                "V1 requires the CPU paddlepaddle distribution"
            )
        object.__setattr__(
            self,
            "cpu_runtime_packages",
            sorted_unique_text_v1(
                "cpu_runtime_packages",
                self.cpu_runtime_packages,
            ),
        )
        object.__setattr__(
            self,
            "locked_wheel_hashes",
            sorted_unique_text_v1(
                "locked_wheel_hashes",
                self.locked_wheel_hashes,
            ),
        )
        if any(
            prohibited in item.casefold()
            for item in (
                *self.cpu_runtime_packages,
                *self.locked_wheel_hashes,
            )
            for prohibited in _PROHIBITED_ACCELERATOR_NAME_PARTS_V1
        ):
            raise ValueError(
                "V1 software identity must contain no GPU/CUDA runtime"
            )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "cpu_runtime_packages": list(self.cpu_runtime_packages),
            "locked_wheel_hashes": list(self.locked_wheel_hashes),
            "paddleocr_version": self.paddleocr_version,
            "paddlepaddle_distribution": self.paddlepaddle_distribution,
            "paddlepaddle_version": self.paddlepaddle_version,
            "paddlex_version": self.paddlex_version,
            "python_abi": self.python_abi,
        }


@dataclass(frozen=True, slots=True)
class CpuRuntimeIdentityV1:
    cpu_qualification_class_sha256: str
    cpu_architecture: str
    cpu_isa_policy: str
    inference_thread_count: int
    inter_op_thread_count: int
    intra_op_thread_count: int
    process_thread_cap: int
    thread_affinity_policy: str
    thread_environment_sha256: str
    runtime_library_versions: tuple[str, ...]
    runtime_configuration_sha256: str

    def __post_init__(self) -> None:
        require_sha256_hex_v1(
            "cpu_qualification_class_sha256",
            self.cpu_qualification_class_sha256,
        )
        require_text_v1("cpu_architecture", self.cpu_architecture)
        require_text_v1("cpu_isa_policy", self.cpu_isa_policy)
        require_text_v1(
            "thread_affinity_policy",
            self.thread_affinity_policy,
        )
        require_sha256_hex_v1(
            "thread_environment_sha256",
            self.thread_environment_sha256,
        )
        require_sha256_hex_v1(
            "runtime_configuration_sha256",
            self.runtime_configuration_sha256,
        )
        for name in (
            "inference_thread_count",
            "inter_op_thread_count",
            "intra_op_thread_count",
            "process_thread_cap",
        ):
            _positive_int_v1(name, getattr(self, name))
        if any(
            count > self.process_thread_cap
            for count in (
                self.inference_thread_count,
                self.inter_op_thread_count,
                self.intra_op_thread_count,
            )
        ):
            raise ValueError("declared thread count exceeds process_thread_cap")
        object.__setattr__(
            self,
            "runtime_library_versions",
            sorted_unique_text_v1(
                "runtime_library_versions",
                self.runtime_library_versions,
            ),
        )
        if any(
            prohibited in item.casefold()
            for item in self.runtime_library_versions
            for prohibited in _PROHIBITED_ACCELERATOR_NAME_PARTS_V1
        ):
            raise ValueError(
                "V1 CPU runtime identity must contain no GPU/CUDA library"
            )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "cpu_architecture": self.cpu_architecture,
            "cpu_isa_policy": self.cpu_isa_policy,
            "cpu_qualification_class_sha256": (
                self.cpu_qualification_class_sha256
            ),
            "inference_thread_count": self.inference_thread_count,
            "inter_op_thread_count": self.inter_op_thread_count,
            "intra_op_thread_count": self.intra_op_thread_count,
            "process_thread_cap": self.process_thread_cap,
            "runtime_configuration_sha256": (
                self.runtime_configuration_sha256
            ),
            "runtime_library_versions": list(
                self.runtime_library_versions
            ),
            "thread_affinity_policy": self.thread_affinity_policy,
            "thread_environment_sha256": self.thread_environment_sha256,
        }


@dataclass(frozen=True, slots=True)
class AcceleratorPolicyV1:
    gpu_allowed: bool
    cuda_initialization_allowed: bool
    cuda_allocation_allowed: bool

    def __post_init__(self) -> None:
        for name in (
            "gpu_allowed",
            "cuda_initialization_allowed",
            "cuda_allocation_allowed",
        ):
            if _bool_v1(name, getattr(self, name)):
                raise ValueError("V1 certificate OCR prohibits GPU/CUDA")

    def canonical_object_v1(self) -> dict[str, bool]:
        return {
            "cuda_allocation_allowed": self.cuda_allocation_allowed,
            "cuda_initialization_allowed": (
                self.cuda_initialization_allowed
            ),
            "gpu_allowed": self.gpu_allowed,
        }


@dataclass(frozen=True, slots=True)
class ExecutionIdentityV1:
    device: str
    automatic_device_selection: bool
    engine: str
    engine_version: str
    engine_configuration_sha256: str
    execution_backend: str
    execution_backend_version: str
    execution_backend_configuration_sha256: str
    automatic_backend_selection: bool
    automatic_backend_fallback: bool
    precision: str
    deterministic_algorithms: bool
    hpi_enabled: bool
    hpi_auto_config: bool
    batch_policy: str
    cpu_runtime: CpuRuntimeIdentityV1
    accelerator_policy: AcceleratorPolicyV1

    def __post_init__(self) -> None:
        if self.device != "cpu":
            raise ValueError("V1 certificate OCR device must be literal cpu")
        for name in (
            "automatic_device_selection",
            "automatic_backend_selection",
            "automatic_backend_fallback",
            "hpi_auto_config",
        ):
            if _bool_v1(name, getattr(self, name)):
                raise ValueError("automatic selection/fallback is prohibited")
        _bool_v1(
            "deterministic_algorithms",
            self.deterministic_algorithms,
        )
        _bool_v1("hpi_enabled", self.hpi_enabled)
        _concrete_name_v1("engine", self.engine)
        _concrete_name_v1("execution_backend", self.execution_backend)
        for name in (
            "engine_version",
            "execution_backend_version",
            "precision",
            "batch_policy",
        ):
            require_text_v1(name, getattr(self, name))
        for name in (
            "engine_configuration_sha256",
            "execution_backend_configuration_sha256",
        ):
            require_sha256_hex_v1(name, getattr(self, name))
        if not isinstance(self.cpu_runtime, CpuRuntimeIdentityV1):
            raise TypeError("cpu_runtime must be CpuRuntimeIdentityV1")
        if not isinstance(self.accelerator_policy, AcceleratorPolicyV1):
            raise TypeError(
                "accelerator_policy must be AcceleratorPolicyV1"
            )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "accelerator_policy": (
                self.accelerator_policy.canonical_object_v1()
            ),
            "automatic_backend_fallback": self.automatic_backend_fallback,
            "automatic_backend_selection": self.automatic_backend_selection,
            "automatic_device_selection": self.automatic_device_selection,
            "batch_policy": self.batch_policy,
            "cpu_runtime": self.cpu_runtime.canonical_object_v1(),
            "deterministic_algorithms": self.deterministic_algorithms,
            "device": self.device,
            "engine": self.engine,
            "engine_configuration_sha256": (
                self.engine_configuration_sha256
            ),
            "engine_version": self.engine_version,
            "execution_backend": self.execution_backend,
            "execution_backend_configuration_sha256": (
                self.execution_backend_configuration_sha256
            ),
            "execution_backend_version": self.execution_backend_version,
            "hpi_auto_config": self.hpi_auto_config,
            "hpi_enabled": self.hpi_enabled,
            "precision": self.precision,
        }


@dataclass(frozen=True, slots=True)
class HostProvenanceV1:
    os_release: str
    kernel_version: str
    cpu_vendor: str
    cpu_model: str
    cpu_features_sha256: str
    microcode_version: str
    logical_cpu_count: int

    def __post_init__(self) -> None:
        for name in (
            "os_release",
            "kernel_version",
            "cpu_vendor",
            "cpu_model",
            "microcode_version",
        ):
            require_text_v1(name, getattr(self, name))
        require_sha256_hex_v1(
            "cpu_features_sha256",
            self.cpu_features_sha256,
        )
        _positive_int_v1("logical_cpu_count", self.logical_cpu_count)

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "cpu_features_sha256": self.cpu_features_sha256,
            "cpu_model": self.cpu_model,
            "cpu_vendor": self.cpu_vendor,
            "kernel_version": self.kernel_version,
            "logical_cpu_count": self.logical_cpu_count,
            "microcode_version": self.microcode_version,
            "os_release": self.os_release,
        }


@dataclass(frozen=True, slots=True)
class ModelIdentityV1:
    role: str
    model_name: str
    source_artifact_sha256: str
    executable_artifact_sha256: str
    configuration_sha256: str

    def __post_init__(self) -> None:
        require_text_v1("role", self.role)
        require_text_v1("model_name", self.model_name)
        for name in (
            "source_artifact_sha256",
            "executable_artifact_sha256",
            "configuration_sha256",
        ):
            require_sha256_hex_v1(name, getattr(self, name))

    def canonical_object_v1(self) -> dict[str, str]:
        return {
            "configuration_sha256": self.configuration_sha256,
            "executable_artifact_sha256": (
                self.executable_artifact_sha256
            ),
            "model_name": self.model_name,
            "role": self.role,
            "source_artifact_sha256": self.source_artifact_sha256,
        }

    def sort_key_v1(self) -> tuple[str, ...]:
        return (
            self.role,
            self.model_name,
            self.source_artifact_sha256,
            self.executable_artifact_sha256,
            self.configuration_sha256,
        )


@dataclass(frozen=True, slots=True)
class ModelConversionIdentityV1:
    enabled: bool
    tool: str | None
    tool_version: str | None
    configuration_sha256: str | None

    def __post_init__(self) -> None:
        _bool_v1("enabled", self.enabled)
        if self.enabled:
            require_text_v1("tool", self.tool)
            require_text_v1("tool_version", self.tool_version)
            require_sha256_hex_v1(
                "configuration_sha256",
                self.configuration_sha256,
            )
            return
        if any(
            value is not None
            for value in (
                self.tool,
                self.tool_version,
                self.configuration_sha256,
            )
        ):
            raise ValueError(
                "disabled model conversion must not carry fake identity"
            )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "configuration_sha256": self.configuration_sha256,
            "enabled": self.enabled,
            "tool": self.tool,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True, slots=True)
class PipelineIdentityV1:
    canonical_configuration_sha256: str
    character_dictionary_sha256: str

    def __post_init__(self) -> None:
        require_sha256_hex_v1(
            "canonical_configuration_sha256",
            self.canonical_configuration_sha256,
        )
        require_sha256_hex_v1(
            "character_dictionary_sha256",
            self.character_dictionary_sha256,
        )

    def canonical_object_v1(self) -> dict[str, str]:
        return {
            "canonical_configuration_sha256": (
                self.canonical_configuration_sha256
            ),
            "character_dictionary_sha256": (
                self.character_dictionary_sha256
            ),
        }


@dataclass(frozen=True, slots=True)
class ProcessingIdentityV1:
    implementation_version: str
    source_sha256: str
    configuration_sha256: str

    def __post_init__(self) -> None:
        require_text_v1(
            "implementation_version",
            self.implementation_version,
        )
        require_sha256_hex_v1("source_sha256", self.source_sha256)
        require_sha256_hex_v1(
            "configuration_sha256",
            self.configuration_sha256,
        )

    def canonical_object_v1(self) -> dict[str, str]:
        return {
            "configuration_sha256": self.configuration_sha256,
            "implementation_version": self.implementation_version,
            "source_sha256": self.source_sha256,
        }


def _canonical_models_v1(
    models: object,
) -> tuple[ModelIdentityV1, ...]:
    if not isinstance(models, tuple):
        raise TypeError("models must be an immutable tuple")
    if not 1 <= len(models) <= 32:
        raise ValueError("models must contain a bounded non-empty set")
    if not all(isinstance(model, ModelIdentityV1) for model in models):
        raise TypeError("models must contain ModelIdentityV1 values")
    sorted_models = tuple(sorted(models, key=ModelIdentityV1.sort_key_v1))
    keys = tuple(model.sort_key_v1() for model in sorted_models)
    if len(set(keys)) != len(keys):
        raise ValueError("models must not contain duplicate identities")
    roles = tuple(model.role for model in sorted_models)
    if len(set(roles)) != len(roles):
        raise ValueError("each model role must be unique")
    return sorted_models


@dataclass(frozen=True, slots=True, kw_only=True)
class InferenceIdentityV1:
    service: ServiceIdentityV1
    software: SoftwareIdentityV1
    execution: ExecutionIdentityV1
    host_provenance: HostProvenanceV1
    models: tuple[ModelIdentityV1, ...]
    model_conversion: ModelConversionIdentityV1
    pipeline: PipelineIdentityV1
    preprocessing: ProcessingIdentityV1
    postprocessing: ProcessingIdentityV1
    schema_version: str = INFERENCE_IDENTITY_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != INFERENCE_IDENTITY_SCHEMA_VERSION_V1:
            raise ValueError("unsupported InferenceIdentityV1 schema version")
        expected_types = (
            ("service", self.service, ServiceIdentityV1),
            ("software", self.software, SoftwareIdentityV1),
            ("execution", self.execution, ExecutionIdentityV1),
            ("host_provenance", self.host_provenance, HostProvenanceV1),
            (
                "model_conversion",
                self.model_conversion,
                ModelConversionIdentityV1,
            ),
            ("pipeline", self.pipeline, PipelineIdentityV1),
            ("preprocessing", self.preprocessing, ProcessingIdentityV1),
            ("postprocessing", self.postprocessing, ProcessingIdentityV1),
        )
        for name, value, expected in expected_types:
            if not isinstance(value, expected):
                raise TypeError(f"{name} has the wrong typed identity")
        object.__setattr__(
            self,
            "models",
            _canonical_models_v1(self.models),
        )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "execution": self.execution.canonical_object_v1(),
            "host_provenance": (
                self.host_provenance.canonical_object_v1()
            ),
            "model_conversion": (
                self.model_conversion.canonical_object_v1()
            ),
            "models": [
                model.canonical_object_v1() for model in self.models
            ],
            "pipeline": self.pipeline.canonical_object_v1(),
            "postprocessing": self.postprocessing.canonical_object_v1(),
            "preprocessing": self.preprocessing.canonical_object_v1(),
            "schema_version": self.schema_version,
            "service": self.service.canonical_object_v1(),
            "software": self.software.canonical_object_v1(),
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def inference_identity_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_v1()).hexdigest()

    def calibration_dependency_v1(self) -> CalibrationDependencyV1:
        return CalibrationDependencyV1.from_inference_identity_v1(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class CalibrationDependencyV1:
    software: SoftwareIdentityV1
    execution: ExecutionIdentityV1
    models: tuple[ModelIdentityV1, ...]
    model_conversion: ModelConversionIdentityV1
    pipeline: PipelineIdentityV1
    preprocessing: ProcessingIdentityV1
    postprocessing: ProcessingIdentityV1
    schema_version: str = CALIBRATION_DEPENDENCY_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != CALIBRATION_DEPENDENCY_SCHEMA_VERSION_V1:
            raise ValueError(
                "unsupported CalibrationDependencyV1 schema version"
            )
        expected_types = (
            ("software", self.software, SoftwareIdentityV1),
            ("execution", self.execution, ExecutionIdentityV1),
            (
                "model_conversion",
                self.model_conversion,
                ModelConversionIdentityV1,
            ),
            ("pipeline", self.pipeline, PipelineIdentityV1),
            ("preprocessing", self.preprocessing, ProcessingIdentityV1),
            ("postprocessing", self.postprocessing, ProcessingIdentityV1),
        )
        for name, value, expected in expected_types:
            if not isinstance(value, expected):
                raise TypeError(f"{name} has the wrong typed dependency")
        object.__setattr__(
            self,
            "models",
            _canonical_models_v1(self.models),
        )

    @classmethod
    def from_inference_identity_v1(
        cls,
        identity: InferenceIdentityV1,
    ) -> CalibrationDependencyV1:
        if not isinstance(identity, InferenceIdentityV1):
            raise TypeError("identity must be InferenceIdentityV1")
        return cls(
            software=identity.software,
            execution=identity.execution,
            models=identity.models,
            model_conversion=identity.model_conversion,
            pipeline=identity.pipeline,
            preprocessing=identity.preprocessing,
            postprocessing=identity.postprocessing,
        )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "execution": self.execution.canonical_object_v1(),
            "model_conversion": (
                self.model_conversion.canonical_object_v1()
            ),
            "models": [
                model.canonical_object_v1() for model in self.models
            ],
            "pipeline": self.pipeline.canonical_object_v1(),
            "postprocessing": self.postprocessing.canonical_object_v1(),
            "preprocessing": self.preprocessing.canonical_object_v1(),
            "schema_version": self.schema_version,
            "software": self.software.canonical_object_v1(),
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def calibration_dependency_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_v1()).hexdigest()


__all__ = [
    "CALIBRATION_DEPENDENCY_SCHEMA_VERSION_V1",
    "INFERENCE_IDENTITY_SCHEMA_VERSION_V1",
    "AcceleratorPolicyV1",
    "CalibrationDependencyV1",
    "CpuRuntimeIdentityV1",
    "ExecutionIdentityV1",
    "HostProvenanceV1",
    "InferenceIdentityV1",
    "ModelConversionIdentityV1",
    "ModelIdentityV1",
    "PipelineIdentityV1",
    "ProcessingIdentityV1",
    "ServiceIdentityV1",
    "SoftwareIdentityV1",
]
