"""Fail-closed production manifest and CPU runtime verification."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from certificate_ocr.protocol import (
    OCR_UDS_PROTOCOL_VERSION_V1,
    SidecarProtocolErrorV1,
    canonical_json_bytes_v1,
    exact_object_v1,
    require_sha256_v1,
    strict_json_object_v1,
)

MODEL_MANIFEST_SCHEMA_VERSION_V1 = "oac.ocr-model-manifest.v1"
QUALIFICATION_RECORD_SCHEMA_VERSION_V1 = "oac.ocr-qualification-record.v1"
MAX_MANIFEST_BYTES_V1 = 256 * 1024
MAX_QUALIFICATION_RECORD_BYTES_V1 = 1024 * 1024

_THREAD_ENVIRONMENT_NAMES_V1 = (
    "FLAGS_paddle_num_threads",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)
_PROHIBITED_PACKAGE_PARTS_V1 = (
    "cuda",
    "cudnn",
    "gpu",
    "nvidia",
    "tensorrt",
)
_REQUIRED_DISTRIBUTIONS_V1 = (
    "numpy",
    "opencv-python-headless",
    "paddleocr",
    "paddlepaddle",
    "paddlex",
    "psutil",
)
_INFERENCE_IDENTITY_SCHEMA_VERSION_V1 = "oac.inference-identity.v1"
_MAX_DEPENDENCY_LOCK_BYTES_V1 = 4 * 1024 * 1024


class ManifestUnavailableV1(RuntimeError):
    """Stable startup failure with no payload-bearing detail."""


def _sha256_file_v1(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise ManifestUnavailableV1("OCR manifest unavailable") from None
    return digest.hexdigest()


def _sha256_directory_v1(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        resolved_root = path.resolve(strict=True)
        files = []
        for candidate in resolved_root.rglob("*"):
            if candidate.is_symlink():
                raise ManifestUnavailableV1("OCR model identity unavailable")
            if candidate.is_file():
                files.append(candidate)
        if not files or len(files) > 4096:
            raise ManifestUnavailableV1("OCR model identity unavailable")
        for candidate in sorted(
            files,
            key=lambda item: item.relative_to(resolved_root).as_posix(),
        ):
            relative = candidate.relative_to(resolved_root).as_posix()
            digest.update(relative.encode("utf-8", errors="strict"))
            digest.update(b"\x00")
            digest.update(bytes.fromhex(_sha256_file_v1(candidate)))
    except (OSError, UnicodeError, ValueError):
        raise ManifestUnavailableV1("OCR model identity unavailable") from None
    return digest.hexdigest()


def _safe_artifact_path_v1(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ManifestUnavailableV1("OCR manifest unavailable")
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise ManifestUnavailableV1("OCR manifest unavailable") from None
    if not resolved.is_file():
        raise ManifestUnavailableV1("OCR manifest unavailable")
    return resolved


def _distribution_digest_v1(name: str) -> tuple[str, str]:
    try:
        distribution = importlib.metadata.distribution(name)
        version = distribution.version
        files = distribution.files
    except importlib.metadata.PackageNotFoundError:
        raise ManifestUnavailableV1("OCR backend unavailable") from None
    if not files:
        raise ManifestUnavailableV1("OCR backend unavailable")
    digest = hashlib.sha256()
    located: list[tuple[str, Path]] = []
    for entry in files:
        path = Path(distribution.locate_file(entry))
        if path.is_file():
            located.append((entry.as_posix(), path))
    if not located:
        raise ManifestUnavailableV1("OCR backend unavailable")
    for relative, path in sorted(located):
        digest.update(relative.encode("utf-8", errors="strict"))
        digest.update(b"\x00")
        digest.update(bytes.fromhex(_sha256_file_v1(path)))
    return version, digest.hexdigest()


def _bounded_text_v1(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="strict")) > 512
    ):
        raise ManifestUnavailableV1("OCR identity unavailable")
    return value


def _boolean_v1(value: object) -> bool:
    if not isinstance(value, bool):
        raise ManifestUnavailableV1("OCR identity unavailable")
    return value


def _positive_integer_v1(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 65_536
    ):
        raise ManifestUnavailableV1("OCR identity unavailable")
    return value


def _text_array_v1(
    value: object,
    *,
    allow_empty: bool,
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > 256
        or not all(isinstance(item, str) and item for item in value)
        or value != sorted(value)
        or len(set(value)) != len(value)
        or any(len(item.encode("utf-8", errors="strict")) > 512 for item in value)
    ):
        raise ManifestUnavailableV1("OCR identity unavailable")
    return value


def _processing_identity_v1(value: object) -> dict[str, Any]:
    item = exact_object_v1(
        value,
        frozenset(
            {
                "configuration_sha256",
                "implementation_version",
                "source_sha256",
            }
        ),
    )
    _bounded_text_v1(item["implementation_version"])
    require_sha256_v1(item["source_sha256"])
    require_sha256_v1(item["configuration_sha256"])
    return item


def _validate_inference_identity_v1(
    identity: object,
    *,
    backend: dict[str, Any],
    thread_environment_sha256: str,
) -> dict[str, Any]:
    root = exact_object_v1(
        identity,
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
    )
    if root["schema_version"] != _INFERENCE_IDENTITY_SCHEMA_VERSION_V1:
        raise ManifestUnavailableV1("OCR identity unavailable")

    service = exact_object_v1(
        root["service"],
        frozenset(
            {
                "container_image_digest",
                "protocol_version",
                "source_revision",
            }
        ),
    )
    for value in service.values():
        _bounded_text_v1(value)

    software = exact_object_v1(
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
    )
    for name in (
        "python_abi",
        "paddleocr_version",
        "paddlepaddle_version",
        "paddlex_version",
    ):
        _bounded_text_v1(software[name])
    if software["paddlepaddle_distribution"] != "paddlepaddle":
        raise ManifestUnavailableV1("OCR identity unavailable")
    _text_array_v1(
        software["cpu_runtime_packages"],
        allow_empty=False,
    )
    _text_array_v1(
        software["locked_wheel_hashes"],
        allow_empty=False,
    )

    execution = exact_object_v1(
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
    )
    if (
        execution["device"] != "cpu"
        or execution["engine"] != backend["engine"]
        or execution["automatic_device_selection"] is not False
        or execution["automatic_backend_selection"] is not False
        or execution["automatic_backend_fallback"] is not False
        or execution["hpi_enabled"] is not backend["enable_hpi"]
        or execution["hpi_auto_config"] is not False
    ):
        raise ManifestUnavailableV1("OCR identity unavailable")
    _boolean_v1(execution["deterministic_algorithms"])
    for name in (
        "engine",
        "engine_version",
        "execution_backend",
        "execution_backend_version",
        "precision",
        "batch_policy",
    ):
        value = _bounded_text_v1(execution[name]).casefold()
        if any(prohibited in value for prohibited in _PROHIBITED_PACKAGE_PARTS_V1):
            raise ManifestUnavailableV1("OCR identity unavailable")
    require_sha256_v1(execution["engine_configuration_sha256"])
    require_sha256_v1(execution["execution_backend_configuration_sha256"])
    accelerator = exact_object_v1(
        execution["accelerator_policy"],
        frozenset(
            {
                "cuda_allocation_allowed",
                "cuda_initialization_allowed",
                "gpu_allowed",
            }
        ),
    )
    if accelerator != {
        "cuda_allocation_allowed": False,
        "cuda_initialization_allowed": False,
        "gpu_allowed": False,
    }:
        raise ManifestUnavailableV1("OCR identity unavailable")

    cpu_runtime = exact_object_v1(
        execution["cpu_runtime"],
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
    )
    for name in (
        "cpu_architecture",
        "cpu_isa_policy",
        "thread_affinity_policy",
    ):
        _bounded_text_v1(cpu_runtime[name])
    for name in (
        "cpu_qualification_class_sha256",
        "runtime_configuration_sha256",
        "thread_environment_sha256",
    ):
        require_sha256_v1(cpu_runtime[name])
    thread_count = _positive_integer_v1(backend["cpu_threads"])
    process_thread_cap = _positive_integer_v1(cpu_runtime["process_thread_cap"])
    for name in (
        "inference_thread_count",
        "inter_op_thread_count",
        "intra_op_thread_count",
    ):
        if _positive_integer_v1(cpu_runtime[name]) > process_thread_cap:
            raise ManifestUnavailableV1("OCR thread identity unavailable")
    if (
        cpu_runtime["inference_thread_count"] != thread_count
        or thread_count > process_thread_cap
        or cpu_runtime["thread_environment_sha256"] != thread_environment_sha256
    ):
        raise ManifestUnavailableV1("OCR thread identity unavailable")
    _text_array_v1(
        cpu_runtime["runtime_library_versions"],
        allow_empty=False,
    )

    host = exact_object_v1(
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
    )
    require_sha256_v1(host["cpu_features_sha256"])
    _positive_integer_v1(host["logical_cpu_count"])
    for name in (
        "cpu_model",
        "cpu_vendor",
        "kernel_version",
        "microcode_version",
        "os_release",
    ):
        _bounded_text_v1(host[name])

    models = root["models"]
    if not isinstance(models, list) or len(models) != 2:
        raise ManifestUnavailableV1("OCR model identity unavailable")
    expected_models = {
        "detector": backend["text_detection_model_dir"],
        "recognizer": backend["text_recognition_model_dir"],
    }
    model_keys: list[tuple[str, ...]] = []
    for value in models:
        model = exact_object_v1(
            value,
            frozenset(
                {
                    "configuration_sha256",
                    "executable_artifact_sha256",
                    "model_name",
                    "role",
                    "source_artifact_sha256",
                }
            ),
        )
        role = _bounded_text_v1(model["role"])
        if expected_models.get(role) != model["model_name"]:
            raise ManifestUnavailableV1("OCR model identity unavailable")
        _bounded_text_v1(model["model_name"])
        for name in (
            "configuration_sha256",
            "executable_artifact_sha256",
            "source_artifact_sha256",
        ):
            require_sha256_v1(model[name])
        model_keys.append(
            (
                role,
                model["model_name"],
                model["source_artifact_sha256"],
                model["executable_artifact_sha256"],
                model["configuration_sha256"],
            )
        )
    if model_keys != sorted(model_keys) or len(set(model_keys)) != 2:
        raise ManifestUnavailableV1("OCR model identity unavailable")

    conversion = exact_object_v1(
        root["model_conversion"],
        frozenset(
            {
                "configuration_sha256",
                "enabled",
                "tool",
                "tool_version",
            }
        ),
    )
    enabled = _boolean_v1(conversion["enabled"])
    if enabled:
        _bounded_text_v1(conversion["tool"])
        _bounded_text_v1(conversion["tool_version"])
        require_sha256_v1(conversion["configuration_sha256"])
    elif any(
        conversion[name] is not None
        for name in (
            "tool",
            "tool_version",
            "configuration_sha256",
        )
    ):
        raise ManifestUnavailableV1("OCR model identity unavailable")
    if backend["engine"] == "paddle_static" and enabled:
        raise ManifestUnavailableV1("OCR model identity unavailable")

    pipeline = exact_object_v1(
        root["pipeline"],
        frozenset(
            {
                "canonical_configuration_sha256",
                "character_dictionary_sha256",
            }
        ),
    )
    require_sha256_v1(pipeline["canonical_configuration_sha256"])
    require_sha256_v1(pipeline["character_dictionary_sha256"])
    _processing_identity_v1(root["preprocessing"])
    _processing_identity_v1(root["postprocessing"])
    return root


def _locked_wheel_hashes_v1(
    path: Path,
    versions: dict[str, str],
) -> list[str]:
    try:
        payload = path.read_bytes()
        if not 0 < len(payload) <= _MAX_DEPENDENCY_LOCK_BYTES_V1:
            raise ValueError
        lock = tomllib.loads(payload.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        raise ManifestUnavailableV1("OCR dependency lock unavailable") from None
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ManifestUnavailableV1("OCR dependency lock unavailable")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            by_name.setdefault(package["name"], []).append(package)
    entries: list[str] = []
    for name, version in versions.items():
        candidates = [
            package
            for package in by_name.get(name, [])
            if package.get("version") == version
        ]
        if len(candidates) != 1:
            raise ManifestUnavailableV1("OCR dependency lock unavailable")
        wheels = candidates[0].get("wheels")
        if not isinstance(wheels, list) or not wheels:
            raise ManifestUnavailableV1("OCR dependency lock unavailable")
        for wheel in wheels:
            if not isinstance(wheel, dict):
                raise ManifestUnavailableV1("OCR dependency lock unavailable")
            url = wheel.get("url")
            digest = wheel.get("hash")
            if (
                not isinstance(url, str)
                or not isinstance(digest, str)
                or not digest.startswith("sha256:")
            ):
                raise ManifestUnavailableV1("OCR dependency lock unavailable")
            require_sha256_v1(digest.removeprefix("sha256:"))
            filename = Path(urlsplit(url).path).name
            _bounded_text_v1(filename)
            entries.append(f"{name}=={version}:{filename}:{digest}")
    if not entries or len(entries) > 256 or len(set(entries)) != len(entries):
        raise ManifestUnavailableV1("OCR dependency lock unavailable")
    return sorted(entries)


def _verify_model_identity_binding_v1(
    *,
    identity: dict[str, Any],
    backend: dict[str, Any],
    model_root: Path,
    artifact_hashes: set[str],
) -> None:
    model_by_role = {model["role"]: model for model in identity["models"]}
    for role, directory_key in (
        ("detector", "text_detection_model_dir"),
        ("recognizer", "text_recognition_model_dir"),
    ):
        model = model_by_role[role]
        try:
            directory = (model_root / backend[directory_key]).resolve(strict=True)
            directory.relative_to(model_root.resolve(strict=True))
        except (OSError, ValueError):
            raise ManifestUnavailableV1("OCR model identity unavailable") from None
        if (
            not directory.is_dir()
            or _sha256_directory_v1(directory) != model["executable_artifact_sha256"]
            or model["source_artifact_sha256"] not in artifact_hashes
            or model["configuration_sha256"] not in artifact_hashes
        ):
            raise ManifestUnavailableV1("OCR model identity unavailable")
    if identity["pipeline"]["character_dictionary_sha256"] not in artifact_hashes:
        raise ManifestUnavailableV1("OCR dictionary identity unavailable")


def _host_provenance_v1() -> dict[str, object]:
    try:
        os_release = Path("/etc/os-release").read_text(
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError):
        raise ManifestUnavailableV1("OCR host identity unavailable") from None
    release_values: dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        release_values[key] = value.strip().strip('"')
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError):
        raise ManifestUnavailableV1("OCR host identity unavailable") from None
    cpu_values: dict[str, str] = {}
    for line in cpuinfo.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = key.strip().casefold()
        if normalized not in cpu_values:
            cpu_values[normalized] = value.strip()
    features = cpu_values.get("flags") or cpu_values.get("features")
    if not features:
        raise ManifestUnavailableV1("OCR host identity unavailable")
    normalized_features = " ".join(sorted(set(features.split())))
    logical_count = os.cpu_count()
    if logical_count is None or logical_count <= 0:
        raise ManifestUnavailableV1("OCR host identity unavailable")
    return {
        "cpu_features_sha256": hashlib.sha256(
            normalized_features.encode("utf-8", errors="strict")
        ).hexdigest(),
        "cpu_model": cpu_values.get(
            "model name",
            cpu_values.get("model", "unavailable"),
        ),
        "cpu_vendor": cpu_values.get(
            "vendor_id",
            cpu_values.get("cpu implementer", "unavailable"),
        ),
        "kernel_version": platform.release(),
        "logical_cpu_count": logical_count,
        "microcode_version": cpu_values.get("microcode", "unavailable"),
        "os_release": (
            f"{release_values.get('ID', 'unavailable')}:"
            f"{release_values.get('VERSION_ID', 'unavailable')}"
        ),
    }


def _verify_runtime_identity_v1(identity: dict[str, Any]) -> None:
    service = identity["service"]
    software = identity["software"]
    cpu_runtime = identity["execution"]["cpu_runtime"]
    image_digest = os.environ.get("OCR_CONTAINER_IMAGE_DIGEST", "")
    if (
        service["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or service["source_revision"] != os.environ.get("OCR_SOURCE_REVISION")
        or service["container_image_digest"] != image_digest
        or not os.environ.get("OCR_SOURCE_REVISION")
        or not image_digest.startswith("sha256:")
        or len(image_digest) != 71
        or any(
            character not in "0123456789abcdef"
            for character in image_digest.removeprefix("sha256:")
        )
        or software["python_abi"]
        != f"cp{sys.version_info.major}{sys.version_info.minor}"
        or cpu_runtime["cpu_architecture"] != platform.machine()
        or identity["host_provenance"] != _host_provenance_v1()
    ):
        raise ManifestUnavailableV1("OCR runtime identity mismatch")

    observed_runtime_packages: list[str] = []
    versions: dict[str, str] = {}
    for distribution_name in _REQUIRED_DISTRIBUTIONS_V1:
        version, distribution_sha256 = _distribution_digest_v1(distribution_name)
        versions[distribution_name] = version
        observed_runtime_packages.append(
            f"{distribution_name}=={version}:{distribution_sha256}"
        )
    if sorted(software["cpu_runtime_packages"]) != sorted(observed_runtime_packages):
        raise ManifestUnavailableV1("OCR software identity mismatch")
    dependency_lock_path = Path(
        os.environ.get(
            "OCR_DEPENDENCY_LOCK_PATH",
            "/opt/certificate-ocr/uv.lock",
        )
    )
    if sorted(software["locked_wheel_hashes"]) != _locked_wheel_hashes_v1(
        dependency_lock_path,
        versions,
    ):
        raise ManifestUnavailableV1("OCR software identity mismatch")
    if (
        software["paddleocr_version"] != versions["paddleocr"]
        or software["paddlepaddle_version"] != versions["paddlepaddle"]
        or software["paddlex_version"] != versions["paddlex"]
    ):
        raise ManifestUnavailableV1("OCR software identity mismatch")
    if any(
        prohibited in item.casefold()
        for item in (
            *software["locked_wheel_hashes"],
            *software["cpu_runtime_packages"],
            *cpu_runtime["runtime_library_versions"],
        )
        for prohibited in _PROHIBITED_PACKAGE_PARTS_V1
    ):
        raise ManifestUnavailableV1("OCR accelerator package prohibited")


def apply_cpu_environment_v1(cpu_threads: int) -> str:
    if (
        isinstance(cpu_threads, bool)
        or not isinstance(cpu_threads, int)
        or not 1 <= cpu_threads <= 64
    ):
        raise ManifestUnavailableV1("OCR thread identity unavailable")
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"
    os.environ["FLAGS_selected_gpus"] = ""
    for name in _THREAD_ENVIRONMENT_NAMES_V1:
        os.environ[name] = str(cpu_threads)
    return hashlib.sha256(
        canonical_json_bytes_v1(
            {name: os.environ[name] for name in _THREAD_ENVIRONMENT_NAMES_V1}
        )
    ).hexdigest()


def verify_no_prohibited_loaded_libraries_v1() -> None:
    try:
        mappings = (
            Path("/proc/self/maps")
            .read_text(
                encoding="utf-8",
                errors="strict",
            )
            .casefold()
        )
    except (OSError, UnicodeError):
        raise ManifestUnavailableV1("OCR runtime proof unavailable") from None
    prohibited = ("libcuda", "libcudnn", "libnvinfer", "libtensorrt")
    if any(name in mappings for name in prohibited):
        raise ManifestUnavailableV1("OCR accelerator runtime prohibited")


@dataclass(frozen=True, slots=True)
class VerifiedManifestV1:
    root: Path
    identity: dict[str, Any]
    identity_sha256: str
    preprocessing_identity_sha256: str
    backend: dict[str, Any]
    qualification_record_sha256: str
    processing_timeout_seconds: float
    warmup_path: Path
    warmup_expected_minimum_spans: int


@dataclass(frozen=True, slots=True)
class QualificationCandidateManifestV1:
    root: Path
    identity: dict[str, Any]
    identity_sha256: str
    preprocessing_identity_sha256: str
    backend: dict[str, Any]
    processing_timeout_seconds: float
    warmup_path: Path
    warmup_expected_minimum_spans: int


def load_qualification_candidate_v1(
    *,
    manifest_path: Path,
    model_root: Path,
) -> QualificationCandidateManifestV1:
    """Load an explicitly unqualified candidate for the offline harness only."""

    try:
        value = strict_json_object_v1(
            manifest_path.read_bytes(),
            maximum_bytes=MAX_MANIFEST_BYTES_V1,
        )
    except (OSError, SidecarProtocolErrorV1):
        raise ManifestUnavailableV1("OCR candidate unavailable") from None
    root = exact_object_v1(
        value,
        frozenset(
            {
                "artifacts",
                "backend",
                "identity",
                "processing_timeout_seconds",
                "qualification_record_path",
                "qualification_record_sha256",
                "qualification_status",
                "schema_version",
                "warmup",
            }
        ),
    )
    if (
        root["schema_version"] != MODEL_MANIFEST_SCHEMA_VERSION_V1
        or root["qualification_status"] != "candidate"
        or not isinstance(root["identity"], dict)
        or root["qualification_record_path"] is not None
        or root["qualification_record_sha256"] is not None
    ):
        raise ManifestUnavailableV1("OCR candidate unavailable")
    backend = exact_object_v1(
        root["backend"],
        frozenset(
            {
                "cpu_threads",
                "device",
                "enable_hpi",
                "engine",
                "ocr_version",
                "text_detection_model_dir",
                "text_recognition_model_dir",
                "use_doc_orientation_classify",
                "use_doc_unwarping",
                "use_textline_orientation",
            }
        ),
    )
    if (
        backend["device"] != "cpu"
        or backend["ocr_version"] != "PP-OCRv6"
        or backend["use_doc_orientation_classify"] is not False
        or backend["use_doc_unwarping"] is not False
        or backend["use_textline_orientation"] is not False
        or (backend["engine"] == "paddle_static" and backend["enable_hpi"] is not False)
    ):
        raise ManifestUnavailableV1("OCR candidate is not fixed CPU")
    thread_environment_sha256 = apply_cpu_environment_v1(backend["cpu_threads"])
    identity = _validate_inference_identity_v1(
        root["identity"],
        backend=backend,
        thread_environment_sha256=thread_environment_sha256,
    )
    _verify_runtime_identity_v1(identity)
    try:
        software = identity["software"]
        execution = identity["execution"]
        cpu_runtime = execution["cpu_runtime"]
        accelerator = execution["accelerator_policy"]
        preprocessing = identity["preprocessing"]
    except (KeyError, TypeError):
        raise ManifestUnavailableV1("OCR candidate identity unavailable") from None
    if (
        software.get("paddlepaddle_distribution") != "paddlepaddle"
        or execution.get("device") != "cpu"
        or execution.get("engine") != backend["engine"]
        or execution.get("automatic_device_selection") is not False
        or execution.get("automatic_backend_selection") is not False
        or execution.get("automatic_backend_fallback") is not False
        or execution.get("hpi_auto_config") is not False
        or accelerator
        != {
            "cuda_allocation_allowed": False,
            "cuda_initialization_allowed": False,
            "gpu_allowed": False,
        }
        or cpu_runtime.get("inference_thread_count") != backend["cpu_threads"]
        or cpu_runtime.get("thread_environment_sha256") != thread_environment_sha256
    ):
        raise ManifestUnavailableV1("OCR candidate identity unavailable")
    timeout = root["processing_timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1.0 <= float(timeout) <= 300.0
    ):
        raise ManifestUnavailableV1("OCR candidate timeout unavailable")
    artifacts = root["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestUnavailableV1("OCR candidate artifacts unavailable")
    observed_paths: set[str] = set()
    artifact_hashes: set[str] = set()
    for artifact_value in artifacts:
        artifact = exact_object_v1(
            artifact_value,
            frozenset({"path", "sha256"}),
        )
        relative = artifact["path"]
        if not isinstance(relative, str) or relative in observed_paths:
            raise ManifestUnavailableV1("OCR candidate manifest duplicated")
        observed_paths.add(relative)
        expected_hash = require_sha256_v1(artifact["sha256"])
        artifact_hashes.add(expected_hash)
        if (
            _sha256_file_v1(_safe_artifact_path_v1(model_root, relative))
            != expected_hash
        ):
            raise ManifestUnavailableV1("OCR candidate artifact mismatch")
    warmup = exact_object_v1(
        root["warmup"],
        frozenset({"expected_minimum_spans", "jpeg_path", "sha256"}),
    )
    warmup_path = _safe_artifact_path_v1(
        model_root,
        warmup["jpeg_path"],
    )
    if _sha256_file_v1(warmup_path) != require_sha256_v1(warmup["sha256"]):
        raise ManifestUnavailableV1("OCR candidate warmup mismatch")
    expected_spans = warmup["expected_minimum_spans"]
    if (
        isinstance(expected_spans, bool)
        or not isinstance(expected_spans, int)
        or not 0 <= expected_spans <= 128
    ):
        raise ManifestUnavailableV1("OCR candidate warmup mismatch")
    _verify_model_identity_binding_v1(
        identity=identity,
        backend=backend,
        model_root=model_root,
        artifact_hashes=artifact_hashes,
    )
    identity_bytes = canonical_json_bytes_v1(identity)
    return QualificationCandidateManifestV1(
        root=model_root,
        identity=identity,
        identity_sha256=hashlib.sha256(identity_bytes).hexdigest(),
        preprocessing_identity_sha256=hashlib.sha256(
            canonical_json_bytes_v1(preprocessing)
        ).hexdigest(),
        backend=backend,
        processing_timeout_seconds=float(timeout),
        warmup_path=warmup_path,
        warmup_expected_minimum_spans=expected_spans,
    )


def load_verified_manifest_v1(
    *,
    manifest_path: Path,
    model_root: Path,
) -> VerifiedManifestV1:
    try:
        payload = manifest_path.read_bytes()
        value = strict_json_object_v1(
            payload,
            maximum_bytes=MAX_MANIFEST_BYTES_V1,
        )
    except (OSError, SidecarProtocolErrorV1):
        raise ManifestUnavailableV1("OCR manifest unavailable") from None
    root = exact_object_v1(
        value,
        frozenset(
            {
                "artifacts",
                "backend",
                "identity",
                "processing_timeout_seconds",
                "qualification_record_path",
                "qualification_record_sha256",
                "qualification_status",
                "schema_version",
                "warmup",
            }
        ),
    )
    if (
        root["schema_version"] != MODEL_MANIFEST_SCHEMA_VERSION_V1
        or root["qualification_status"] != "qualified"
        or not isinstance(root["identity"], dict)
    ):
        raise ManifestUnavailableV1("OCR manifest unavailable")
    qualification_sha256 = require_sha256_v1(root["qualification_record_sha256"])
    timeout = root["processing_timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1.0 <= float(timeout) <= 300.0
    ):
        raise ManifestUnavailableV1("OCR manifest unavailable")
    backend = exact_object_v1(
        root["backend"],
        frozenset(
            {
                "cpu_threads",
                "device",
                "enable_hpi",
                "engine",
                "ocr_version",
                "text_detection_model_dir",
                "text_recognition_model_dir",
                "use_doc_orientation_classify",
                "use_doc_unwarping",
                "use_textline_orientation",
            }
        ),
    )
    if (
        backend["device"] != "cpu"
        or backend["engine"] != "paddle_static"
        or backend["enable_hpi"] is not False
        or backend["ocr_version"] != "PP-OCRv6"
        or backend["use_doc_orientation_classify"] is not False
        or backend["use_doc_unwarping"] is not False
        or backend["use_textline_orientation"] is not False
    ):
        raise ManifestUnavailableV1("OCR CPU backend unavailable")
    thread_environment_sha256 = apply_cpu_environment_v1(backend["cpu_threads"])

    identity = _validate_inference_identity_v1(
        root["identity"],
        backend=backend,
        thread_environment_sha256=thread_environment_sha256,
    )
    try:
        service = identity["service"]
        software = identity["software"]
        execution = identity["execution"]
        cpu_runtime = execution["cpu_runtime"]
        accelerator = execution["accelerator_policy"]
        preprocessing = identity["preprocessing"]
    except (KeyError, TypeError):
        raise ManifestUnavailableV1("OCR identity unavailable") from None
    if (
        service.get("protocol_version") != OCR_UDS_PROTOCOL_VERSION_V1
        or service.get("source_revision") != os.environ.get("OCR_SOURCE_REVISION")
        or service.get("container_image_digest")
        != os.environ.get("OCR_CONTAINER_IMAGE_DIGEST")
        or not os.environ.get("OCR_SOURCE_REVISION")
        or not os.environ.get("OCR_CONTAINER_IMAGE_DIGEST", "").startswith("sha256:")
        or len(os.environ.get("OCR_CONTAINER_IMAGE_DIGEST", "")) != 71
        or any(
            character not in "0123456789abcdef"
            for character in os.environ.get(
                "OCR_CONTAINER_IMAGE_DIGEST",
                "",
            ).removeprefix("sha256:")
        )
        or software.get("python_abi")
        != f"cp{sys.version_info.major}{sys.version_info.minor}"
        or software.get("paddlepaddle_distribution") != "paddlepaddle"
        or execution.get("device") != "cpu"
        or execution.get("engine") != "paddle_static"
        or execution.get("automatic_device_selection") is not False
        or execution.get("automatic_backend_selection") is not False
        or execution.get("automatic_backend_fallback") is not False
        or execution.get("hpi_enabled") is not False
        or execution.get("hpi_auto_config") is not False
        or accelerator
        != {
            "cuda_allocation_allowed": False,
            "cuda_initialization_allowed": False,
            "gpu_allowed": False,
        }
        or cpu_runtime.get("inference_thread_count") != backend["cpu_threads"]
        or cpu_runtime.get("thread_environment_sha256") != thread_environment_sha256
        or cpu_runtime.get("cpu_architecture") != platform.machine()
    ):
        raise ManifestUnavailableV1("OCR identity unavailable")
    _verify_runtime_identity_v1(identity)

    artifacts = root["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestUnavailableV1("OCR model artifacts unavailable")
    observed_paths: set[str] = set()
    artifact_hashes: set[str] = set()
    for artifact_value in artifacts:
        artifact = exact_object_v1(
            artifact_value,
            frozenset({"path", "sha256"}),
        )
        relative = artifact["path"]
        if not isinstance(relative, str) or relative in observed_paths:
            raise ManifestUnavailableV1("OCR model manifest duplicated")
        observed_paths.add(relative)
        expected_hash = require_sha256_v1(artifact["sha256"])
        artifact_hashes.add(expected_hash)
        if (
            _sha256_file_v1(_safe_artifact_path_v1(model_root, relative))
            != expected_hash
        ):
            raise ManifestUnavailableV1("OCR model artifact mismatch")

    qualification_path = _safe_artifact_path_v1(
        model_root,
        root["qualification_record_path"],
    )
    if _sha256_file_v1(qualification_path) != qualification_sha256:
        raise ManifestUnavailableV1("OCR qualification record mismatch")
    try:
        qualification = strict_json_object_v1(
            qualification_path.read_bytes(),
            maximum_bytes=MAX_QUALIFICATION_RECORD_BYTES_V1,
        )
    except (OSError, SidecarProtocolErrorV1):
        raise ManifestUnavailableV1("OCR qualification record unavailable") from None
    qualification = exact_object_v1(
        qualification,
        frozenset(
            {
                "benchmark_environment_sha256",
                "conclusion",
                "qualification_result_sha256s",
                "realtime_impact_measured",
                "schema_version",
                "selected_backend",
                "selected_identity_sha256",
                "selected_model",
                "selected_thread_count",
                "validated_candidate_backends",
            }
        ),
    )
    identity_bytes = canonical_json_bytes_v1(identity)
    identity_sha256 = hashlib.sha256(identity_bytes).hexdigest()
    result_hashes = qualification["qualification_result_sha256s"]
    candidate_backends = qualification["validated_candidate_backends"]
    if (
        qualification["schema_version"] != QUALIFICATION_RECORD_SCHEMA_VERSION_V1
        or qualification["selected_backend"] != "paddle_static"
        or qualification["selected_thread_count"] != backend["cpu_threads"]
        or qualification["selected_model"] != "PP-OCRv6-medium"
        or qualification["selected_identity_sha256"] != identity_sha256
        or qualification["conclusion"] != "qualified"
        or not isinstance(
            qualification["realtime_impact_measured"],
            bool,
        )
        or not isinstance(candidate_backends, list)
        or candidate_backends != sorted(candidate_backends)
        or len(candidate_backends) != len(set(candidate_backends))
        or "paddle_static" not in candidate_backends
        or not isinstance(result_hashes, list)
        or not result_hashes
        or len(result_hashes) > 16
        or result_hashes != sorted(result_hashes)
        or len(result_hashes) != len(set(result_hashes))
    ):
        raise ManifestUnavailableV1("OCR qualification record mismatch")
    require_sha256_v1(qualification["benchmark_environment_sha256"])
    for result_hash in result_hashes:
        require_sha256_v1(result_hash)
        if result_hash not in artifact_hashes:
            raise ManifestUnavailableV1("OCR qualification record mismatch")

    warmup = exact_object_v1(
        root["warmup"],
        frozenset({"expected_minimum_spans", "jpeg_path", "sha256"}),
    )
    expected_spans = warmup["expected_minimum_spans"]
    if (
        isinstance(expected_spans, bool)
        or not isinstance(expected_spans, int)
        or not 0 <= expected_spans <= 128
    ):
        raise ManifestUnavailableV1("OCR warmup unavailable")
    warmup_path = _safe_artifact_path_v1(
        model_root,
        warmup["jpeg_path"],
    )
    if _sha256_file_v1(warmup_path) != require_sha256_v1(warmup["sha256"]):
        raise ManifestUnavailableV1("OCR warmup unavailable")
    _verify_model_identity_binding_v1(
        identity=identity,
        backend=backend,
        model_root=model_root,
        artifact_hashes=artifact_hashes,
    )

    preprocessing_sha256 = hashlib.sha256(
        canonical_json_bytes_v1(preprocessing)
    ).hexdigest()
    return VerifiedManifestV1(
        root=model_root,
        identity=identity,
        identity_sha256=identity_sha256,
        preprocessing_identity_sha256=preprocessing_sha256,
        backend=backend,
        qualification_record_sha256=qualification_sha256,
        processing_timeout_seconds=float(timeout),
        warmup_path=warmup_path,
        warmup_expected_minimum_spans=expected_spans,
    )


__all__ = [
    "ManifestUnavailableV1",
    "QualificationCandidateManifestV1",
    "VerifiedManifestV1",
    "apply_cpu_environment_v1",
    "load_qualification_candidate_v1",
    "load_verified_manifest_v1",
    "verify_no_prohibited_loaded_libraries_v1",
]
