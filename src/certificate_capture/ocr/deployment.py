"""Strict local deployment configuration for the private OCR owner."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from certificate_capture.contracts.ocr import decode_strict_ocr_json_object_v1
from certificate_capture.ocr.client import (
    OcrDeploymentConfigV1,
    OcrSocketPolicyV1,
    OcrTimeoutsV1,
)
from certificate_capture.ocr.identity import inference_identity_from_object_v1

OCR_DEPLOYMENT_MANIFEST_ENV_V1 = "OPENAVATAR_CERTIFICATE_OCR_DEPLOYMENT_MANIFEST"
OCR_DEPLOYMENT_MANIFEST_SCHEMA_VERSION_V1 = "oac.certificate-ocr-deployment.v1"
MAX_OCR_DEPLOYMENT_MANIFEST_BYTES_V1 = 64 * 1024


class OcrDeploymentUnavailableV1(RuntimeError):
    """Payload-free, fail-closed deployment configuration error."""

    def __init__(self) -> None:
        super().__init__("OCR_DEPLOYMENT_UNAVAILABLE")


def _exact_object_v1(
    value: object,
    fields: frozenset[str],
) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise OcrDeploymentUnavailableV1
    return value


def _read_bounded_regular_file_v1(path: Path) -> bytes:
    normalized = Path(path)
    if not normalized.is_absolute():
        raise OcrDeploymentUnavailableV1
    try:
        details = os.lstat(normalized)
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o022:
            raise OcrDeploymentUnavailableV1
        with normalized.open("rb") as stream:
            payload = stream.read(MAX_OCR_DEPLOYMENT_MANIFEST_BYTES_V1 + 1)
    except OcrDeploymentUnavailableV1:
        raise
    except OSError:
        raise OcrDeploymentUnavailableV1 from None
    if not payload or len(payload) > MAX_OCR_DEPLOYMENT_MANIFEST_BYTES_V1:
        raise OcrDeploymentUnavailableV1
    return payload


def _require_cpu_only_identity_v1(identity) -> None:
    execution = identity.execution
    accelerator = execution.accelerator_policy
    if (
        execution.device != "cpu"
        or execution.automatic_device_selection
        or execution.automatic_backend_selection
        or execution.automatic_backend_fallback
        or execution.hpi_auto_config
        or accelerator.gpu_allowed
        or accelerator.cuda_initialization_allowed
        or accelerator.cuda_allocation_allowed
    ):
        raise OcrDeploymentUnavailableV1


def load_ocr_deployment_config_v1(
    manifest_path: Path,
) -> OcrDeploymentConfigV1:
    """Load one reviewed local identity; never resolve models or use network."""

    try:
        root = _exact_object_v1(
            decode_strict_ocr_json_object_v1(
                _read_bounded_regular_file_v1(manifest_path),
                maximum_bytes=MAX_OCR_DEPLOYMENT_MANIFEST_BYTES_V1,
            ),
            frozenset(
                {
                    "expected_identity",
                    "expected_qualification_record_sha256",
                    "schema_version",
                    "socket",
                    "timeouts",
                }
            ),
        )
        if root["schema_version"] != OCR_DEPLOYMENT_MANIFEST_SCHEMA_VERSION_V1:
            raise OcrDeploymentUnavailableV1
        socket_value = _exact_object_v1(
            root["socket"],
            frozenset(
                {
                    "expected_gid",
                    "expected_uid",
                    "maximum_permissions",
                    "path",
                }
            ),
        )
        timeout_value = _exact_object_v1(
            root["timeouts"],
            frozenset(
                {
                    "connect_seconds",
                    "processing_seconds",
                    "response_read_seconds",
                    "write_seconds",
                }
            ),
        )
        identity = inference_identity_from_object_v1(root["expected_identity"])
        _require_cpu_only_identity_v1(identity)
        return OcrDeploymentConfigV1(
            socket_policy=OcrSocketPolicyV1(
                path=Path(socket_value["path"]),
                expected_uid=socket_value["expected_uid"],
                expected_gid=socket_value["expected_gid"],
                maximum_permissions=socket_value["maximum_permissions"],
            ),
            expected_identity=identity,
            expected_qualification_record_sha256=(
                root["expected_qualification_record_sha256"]
            ),
            timeouts=OcrTimeoutsV1(
                connect_seconds=timeout_value["connect_seconds"],
                write_seconds=timeout_value["write_seconds"],
                processing_seconds=timeout_value["processing_seconds"],
                response_read_seconds=(timeout_value["response_read_seconds"]),
            ),
        )
    except OcrDeploymentUnavailableV1:
        raise
    except (TypeError, ValueError):
        raise OcrDeploymentUnavailableV1 from None


__all__ = [
    "MAX_OCR_DEPLOYMENT_MANIFEST_BYTES_V1",
    "OCR_DEPLOYMENT_MANIFEST_ENV_V1",
    "OCR_DEPLOYMENT_MANIFEST_SCHEMA_VERSION_V1",
    "OcrDeploymentUnavailableV1",
    "load_ocr_deployment_config_v1",
]
