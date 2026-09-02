from __future__ import annotations

import hashlib
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from service.admission_notice_lite_ocr_qualification import (
    QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1,
)
from service.service_data_models.service_config_data import ServiceConfigData


class InstallFeature(str, Enum):
    ADMISSION_NOTICE_LITE = "admission_notice_lite"


CommandExecutor = Callable[[list[str], str], int]


@dataclass(frozen=True, slots=True)
class AdmissionNoticeLiteSidecarLayout:
    project: Path
    pyproject: Path
    lockfile: Path
    manifest: Path


def resolve_features(config: Mapping[str, Any]) -> frozenset[InstallFeature]:
    """Resolve explicitly supported service-level installation features."""
    default = config.get("default", {})
    if not isinstance(default, Mapping):
        default = {}
    service = default.get("service", {})
    service_config = ServiceConfigData.model_validate(service)
    if service_config.admission_notice_lite.enabled:
        return frozenset((InstallFeature.ADMISSION_NOTICE_LITE,))
    return frozenset()


def admission_notice_lite_sidecar_layout(
    project_root: Path,
) -> AdmissionNoticeLiteSidecarLayout:
    project = project_root / "services" / "admission_notice_ocr"
    return AdmissionNoticeLiteSidecarLayout(
        project=project,
        pyproject=project / "pyproject.toml",
        lockfile=project / "uv.lock",
        manifest=project / "model_manifest.json",
    )


def validate_sidecar_layout(
    project_root: Path,
) -> AdmissionNoticeLiteSidecarLayout:
    layout = admission_notice_lite_sidecar_layout(project_root)
    try:
        project_stat = layout.project.lstat()
    except OSError as exc:
        raise RuntimeError(
            "Admission Notice Lite OCR sidecar project is missing"
        ) from exc
    if not stat.S_ISDIR(project_stat.st_mode) or layout.project.is_symlink():
        raise RuntimeError("Admission Notice Lite OCR sidecar project is invalid")
    for label, path in (
        ("project metadata", layout.pyproject),
        ("lockfile", layout.lockfile),
        ("production model manifest", layout.manifest),
    ):
        try:
            path_stat = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"Admission Notice Lite OCR {label} is missing") from exc
        if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
            raise RuntimeError(f"Admission Notice Lite OCR {label} is invalid")
    return layout


def sidecar_sync_command(layout: AdmissionNoticeLiteSidecarLayout) -> list[str]:
    return [
        "uv",
        "sync",
        "--locked",
        "--project",
        str(layout.project),
        "--no-dev",
        "--python",
        "3.11",
    ]


def sidecar_model_command(
    layout: AdmissionNoticeLiteSidecarLayout,
    *,
    verify_only: bool,
) -> list[str]:
    command = [
        "uv",
        "run",
        "--locked",
        "--project",
        str(layout.project),
        "--no-dev",
        "python",
        "-m",
        "admission_notice_ocr.provision_models",
    ]
    if verify_only:
        command.append("--verify-only")
    else:
        command.extend(("--thread-count", "2"))
    return command


def approved_manifest_is_current(
    layout: AdmissionNoticeLiteSidecarLayout,
) -> bool:
    try:
        actual = hashlib.sha256(layout.manifest.read_bytes()).hexdigest()
    except OSError:
        return False
    return actual == QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1


def prepare_admission_notice_lite_models(
    layout: AdmissionNoticeLiteSidecarLayout,
    execute: CommandExecutor,
    *,
    dry_run: bool = False,
) -> bool:
    """Verify existing models, provisioning with the sidecar tool only if needed."""
    if not approved_manifest_is_current(layout):
        print("Error: Admission Notice Lite OCR production manifest is not approved.")
        return False

    verify_command = sidecar_model_command(layout, verify_only=True)
    provision_command = sidecar_model_command(layout, verify_only=False)
    if dry_run:
        return (
            execute(
                provision_command,
                "Provisioning Admission Notice Lite PP-OCRv6 models if needed",
            )
            == 0
            and execute(
                verify_command,
                "Verifying Admission Notice Lite OCR model manifest",
            )
            == 0
        )

    if (
        execute(
            verify_command,
            "Checking existing Admission Notice Lite OCR models",
        )
        == 0
    ):
        return True

    if (
        execute(
            provision_command,
            "Provisioning Admission Notice Lite PP-OCRv6 models",
        )
        != 0
    ):
        return False
    if not approved_manifest_is_current(layout):
        print(
            "Error: Admission Notice Lite OCR provisioner changed the approved manifest."
        )
        return False
    return (
        execute(
            verify_command,
            "Verifying Admission Notice Lite OCR model manifest",
        )
        == 0
    )
