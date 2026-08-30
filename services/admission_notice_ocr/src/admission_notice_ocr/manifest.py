from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

MANIFEST_SCHEMA_VERSION = 1
BACKEND = "paddle_static"
DEVICE = "cpu"
PACKAGE_VERSIONS = MappingProxyType(
    {
        "paddleocr": "3.7.0",
        "paddlepaddle": "3.3.0",
        "paddlex": "3.7.2",
    }
)
PADDLE_CPU_WHEEL_URL = (
    "https://paddle-whl.cdn.bcebos.com/stable/cpu/paddlepaddle/"
    "paddlepaddle-3.3.0-cp311-cp311-linux_x86_64.whl"
)
PADDLE_CPU_WHEEL_SHA256 = (
    "a4f2e0595e827c179b4fff4278fb41a24f4abe5927ffd5efb1ace26a916145f2"
)
PADDLE_CPU_WHEEL_SIZE = 193_703_893
THREAD_CANDIDATES = frozenset((1, 2, 4, 6, 8))
MODEL_IDENTITIES = MappingProxyType(
    {
        "text_detection": (
            "PP-OCRv6_medium_det",
            "PP-OCRv6_medium_det_infer",
        ),
        "text_recognition": (
            "PP-OCRv6_medium_rec",
            "PP-OCRv6_medium_rec_infer",
        ),
    }
)
RUNTIME_FLAGS = MappingProxyType(
    {
        "enable_hpi": False,
        "enable_mkldnn": False,
        "use_doc_orientation_classify": False,
        "use_doc_unwarping": False,
        "use_tensorrt": False,
        "use_textline_orientation": False,
    }
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_MANIFEST_BYTES = 64 * 1024


class ManifestError(Exception):
    def __init__(self) -> None:
        super().__init__("MODEL_MANIFEST_INVALID")


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    relative_path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class Model:
    role: str
    name: str
    relative_path: str
    files: tuple[ModelArtifact, ...]


@dataclass(frozen=True, slots=True)
class VerifiedManifest:
    thread_count: int
    models: tuple[Model, Model]
    model_root: Path
    manifest_sha256: str

    def model_directory(self, role: str) -> Path:
        for model in self.models:
            if model.role == role:
                return self.model_root / model.relative_path
        raise ManifestError()

    def runtime_identity(self) -> dict[str, str | int]:
        return {
            "backend": BACKEND,
            "device": DEVICE,
            "model_manifest_sha256": self.manifest_sha256,
            "paddle_version": PACKAGE_VERSIONS["paddlepaddle"],
            "paddleocr_version": PACKAGE_VERSIONS["paddleocr"],
            "paddlex_version": PACKAGE_VERSIONS["paddlex"],
            "thread_count": self.thread_count,
        }


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError


def _reject_duplicate_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _exact_keys(value: dict[str, Any], expected: set[str]) -> bool:
    return set(value) == expected and all(type(key) is str for key in value)


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        if path.is_symlink():
            raise ManifestError()
        raw = path.read_bytes()
        if not 1 <= len(raw) <= _MAX_MANIFEST_BYTES:
            raise ManifestError()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
            parse_constant=_reject_json_constant,
        )
    except ManifestError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ManifestError() from None
    if type(value) is not dict:
        raise ManifestError()
    return value, raw


def _safe_relative_file_path(value: Any) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise ManifestError()
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ManifestError()
    return value


def _parse_artifact(value: Any) -> ModelArtifact:
    if type(value) is not dict or not _exact_keys(value, {"path", "sha256", "size"}):
        raise ManifestError()
    relative_path = _safe_relative_file_path(value["path"])
    sha256 = value["sha256"]
    size = value["size"]
    if type(sha256) is not str or _SHA256_PATTERN.fullmatch(sha256) is None:
        raise ManifestError()
    if type(size) is not int or not 1 <= size <= 1024 * 1024 * 1024:
        raise ManifestError()
    return ModelArtifact(relative_path=relative_path, sha256=sha256, size=size)


def _parse_model(value: Any) -> Model:
    if type(value) is not dict or not _exact_keys(
        value, {"role", "name", "relative_path", "files"}
    ):
        raise ManifestError()
    role = value["role"]
    if type(role) is not str or role not in MODEL_IDENTITIES:
        raise ManifestError()
    name, expected_relative_path = MODEL_IDENTITIES[role]
    if value["name"] != name or value["relative_path"] != expected_relative_path:
        raise ManifestError()
    files_value = value["files"]
    if type(files_value) is not list or not files_value:
        raise ManifestError()
    files = tuple(_parse_artifact(item) for item in files_value)
    paths = tuple(artifact.relative_path for artifact in files)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ManifestError()
    return Model(
        role=role,
        name=name,
        relative_path=expected_relative_path,
        files=files,
    )


def _parse_manifest(value: dict[str, Any]) -> tuple[int, tuple[Model, Model]]:
    if not _exact_keys(
        value,
        {
            "schema_version",
            "backend",
            "device",
            "thread_count",
            "package_versions",
            "models",
            "runtime_flags",
        },
    ):
        raise ManifestError()
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != MANIFEST_SCHEMA_VERSION
        or value["backend"] != BACKEND
        or value["device"] != DEVICE
        or value["package_versions"] != PACKAGE_VERSIONS
        or value["runtime_flags"] != RUNTIME_FLAGS
    ):
        raise ManifestError()
    thread_count = value["thread_count"]
    if type(thread_count) is not int or thread_count not in THREAD_CANDIDATES:
        raise ManifestError()
    models_value = value["models"]
    if type(models_value) is not list or len(models_value) != 2:
        raise ManifestError()
    models = tuple(_parse_model(item) for item in models_value)
    if tuple(model.role for model in models) != (
        "text_detection",
        "text_recognition",
    ):
        raise ManifestError()
    return thread_count, models


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ManifestError() from None
    return digest.hexdigest()


def _verify_model_files(model_root: Path, models: tuple[Model, Model]) -> None:
    try:
        root_stat = model_root.lstat()
    except OSError:
        raise ManifestError() from None
    if not stat.S_ISDIR(root_stat.st_mode) or model_root.is_symlink():
        raise ManifestError()

    for model in models:
        directory = model_root / model.relative_path
        try:
            directory_stat = directory.lstat()
        except OSError:
            raise ManifestError() from None
        if not stat.S_ISDIR(directory_stat.st_mode) or directory.is_symlink():
            raise ManifestError()

        actual_files: list[str] = []
        for root, directories, filenames in os.walk(directory, followlinks=False):
            directories.sort()
            filenames.sort()
            root_path = Path(root)
            for directory_name in directories:
                if (root_path / directory_name).is_symlink():
                    raise ManifestError()
            for filename in filenames:
                path = root_path / filename
                if path.is_symlink() or not path.is_file():
                    raise ManifestError()
                actual_files.append(path.relative_to(directory).as_posix())
        expected_files = tuple(artifact.relative_path for artifact in model.files)
        if tuple(sorted(actual_files)) != expected_files:
            raise ManifestError()

        for artifact in model.files:
            path = directory / artifact.relative_path
            try:
                file_stat = path.stat()
            except OSError:
                raise ManifestError() from None
            if (
                file_stat.st_size != artifact.size
                or _hash_file(path) != artifact.sha256
            ):
                raise ManifestError()


def _verify_package_versions() -> None:
    for package, expected_version in PACKAGE_VERSIONS.items():
        try:
            installed_version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            raise ManifestError() from None
        if installed_version != expected_version:
            raise ManifestError()


def load_and_verify_manifest(
    manifest_path: Path,
    model_root: Path,
    *,
    verify_package_versions: bool = True,
) -> VerifiedManifest:
    value, raw = _load_json(manifest_path)
    thread_count, models = _parse_manifest(value)
    _verify_model_files(model_root, models)
    if verify_package_versions:
        _verify_package_versions()
    return VerifiedManifest(
        thread_count=thread_count,
        models=models,
        model_root=model_root,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )
