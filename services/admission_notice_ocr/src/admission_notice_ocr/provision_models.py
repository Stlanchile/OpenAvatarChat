from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from admission_notice_ocr.manifest import (
    BACKEND,
    DEVICE,
    MANIFEST_SCHEMA_VERSION,
    MODEL_IDENTITIES,
    PACKAGE_VERSIONS,
    RUNTIME_FLAGS,
    THREAD_CANDIDATES,
    ManifestError,
    load_and_verify_manifest,
)


class ProvisioningError(Exception):
    def __init__(self) -> None:
        super().__init__("MODEL_PROVISIONING_FAILED")


PRODUCTION_THREAD_COUNT = 2


@dataclass(frozen=True, slots=True)
class SourceFile:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ModelSource:
    role: str
    repository: str
    revision: str
    files: tuple[SourceFile, ...]


MODEL_SOURCES = (
    ModelSource(
        role="text_detection",
        repository="PaddlePaddle/PP-OCRv6_medium_det",
        revision="8e0f56fb2ef86b461d99cfc7ac5c137738985f61",
        files=(
            SourceFile(
                "inference.json",
                312_150,
                "0f1a7ec35da36173529c7a60238b7f7919e3831929c3f700ad90ad4896adecd5",
            ),
            SourceFile(
                "inference.pdiparams",
                61_960_476,
                "85218d2e3d98f5a21c58b4220627be923a97aee5db3cc71f39536ab31ac53960",
            ),
            SourceFile(
                "inference.yml",
                886,
                "7298d5ead546584af2504d03355f881ac7a7bc0eb1e282d3e159277c1d0af871",
            ),
        ),
    ),
    ModelSource(
        role="text_recognition",
        repository="PaddlePaddle/PP-OCRv6_medium_rec",
        revision="e5a92bcbc5cc1b494628e458d267778f0704fd7c",
        files=(
            SourceFile(
                "inference.json",
                221_814,
                "0b2e25e990bd072f1bf77d59d67d508bce6c4bd44af6624e0fb27d6da2cd00e8",
            ),
            SourceFile(
                "inference.pdiparams",
                76_465_087,
                "1b01c79a914587933f615569e75de54f2e638ebb5d3f3b3c1b38c24ede8c7319",
            ),
            SourceFile(
                "inference.yml",
                150_580,
                "991b700facf5b50a7de193468207d5f4255b538dde0d312ae3b7c7a9b6873129",
            ),
        ),
    ),
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_source_file(path: Path, source: SourceFile) -> None:
    try:
        file_stat = path.lstat()
    except OSError:
        raise ProvisioningError() from None
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or path.is_symlink()
        or file_stat.st_size != source.size
        or _hash_file(path) != source.sha256
    ):
        raise ProvisioningError()


def _download_file(url: str, target: Path, source: SourceFile) -> None:
    digest = hashlib.sha256()
    total = 0
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "OpenAvatarChat-Admission-Notice-Lite/1"},
        )
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            target.open("xb") as destination,
        ):
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > source.size:
                    raise ProvisioningError()
                digest.update(chunk)
                destination.write(chunk)
    except ProvisioningError:
        raise
    except (OSError, urllib.error.URLError):
        raise ProvisioningError() from None
    if total != source.size or digest.hexdigest() != source.sha256:
        raise ProvisioningError()


def _verify_existing_model(directory: Path, source: ModelSource) -> None:
    try:
        directory_stat = directory.lstat()
    except OSError:
        raise ProvisioningError() from None
    if not stat.S_ISDIR(directory_stat.st_mode) or directory.is_symlink():
        raise ProvisioningError()
    actual_files = tuple(sorted(path.name for path in directory.iterdir()))
    expected_files = tuple(file.name for file in source.files)
    if actual_files != expected_files:
        raise ProvisioningError()
    for file in source.files:
        _verify_source_file(directory / file.name, file)


def _provision_model(model_root: Path, source: ModelSource) -> None:
    _, directory_name = MODEL_IDENTITIES[source.role]
    target = model_root / directory_name
    if target.exists() or target.is_symlink():
        _verify_existing_model(target, source)
        return

    try:
        with tempfile.TemporaryDirectory(
            prefix=".admission-ocr-provision-",
            dir=model_root,
        ) as temporary:
            staging = Path(temporary) / directory_name
            staging.mkdir()
            for file in source.files:
                url = (
                    f"https://huggingface.co/{source.repository}/resolve/"
                    f"{source.revision}/{file.name}"
                )
                _download_file(url, staging / file.name, file)
            _verify_existing_model(staging, source)
            staging.rename(target)
    except ProvisioningError:
        raise
    except OSError:
        raise ProvisioningError() from None


def _manifest_value(thread_count: int) -> dict:
    models = []
    for source in MODEL_SOURCES:
        model_name, directory_name = MODEL_IDENTITIES[source.role]
        models.append(
            {
                "files": [
                    {
                        "path": file.name,
                        "sha256": file.sha256,
                        "size": file.size,
                    }
                    for file in source.files
                ],
                "name": model_name,
                "relative_path": directory_name,
                "role": source.role,
            }
        )
    return {
        "backend": BACKEND,
        "device": DEVICE,
        "models": models,
        "package_versions": dict(PACKAGE_VERSIONS),
        "runtime_flags": dict(RUNTIME_FLAGS),
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "thread_count": thread_count,
    }


def _write_manifest(path: Path, thread_count: int) -> None:
    payload = (
        json.dumps(
            _manifest_value(thread_count),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        if temporary.exists() or temporary.is_symlink():
            raise ProvisioningError()
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except ProvisioningError:
        raise
    except OSError:
        raise ProvisioningError() from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def provision(
    *,
    model_root: Path,
    manifest_path: Path,
    thread_count: int,
) -> str:
    if thread_count not in THREAD_CANDIDATES:
        raise ProvisioningError()
    try:
        model_root.mkdir(parents=True, exist_ok=True)
        model_root_stat = model_root.lstat()
    except OSError:
        raise ProvisioningError() from None
    if not stat.S_ISDIR(model_root_stat.st_mode) or model_root.is_symlink():
        raise ProvisioningError()

    for source in MODEL_SOURCES:
        _provision_model(model_root, source)
    _write_manifest(manifest_path, thread_count)
    try:
        verified = load_and_verify_manifest(
            manifest_path,
            model_root,
            verify_package_versions=False,
        )
    except ManifestError:
        raise ProvisioningError() from None
    return verified.manifest_sha256


def _parse_args() -> argparse.Namespace:
    project_root = _project_root()
    parser = argparse.ArgumentParser(
        description="Provision hash-pinned PP-OCRv6 medium model files"
    )
    parser.add_argument(
        "--models-root",
        type=Path,
        default=project_root / "models",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=project_root / "model_manifest.json",
    )
    parser.add_argument(
        "--thread-count",
        type=int,
        default=PRODUCTION_THREAD_COUNT,
    )
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        if args.verify_only:
            verified = load_and_verify_manifest(
                args.manifest,
                args.models_root,
                verify_package_versions=False,
            )
            manifest_sha256 = verified.manifest_sha256
        else:
            manifest_sha256 = provision(
                model_root=args.models_root,
                manifest_path=args.manifest,
                thread_count=args.thread_count,
            )
    except (ManifestError, ProvisioningError):
        raise SystemExit("BLOCKED: MODEL_PROVISIONING_FAILED") from None
    print(f"PASS: model_manifest_sha256={manifest_sha256}")


if __name__ == "__main__":
    main()
