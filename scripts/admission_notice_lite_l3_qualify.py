#!/usr/bin/env python3
"""Combine sidecar evidence with real main-environment AF_UNIX integration."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_SOURCE = PROJECT_ROOT / "src"
if str(MAIN_SOURCE) not in sys.path:
    sys.path.insert(0, str(MAIN_SOURCE))

from service.admission_notice_lite_contracts import (  # noqa: E402
    OcrBatchLiteV1,
    OcrRuntimeIdentityLiteV1,
    RecognitionStateLiteV1,
)
from service.admission_notice_lite_ingestion import (  # noqa: E402
    _validate_admission_jpeg,
)
from service.admission_notice_lite_ocr import (  # noqa: E402
    QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1,
    AdmissionNoticeOcrClientLiteV1,
    AdmissionNoticeOcrProcessorLiteV1,
)
from service.admission_notice_lite_service import (  # noqa: E402
    AdmissionNoticeLiteService,
)
from service.service_data_models.admission_notice_lite_config import (  # noqa: E402
    AdmissionNoticeLiteFeatureConfigV1,
)

FINAL_REPORT_SCHEMA_VERSION = 2
SIDECAR_REPORT_SCHEMA_VERSION = 1
SIDECAR_STARTUP_TIMEOUT_SECONDS = 90.0
INTEGRATION_TIMEOUT_SECONDS = 60.0
MAX_SIDECAR_REPORT_BYTES = 1024 * 1024
_SHA256_LENGTH = 64
_EXPECTED_PADDLE_CPU_WHEEL_SHA256 = (
    "a4f2e0595e827c179b4fff4278fb41a24f4abe5927ffd5efb1ace26a916145f2"
)
_EXPECTED_PADDLE_CPU_WHEEL_SIZE = 193_703_893
_SIDECAR_SOURCE_PATHS = (
    "services/admission_notice_ocr/model_manifest.json",
    "services/admission_notice_ocr/pyproject.toml",
    "services/admission_notice_ocr/uv.lock",
    "services/admission_notice_ocr/src/admission_notice_ocr/__init__.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/app.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/manifest.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/pipeline.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/protocol.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/qualify.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/sidecar_qualify.py",
)
_MAIN_SOURCE_PATHS = (
    "scripts/admission_notice_lite_l3_qualify.py",
    "src/service/__init__.py",
    "src/service/admission_notice_lite_contracts.py",
    "src/service/admission_notice_lite_ingestion.py",
    "src/service/admission_notice_lite_ocr.py",
    "src/service/admission_notice_lite_ocr_qualification.py",
    "src/service/admission_notice_lite_service.py",
    "src/service/service_data_models/__init__.py",
    "src/service/service_data_models/admission_notice_lite_config.py",
)
_SYNTHETIC_FIXTURE_LINES = (
    (
        "中文测试 简体文本",
        "OpenAvatarChat 2026",
        "编号 A-123 (3+2) +",
    ),
    (
        "受控中文印刷样例",
        "CPU OCR Runtime 67890",
        "括号（测试） + punctuation",
    ),
    (
        "多文本框识别测试",
        "Latin ABC xyz 2468",
        "符号：，。！？ (1+2)",
    ),
)


class QualificationBlocked(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class QualificationFailed(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(slots=True)
class RunningSidecar:
    process: subprocess.Popen[bytes]
    socket_path: Path
    ready: dict[str, Any]


def _read_regular_source(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _source_identity(before) != _source_identity(after):
            raise OSError
        payload = b"".join(chunks)
        if len(payload) != after.st_size:
            raise OSError
        return payload
    finally:
        os.close(descriptor)


def _source_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _hash_paths(relative_paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    try:
        for relative_path in relative_paths:
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(_read_regular_source(PROJECT_ROOT / relative_path))
            digest.update(b"\0")
    except OSError:
        raise QualificationBlocked("QUALIFICATION_SOURCE_UNAVAILABLE") from None
    return digest.hexdigest()


def _sidecar_source_sha256() -> str:
    relative_to_service = tuple(
        path.removeprefix("services/admission_notice_ocr/")
        for path in _SIDECAR_SOURCE_PATHS
    )
    digest = hashlib.sha256()
    service_root = PROJECT_ROOT / "services" / "admission_notice_ocr"
    try:
        for relative_path in relative_to_service:
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(_read_regular_source(service_root / relative_path))
            digest.update(b"\0")
    except OSError:
        raise QualificationBlocked("QUALIFICATION_SOURCE_UNAVAILABLE") from None
    return digest.hexdigest()


def _qualification_source_sha256() -> str:
    return _hash_paths(_SIDECAR_SOURCE_PATHS + _MAIN_SOURCE_PATHS)


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


def _load_json_object(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise OSError
        raw = path.read_bytes()
    except OSError:
        raise QualificationBlocked("SIDECAR_EVIDENCE_UNAVAILABLE") from None
    try:
        if not 1 <= len(raw) <= maximum_bytes:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise QualificationBlocked("SIDECAR_EVIDENCE_INVALID") from None
    if type(value) is not dict:
        raise QualificationBlocked("SIDECAR_EVIDENCE_INVALID")
    return value


def _valid_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _finite_nonnegative(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and value >= 0
    )


def _valid_percentiles(value: Any) -> bool:
    return (
        type(value) is dict
        and type(value.get("samples")) is int
        and value["samples"] >= 5
        and _finite_nonnegative(value.get("p50_ms"))
        and _finite_nonnegative(value.get("p95_ms"))
    )


def _valid_candidate(candidate: dict[str, Any]) -> bool:
    functional = candidate.get("functional")
    determinism = candidate.get("determinism")
    loaded_libraries = candidate.get("loaded_libraries")
    return (
        candidate.get("result") == "PASS"
        and candidate.get("thread_count") in {1, 2, 4, 6, 8}
        and candidate.get("device") == "cpu"
        and candidate.get("compiled_with_cuda") is False
        and candidate.get("error_count") == 0
        and candidate.get("cache_environment_match") is True
        and candidate.get("thread_environment_match") is True
        and candidate.get("isolated_cache_model_file_count") == 0
        and candidate.get("tcp_listener_count") in {0, None}
        and all(
            _finite_nonnegative(candidate.get(key))
            for key in (
                "cold_startup_ms",
                "cpu_percent",
                "first_inference_ms",
                "model_init_ms",
                "rss_mb",
            )
        )
        and all(
            _valid_percentiles(candidate.get(key))
            for key in ("one_frame", "two_frame", "three_frame")
        )
        and type(functional) is dict
        and all(
            functional.get(key) is True
            for key in ("chinese", "digits", "latin", "polygon", "score")
        )
        and type(functional.get("span_count")) is int
        and functional["span_count"] > 0
        and type(determinism) is dict
        and all(
            determinism.get(key) is True
            for key in (
                "polygon_shape_stable",
                "score_shape_stable",
                "span_count_stable",
                "span_text_stable",
            )
        )
        and _finite_nonnegative(determinism.get("polygon_max_abs_delta"))
        and _finite_nonnegative(determinism.get("score_max_abs_delta"))
        and type(loaded_libraries) is dict
        and loaded_libraries.get("forbidden_loaded") == []
    )


def _valid_pass_sidecar_evidence(value: dict[str, Any]) -> bool:
    candidates = value.get("thread_candidates")
    package_versions = value.get("package_versions")
    package_audit = value.get("package_audit")
    clean_start = value.get("clean_start_offline")
    gpu_observation = value.get("gpu_observation")
    if (
        value.get("backend") != "paddle_static"
        or value.get("device") != "cpu"
        or not _valid_sha256(value.get("model_manifest_sha256"))
        or type(candidates) is not list
        or len(candidates) != 5
        or any(type(candidate) is not dict for candidate in candidates)
        or {candidate.get("thread_count") for candidate in candidates}
        != {1, 2, 4, 6, 8}
        or any(not _valid_candidate(candidate) for candidate in candidates)
        or any(
            candidate.get("sidecar_source_sha256") != value.get("sidecar_source_sha256")
            for candidate in candidates
        )
        or value.get("selected_thread_count") not in {1, 2, 4, 6, 8}
        or value.get("manifest_thread_count") not in {1, 2, 4, 6, 8}
        or type(value.get("selected")) is not dict
        or value["selected"]
        != next(
            candidate
            for candidate in candidates
            if candidate["thread_count"] == value["selected_thread_count"]
        )
        or value["selected"]["first_inference_ms"] >= 30_000
        or value["selected"]["three_frame"]["p95_ms"] >= 30_000
        or value["selected"]["determinism"]["polygon_max_abs_delta"] != 0.0
        or value["selected"]["determinism"]["score_max_abs_delta"] != 0.0
        or package_versions
        != {
            "paddleocr": "3.7.0",
            "paddlepaddle": "3.3.0",
            "paddlex": "3.7.2",
        }
        or type(package_audit) is not dict
        or package_audit.get("forbidden_packages") != []
        or package_audit.get("paddle_package") != "paddlepaddle"
        or package_audit.get("paddle_cpu_wheel_lock_enforced") is not True
        or package_audit.get("paddle_cpu_wheel_sha256")
        != _EXPECTED_PADDLE_CPU_WHEEL_SHA256
        or package_audit.get("paddle_cpu_wheel_size") != _EXPECTED_PADDLE_CPU_WHEEL_SIZE
        or not (
            type(package_audit.get("paddle_installed_record_files_verified")) is int
            and package_audit["paddle_installed_record_files_verified"] > 0
        )
        or type(clean_start) is not dict
        or clean_start.get("passed") is not True
        or clean_start.get("developer_cache_used") is not False
        or clean_start.get("runtime_model_download") is not False
        or type(gpu_observation) is not dict
        or gpu_observation.get("sidecar_allocations") != []
        or (
            gpu_observation.get("available") is True
            and not (
                type(gpu_observation.get("live_inference_sample_count")) is int
                and gpu_observation["live_inference_sample_count"] > 0
            )
        )
    ):
        return False
    return True


def _load_sidecar_evidence(path: Path) -> dict[str, Any]:
    value = _load_json_object(path, maximum_bytes=MAX_SIDECAR_REPORT_BYTES)
    if (
        value.get("schema_version") != SIDECAR_REPORT_SCHEMA_VERSION
        or value.get("scope") != "sidecar_only"
        or value.get("result") not in {"PASS", "BLOCKED", "FAIL"}
        or not _valid_sha256(value.get("sidecar_source_sha256"))
    ):
        raise QualificationBlocked("SIDECAR_EVIDENCE_INVALID")
    if value["sidecar_source_sha256"] != _sidecar_source_sha256():
        raise QualificationBlocked("SIDECAR_EVIDENCE_STALE")
    if value["result"] == "PASS":
        try:
            valid_pass_evidence = _valid_pass_sidecar_evidence(value)
        except (KeyError, StopIteration, TypeError, ValueError):
            valid_pass_evidence = False
        if not valid_pass_evidence:
            raise QualificationBlocked("SIDECAR_EVIDENCE_INVALID")
    return value


def _font_path(explicit: Path | None) -> Path:
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    candidates.extend(
        (
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
            Path("/mnt/c/Windows/Fonts/msyhbd.ttc"),
            Path("/mnt/c/Windows/Fonts/simhei.ttf"),
        )
    )
    for path in candidates:
        if path.is_file() and not path.is_symlink():
            return path
    raise QualificationBlocked("CJK_FONT_UNAVAILABLE")


def _validated_frames(font_path: Path):
    try:
        font = ImageFont.truetype(str(font_path), 64)
        frames = []
        for frame_index, lines in enumerate(_SYNTHETIC_FIXTURE_LINES, start=1):
            with Image.new("RGB", (1000, 600), "white") as image:
                draw = ImageDraw.Draw(image)
                for y, text in zip((50, 220, 390), lines, strict=True):
                    draw.text((50, y), text, font=font, fill="black")
                with io.BytesIO() as output:
                    image.save(output, format="JPEG", quality=94)
                    jpeg_bytes = output.getvalue()
            frames.append(
                _validate_admission_jpeg(
                    frame_index=frame_index,
                    jpeg_bytes=jpeg_bytes,
                )
            )
    except (OSError, ValueError):
        raise QualificationBlocked("SYNTHETIC_FIXTURE_UNAVAILABLE") from None
    return tuple(frames)


def _probe_af_unix(directory: Path) -> str | None:
    probe_path = directory / "af-unix-capability.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(probe_path))
        return None
    except PermissionError:
        return "AF_UNIX_BIND_PERMISSION_DENIED"
    except OSError:
        return "AF_UNIX_BIND_UNAVAILABLE"
    finally:
        listener.close()
        try:
            node = probe_path.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        else:
            if stat.S_ISSOCK(node.st_mode) and node.st_uid == os.geteuid():
                with contextlib.suppress(OSError):
                    probe_path.unlink()


def _offline_prefix() -> tuple[str, ...]:
    command = ("unshare", "--user", "--map-root-user", "--net", "--", "true")
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise QualificationBlocked("NETWORK_ISOLATION_UNAVAILABLE") from None
    if completed.returncode != 0:
        raise QualificationBlocked("NETWORK_ISOLATION_UNAVAILABLE")
    return command[:-1]


def _sidecar_python_path() -> Path:
    return (
        PROJECT_ROOT / "services" / "admission_notice_ocr" / ".venv" / "bin" / "python"
    )


def _sidecar_command(
    *,
    sidecar_python: Path,
    socket_path: Path,
    manifest_path: Path,
    model_root: Path,
    ready_file: Path,
    offline_prefix: tuple[str, ...],
) -> tuple[str, ...]:
    return (
        *offline_prefix,
        str(sidecar_python),
        "-m",
        "admission_notice_ocr.app",
        "--socket-path",
        str(socket_path),
        "--manifest",
        str(manifest_path),
        "--models-root",
        str(model_root),
        "--ready-file",
        str(ready_file),
    )


def _sidecar_environment(temporary_root: Path) -> dict[str, str]:
    launch_home = temporary_root / "launch-home"
    launch_tmp = temporary_root / "launch-tmp"
    launch_xdg = temporary_root / "launch-xdg-cache"
    launch_paddle = temporary_root / "launch-paddle-home"
    for path in (launch_home, launch_tmp, launch_xdg, launch_paddle):
        path.mkdir(mode=0o700)
    return {
        "HOME": str(launch_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PADDLE_HOME": str(launch_paddle),
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": str(launch_tmp),
        "XDG_CACHE_HOME": str(launch_xdg),
    }


def _wait_ready(
    process: subprocess.Popen[bytes],
    ready_file: Path,
) -> dict[str, Any]:
    deadline = time.monotonic() + SIDECAR_STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise QualificationFailed("SIDECAR_STARTUP_FAILED")
        if ready_file.is_symlink():
            raise QualificationFailed("SIDECAR_READY_INVALID")
        if ready_file.is_file():
            try:
                raw = ready_file.read_bytes()
                if not 1 <= len(raw) <= 4096:
                    raise ValueError
                value = json.loads(
                    raw.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                raise QualificationFailed("SIDECAR_READY_INVALID") from None
            if (
                type(value) is not dict
                or set(value)
                != {
                    "cache_environment_match",
                    "model_init_ms",
                    "pid",
                    "startup_ms",
                    "thread_environment_match",
                }
                or type(value["pid"]) is not int
                or value["pid"] != process.pid
                or not _finite_nonnegative(value["model_init_ms"])
                or not _finite_nonnegative(value["startup_ms"])
                or type(value["cache_environment_match"]) is not bool
                or type(value["thread_environment_match"]) is not bool
            ):
                raise QualificationFailed("SIDECAR_READY_INVALID")
            return value
        time.sleep(0.05)
    raise QualificationFailed("SIDECAR_STARTUP_TIMEOUT")


def _start_sidecar(
    *,
    temporary_root: Path,
    sidecar_python: Path,
    manifest_path: Path,
    model_root: Path,
    offline_prefix: tuple[str, ...],
) -> RunningSidecar:
    if not sidecar_python.is_file() or not os.access(sidecar_python, os.X_OK):
        raise QualificationBlocked("SIDECAR_PYTHON_UNAVAILABLE")
    socket_path = temporary_root / "ocr.sock"
    ready_file = temporary_root / "ready.json"
    command = _sidecar_command(
        sidecar_python=sidecar_python,
        socket_path=socket_path,
        manifest_path=manifest_path,
        model_root=model_root,
        ready_file=ready_file,
        offline_prefix=offline_prefix,
    )
    try:
        process = subprocess.Popen(
            command,
            env=_sidecar_environment(temporary_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        raise QualificationBlocked("SIDECAR_PROCESS_UNAVAILABLE") from None
    try:
        ready = _wait_ready(process, ready_file)
    except Exception:
        _stop_process(process)
        raise
    return RunningSidecar(
        process=process,
        socket_path=socket_path,
        ready=ready,
    )


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


async def _event_loop_lag_during(coroutine) -> tuple[Any, float]:
    stop = asyncio.Event()
    maximum_lag = 0.0

    async def ticker() -> None:
        nonlocal maximum_lag
        expected = asyncio.get_running_loop().time() + 0.01
        while not stop.is_set():
            await asyncio.sleep(0.01)
            now = asyncio.get_running_loop().time()
            maximum_lag = max(maximum_lag, now - expected)
            expected = now + 0.01

    task = asyncio.create_task(ticker())
    try:
        result = await coroutine
    finally:
        stop.set()
        await task
    return result, maximum_lag * 1000.0


async def _wait_terminal(
    service: AdmissionNoticeLiteService,
    recognition_id: str,
) -> Any:
    deadline = time.monotonic() + INTEGRATION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        snapshot = await service.get_recognition("owner", recognition_id)
        if snapshot.state not in {
            RecognitionStateLiteV1.CREATED,
            RecognitionStateLiteV1.PROCESSING,
        }:
            return snapshot
        await asyncio.sleep(0.05)
    raise QualificationFailed("PRODUCTION_PROCESSOR_TIMEOUT")


async def _integration_observation(
    *,
    sidecar: RunningSidecar,
    frames,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    if (
        sidecar.ready.get("cache_environment_match") is not True
        or sidecar.ready.get("thread_environment_match") is not True
    ):
        raise QualificationFailed("SIDECAR_RUNTIME_CONFIGURATION_INVALID")
    expected_identity = OcrRuntimeIdentityLiteV1(
        backend=evidence["backend"],
        device=evidence["device"],
        thread_count=evidence["manifest_thread_count"],
        paddle_version=evidence["package_versions"]["paddlepaddle"],
        paddleocr_version=evidence["package_versions"]["paddleocr"],
        paddlex_version=evidence["package_versions"]["paddlex"],
        model_manifest_sha256=evidence["model_manifest_sha256"],
    )
    client = AdmissionNoticeOcrClientLiteV1(
        socket_path=str(sidecar.socket_path),
        connect_timeout_seconds=1.0,
        timeout_seconds=30.0,
    )
    identity = await client.ping()
    if identity != expected_identity:
        raise QualificationFailed("SIDECAR_RUNTIME_IDENTITY_MISMATCH")

    typed_batch, event_loop_lag_ms = await _event_loop_lag_during(
        client.recognize(frames)
    )
    if not isinstance(typed_batch, OcrBatchLiteV1) or len(typed_batch.frames) != len(
        frames
    ):
        raise QualificationFailed("OCR_BATCH_INVALID")
    span_count = sum(len(frame.spans) for frame in typed_batch.frames)
    del typed_batch

    processor = AdmissionNoticeOcrProcessorLiteV1(client=client)
    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path=str(sidecar.socket_path),
    )
    owner = object()
    service = AdmissionNoticeLiteService(
        config=config,
        session_lookup=lambda session_id: owner if session_id == "owner" else None,
        processor=processor,
    )
    try:
        permit = await service.begin_ingestion("owner")
        try:
            job = await service.create_recognition(permit, frames)
        finally:
            service.release_ingestion(permit)
        snapshot = await _wait_terminal(service, job.recognition_id)
        if snapshot.state is not RecognitionStateLiteV1.COMPLETED:
            raise QualificationFailed("PRODUCTION_PROCESSOR_PATH_FAILED")
        if service.retained_frame_count != 0:
            raise QualificationFailed("FRAME_LIFECYCLE_INVALID")
    finally:
        await service.shutdown()

    return {
        "backend_event_loop_max_lag_ms": round(event_loop_lag_ms, 3),
        "builder_gate_enabled": (QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 is not None),
        "frame_count": len(frames),
        "passed": True,
        "sidecar_model_init_ms": sidecar.ready["model_init_ms"],
        "sidecar_startup_ms": sidecar.ready["startup_ms"],
        "span_count": span_count,
        "terminal_state": snapshot.state.value,
        "typed_batch_valid": True,
    }


def _main_environment_is_paddle_free() -> bool:
    return all(
        importlib.util.find_spec(name) is None
        for name in ("paddle", "paddleocr", "paddlex")
    )


def _copy_sidecar_evidence(report: dict[str, Any], evidence: dict[str, Any]) -> None:
    for key in (
        "backend",
        "clean_start_offline",
        "device",
        "font_source",
        "gpu_observation",
        "host",
        "manifest_thread_count",
        "model_manifest_sha256",
        "package_audit",
        "package_versions",
        "python_version",
        "selected",
        "selected_thread_count",
        "sidecar_source_sha256",
        "thread_candidates",
    ):
        if key in evidence:
            report[key] = evidence[key]


def _write_report(report_path: Path, report: dict[str, Any]) -> None:
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, report_path)
    finally:
        temporary.unlink(missing_ok=True)


async def qualify_full_integration(
    *,
    sidecar_report_path: Path,
    manifest_path: Path,
    model_root: Path,
    report_path: Path,
    sidecar_python: Path,
    font_path: Path | None,
) -> dict[str, Any]:
    initial_source_sha256 = _qualification_source_sha256()
    report: dict[str, Any] = {
        "qualification_source_sha256": initial_source_sha256,
        "result": "BLOCKED",
        "schema_version": FINAL_REPORT_SCHEMA_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 is not None:
            raise QualificationFailed("PRODUCTION_GATE_MUST_REMAIN_DISABLED")
        if not _main_environment_is_paddle_free():
            raise QualificationFailed("MAIN_ENVIRONMENT_PADDLE_POLLUTED")

        evidence = _load_sidecar_evidence(sidecar_report_path)
        _copy_sidecar_evidence(report, evidence)
        if evidence["result"] == "BLOCKED":
            raise QualificationBlocked(
                evidence.get("blocker", "SIDECAR_QUALIFICATION_BLOCKED")
            )
        if evidence["result"] == "FAIL":
            raise QualificationFailed(
                evidence.get("failure", "SIDECAR_QUALIFICATION_FAILED")
            )
        if evidence["selected_thread_count"] != evidence["manifest_thread_count"]:
            raise QualificationFailed("PRODUCTION_THREAD_MISMATCH")
        try:
            manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        except OSError:
            raise QualificationBlocked("MODEL_MANIFEST_UNAVAILABLE") from None
        if manifest_sha256 != evidence["model_manifest_sha256"]:
            raise QualificationFailed("MODEL_MANIFEST_IDENTITY_MISMATCH")

        with tempfile.TemporaryDirectory(
            prefix="admission-ocr-full-qualification-"
        ) as temporary:
            temporary_root = Path(temporary)
            af_unix_blocker = _probe_af_unix(temporary_root)
            if af_unix_blocker is not None:
                raise QualificationBlocked(af_unix_blocker)
            frames = _validated_frames(_font_path(font_path))
            sidecar = _start_sidecar(
                temporary_root=temporary_root,
                sidecar_python=sidecar_python,
                manifest_path=manifest_path,
                model_root=model_root,
                offline_prefix=_offline_prefix(),
            )
            try:
                integration = await _integration_observation(
                    sidecar=sidecar,
                    frames=frames,
                    evidence=evidence,
                )
            finally:
                _stop_process(sidecar.process)

        if _qualification_source_sha256() != initial_source_sha256:
            raise QualificationFailed("QUALIFICATION_SOURCE_CHANGED")
        report.update(
            {
                "af_unix_integration": {
                    "passed": True,
                    "socket_family": "AF_UNIX",
                },
                "contention_notes": {
                    "backend_event_loop_max_lag_ms": integration[
                        "backend_event_loop_max_lag_ms"
                    ],
                    "representative_avatar_workload": "not_available",
                },
                "production_processor_path": integration,
                "result": "PASS",
            }
        )
    except QualificationBlocked as error:
        report["blocker"] = error.code
        report["blocked_gates"] = (
            [
                "real_af_unix_integration",
                "production_processor_completed_path",
            ]
            if error.code
            in {
                "AF_UNIX_BIND_PERMISSION_DENIED",
                "AF_UNIX_BIND_UNAVAILABLE",
            }
            else [
                "sidecar_qualification",
                "real_af_unix_integration",
                "production_processor_completed_path",
            ]
        )
        report["result"] = "BLOCKED"
    except QualificationFailed as error:
        report["failure"] = error.code
        report["result"] = "FAIL"
    except Exception:
        report["failure"] = "QUALIFICATION_INTERNAL_ERROR"
        report["result"] = "FAIL"
    _write_report(report_path, report)
    return report


def _parse_args() -> argparse.Namespace:
    service_root = PROJECT_ROOT / "services" / "admission_notice_ocr"
    parser = argparse.ArgumentParser(
        description="Run main-environment AF_UNIX Admission Notice Lite L3 qualification"
    )
    parser.add_argument(
        "--sidecar-report",
        type=Path,
        default=service_root / "qualification" / "sidecar-qualification.json",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=service_root / "model_manifest.json",
    )
    parser.add_argument(
        "--models-root",
        type=Path,
        default=service_root / "models",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=service_root / "qualification" / "qualification.json",
    )
    parser.add_argument("--sidecar-python", type=Path, default=_sidecar_python_path())
    parser.add_argument("--font", type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    report = asyncio.run(
        qualify_full_integration(
            sidecar_report_path=args.sidecar_report,
            manifest_path=args.manifest,
            model_root=args.models_root,
            report_path=args.report,
            sidecar_python=args.sidecar_python,
            font_path=args.font,
        )
    )
    print(report["result"])
    if report["result"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
