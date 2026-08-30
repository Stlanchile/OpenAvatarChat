from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from admission_notice_ocr.manifest import (
    BACKEND,
    DEVICE,
    PACKAGE_VERSIONS,
    PADDLE_CPU_WHEEL_SHA256,
    PADDLE_CPU_WHEEL_SIZE,
    PADDLE_CPU_WHEEL_URL,
    THREAD_CANDIDATES,
    load_and_verify_manifest,
)
from admission_notice_ocr.protocol import FrameRequest

SIDECAR_REPORT_SCHEMA_VERSION = 1
CANDIDATE_REPORT_SCHEMA_VERSION = 1
DEFAULT_SAMPLES = 8
CANDIDATE_TIMEOUT_SECONDS = 600.0
MAX_CANDIDATE_REPORT_BYTES = 128 * 1024
_PROCESS_STARTED_AT = time.monotonic()
_MODEL_ARTIFACT_FILENAMES = frozenset(
    ("inference.json", "inference.yml", "inference.pdiparams")
)
_SIDECAR_SOURCE_PATHS = (
    "model_manifest.json",
    "pyproject.toml",
    "uv.lock",
    "src/admission_notice_ocr/__init__.py",
    "src/admission_notice_ocr/app.py",
    "src/admission_notice_ocr/manifest.py",
    "src/admission_notice_ocr/pipeline.py",
    "src/admission_notice_ocr/protocol.py",
    "src/admission_notice_ocr/qualify.py",
    "src/admission_notice_ocr/sidecar_qualify.py",
)
_FORBIDDEN_LIBRARY_FRAGMENTS = ("libcuda", "libcudnn", "libnvinfer", "tensorrt")
_FORBIDDEN_PACKAGE_FRAGMENTS = (
    "paddlepaddle-gpu",
    "nvidia-",
    "tensorrt",
    "openvino",
    "onnxruntime",
    "fastapi",
    "starlette",
    "flask",
    "gradio",
    "gunicorn",
    "uvicorn",
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


def _service_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


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


def _qualification_source_sha256() -> str:
    """Hash only the isolated sidecar qualification/runtime dependency set."""

    digest = hashlib.sha256()
    service_root = _service_root()
    try:
        for relative_path in _SIDECAR_SOURCE_PATHS:
            source_path = service_root / relative_path
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(_read_regular_source(source_path))
            digest.update(b"\0")
    except OSError:
        raise QualificationBlocked("QUALIFICATION_SOURCE_UNAVAILABLE") from None
    return digest.hexdigest()


def _font_path(explicit: Path | None) -> tuple[Path, str]:
    candidates = []
    if explicit is not None:
        candidates.append((explicit, "operator-provided"))
    candidates.extend(
        (
            (
                Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
                "system-cjk",
            ),
            (Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"), "system-cjk"),
            (Path("/mnt/c/Windows/Fonts/msyhbd.ttc"), "system-cjk"),
            (Path("/mnt/c/Windows/Fonts/simhei.ttf"), "system-cjk"),
        )
    )
    for path, source in candidates:
        if path.is_file() and not path.is_symlink():
            return path, source
    raise QualificationBlocked("CJK_FONT_UNAVAILABLE")


def _qualification_frames(font_path: Path) -> tuple[FrameRequest, ...]:
    """Build sidecar-native synthetic frames without importing OpenAvatarChat."""

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
                FrameRequest(
                    frame_index=frame_index,
                    encoded_size=len(jpeg_bytes),
                    logical_width=1000,
                    logical_height=600,
                    exif_orientation=1,
                    jpeg_bytes=jpeg_bytes,
                )
            )
    except (OSError, ValueError):
        raise QualificationBlocked("SYNTHETIC_FIXTURE_UNAVAILABLE") from None
    return tuple(frames)


def _offline_prefix() -> tuple[str, ...]:
    command = ("unshare", "--user", "--map-root-user", "--net", "--", "true")
    try:
        completed = subprocess.run(
            command,
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


def _candidate_manifest(
    production_manifest: Path,
    target: Path,
    thread_count: int,
) -> None:
    try:
        if production_manifest.is_symlink():
            raise OSError
        value = json.loads(
            production_manifest.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
            parse_constant=_reject_json_constant,
        )
        value["thread_count"] = thread_count
        target.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise QualificationBlocked("CANDIDATE_MANIFEST_FAILED") from None


def _rss_mb(pid: int) -> float:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024.0, 3)
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _cpu_seconds(pid: int) -> float:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        ticks = int(fields[13]) + int(fields[14])
        return ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return 0.0


def _loaded_library_observation(pid: int) -> dict[str, Any]:
    try:
        maps = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8").lower()
    except OSError:
        return {
            "available": False,
            "bundled_openvino_loaded": [],
            "forbidden_loaded": [],
        }
    forbidden = sorted(
        fragment for fragment in _FORBIDDEN_LIBRARY_FRAGMENTS if fragment in maps
    )
    bundled_openvino = sorted(
        {
            Path(line.rsplit(maxsplit=1)[-1]).name
            for line in maps.splitlines()
            if "libopenvino" in line and "/" in line
        }
    )
    return {
        "available": True,
        "bundled_openvino_loaded": bundled_openvino,
        "forbidden_loaded": forbidden,
    }


def _tcp_listener_count(pid: int) -> int | None:
    try:
        lines = Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]
        lines += Path(f"/proc/{pid}/net/tcp6").read_text().splitlines()[1:]
    except OSError:
        return None
    return sum(len(line.split()) > 3 and line.split()[3] == "0A" for line in lines)


def _gpu_processes() -> tuple[bool, dict[int, int]]:
    if shutil.which("nvidia-smi") is None:
        return False, {}
    try:
        completed = subprocess.run(
            (
                "nvidia-smi",
                "--query-compute-apps=pid,used_memory",
                "--format=csv,noheader,nounits",
            ),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, {}
    if completed.returncode != 0:
        return False, {}
    processes = {}
    for line in completed.stdout.splitlines():
        parts = tuple(part.strip() for part in line.split(","))
        if len(parts) != 2:
            continue
        try:
            processes[int(parts[0])] = int(parts[1])
        except ValueError:
            continue
    return True, processes


def _observe_gpu_during(
    pid: int,
    operation: Callable[[], Any],
) -> tuple[Any, dict[str, Any]]:
    stop = threading.Event()
    instrumentation_available = False
    samples = 0
    sidecar_allocations: list[int] = []

    def sample() -> None:
        nonlocal instrumentation_available, samples
        while not stop.is_set():
            available, processes = _gpu_processes()
            if available:
                instrumentation_available = True
                samples += 1
                if pid in processes:
                    sidecar_allocations.append(processes[pid])
            stop.wait(timeout=0.1)

    sampler = threading.Thread(
        target=sample,
        name="admission-ocr-gpu-observer",
        daemon=True,
    )
    sampler.start()
    try:
        result = operation()
    finally:
        stop.set()
        sampler.join(timeout=11)
    if sampler.is_alive():
        raise QualificationFailed("GPU_SAMPLER_SHUTDOWN_FAILED")
    return result, {
        "instrumentation_available": instrumentation_available,
        "live_inference_samples": samples,
        "sidecar_allocation_samples_mb": sidecar_allocations,
    }


def _hash_installed_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")


def _verify_installed_paddle_record() -> int:
    try:
        distribution = importlib.metadata.distribution("paddlepaddle")
        files = distribution.files
    except importlib.metadata.PackageNotFoundError:
        return 0
    if files is None:
        return 0
    verified = 0
    try:
        for package_path in files:
            recorded_hash = package_path.hash
            if recorded_hash is None:
                continue
            if recorded_hash.mode != "sha256":
                return 0
            installed_path = Path(package_path.locate())
            if (
                not installed_path.is_file()
                or _hash_installed_file(installed_path) != recorded_hash.value
            ):
                return 0
            verified += 1
    except OSError:
        return 0
    return verified


def _paddle_wheel_lock_enforced() -> bool:
    service_root = _service_root()
    try:
        pyproject = (service_root / "pyproject.toml").read_text(encoding="utf-8")
        lock = (service_root / "uv.lock").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    requirement = f"{PADDLE_CPU_WHEEL_URL}#sha256={PADDLE_CPU_WHEEL_SHA256}"
    return (
        requirement in pyproject
        and PADDLE_CPU_WHEEL_URL in lock
        and PADDLE_CPU_WHEEL_SHA256 in lock
    )


def _package_audit() -> dict[str, Any]:
    names = sorted(
        distribution.metadata["Name"].lower()
        for distribution in importlib.metadata.distributions()
        if distribution.metadata["Name"]
    )
    forbidden = sorted(
        name
        for name in names
        if any(fragment in name for fragment in _FORBIDDEN_PACKAGE_FRAGMENTS)
    )
    installed_record_files_verified = _verify_installed_paddle_record()
    return {
        "forbidden_packages": forbidden,
        "paddle_package": (
            "paddlepaddle"
            if "paddlepaddle" in names and "paddlepaddle-gpu" not in names
            else "INVALID"
        ),
        "paddle_cpu_wheel_lock_enforced": _paddle_wheel_lock_enforced(),
        "paddle_cpu_wheel_sha256": PADDLE_CPU_WHEEL_SHA256,
        "paddle_cpu_wheel_size": PADDLE_CPU_WHEEL_SIZE,
        "paddle_installed_record_files_verified": installed_record_files_verified,
    }


def _percentiles(values: list[float]) -> dict[str, Any]:
    return {
        "samples": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(
            statistics.quantiles(values, n=20, method="inclusive")[18],
            3,
        ),
    }


def _functional_observation(batch: list[dict[str, Any]]) -> dict[str, bool | int]:
    texts = tuple(span["text"] for frame in batch for span in frame.get("spans", ()))
    joined = "\n".join(texts)
    spans = tuple(span for frame in batch for span in frame.get("spans", ()))
    return {
        "chinese": any("\u4e00" <= character <= "\u9fff" for character in joined),
        "digits": any(character.isdigit() for character in joined),
        "latin": any(
            "A" <= character <= "Z" or "a" <= character <= "z" for character in joined
        ),
        "polygon": all(len(span["polygon"]) == 4 for span in spans),
        "score": all(_finite_unit(span["score"]) for span in spans),
        "span_count": len(spans),
    }


def _finite_unit(value: float) -> bool:
    return (
        value == value
        and value not in (float("inf"), float("-inf"))
        and 0 <= value <= 1
    )


def _determinism_observation(
    batches: list[list[dict[str, Any]]],
) -> dict[str, bool | float]:
    text_signatures = []
    polygon_signatures = []
    score_signatures = []
    for batch in batches:
        spans = tuple(span for frame in batch for span in frame["spans"])
        text_signatures.append(tuple(span["text"] for span in spans))
        polygon_signatures.append(
            tuple(
                coordinate
                for span in spans
                for point in span["polygon"]
                for coordinate in point
            )
        )
        score_signatures.append(tuple(span["score"] for span in spans))

    polygon_shapes_stable = len({len(value) for value in polygon_signatures}) == 1
    score_shapes_stable = len({len(value) for value in score_signatures}) == 1
    polygon_max_abs_delta = 0.0
    score_max_abs_delta = 0.0
    if polygon_shapes_stable and polygon_signatures:
        baseline = polygon_signatures[0]
        polygon_max_abs_delta = max(
            (
                abs(observed - expected)
                for signature in polygon_signatures[1:]
                for observed, expected in zip(signature, baseline, strict=True)
            ),
            default=0.0,
        )
    if score_shapes_stable and score_signatures:
        baseline = score_signatures[0]
        score_max_abs_delta = max(
            (
                abs(observed - expected)
                for signature in score_signatures[1:]
                for observed, expected in zip(signature, baseline, strict=True)
            ),
            default=0.0,
        )
    return {
        "polygon_max_abs_delta": round(polygon_max_abs_delta, 9),
        "polygon_shape_stable": polygon_shapes_stable,
        "score_max_abs_delta": round(score_max_abs_delta, 9),
        "score_shape_stable": score_shapes_stable,
        "span_count_stable": len({len(value) for value in text_signatures}) == 1,
        "span_text_stable": len(set(text_signatures)) == 1,
    }


def _cache_observation(runtime_cache: Path) -> tuple[int, int]:
    files = tuple(path for path in runtime_cache.rglob("*") if path.is_file())
    model_files = tuple(
        path for path in files if path.name in _MODEL_ARTIFACT_FILENAMES
    )
    return len(files), len(model_files)


def _write_report(report_path: Path, report: dict[str, Any]) -> None:
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, report_path)
    finally:
        temporary.unlink(missing_ok=True)


def _measure_candidate_worker(
    *,
    manifest_path: Path,
    model_root: Path,
    output_path: Path,
    font_path: Path | None,
    samples: int,
) -> dict[str, Any]:
    initial_source_sha256 = _qualification_source_sha256()
    report: dict[str, Any] = {
        "result": "FAIL",
        "schema_version": CANDIDATE_REPORT_SCHEMA_VERSION,
        "sidecar_source_sha256": initial_source_sha256,
    }
    try:
        verified = load_and_verify_manifest(manifest_path, model_root)
        runtime_cache = output_path.parent / "runtime-cache"
        from admission_notice_ocr.app import (
            _configure_cpu_runtime,
            _runtime_environment,
        )

        _configure_cpu_runtime(verified.thread_count, runtime_cache)
        cache_environment_match = all(
            os.environ.get(name) == expected
            for name, expected in _runtime_environment(runtime_cache).items()
        )
        if not cache_environment_match:
            raise QualificationFailed("CACHE_CONFIGURATION_INVALID")
        font, _ = _font_path(font_path)
        frames = _qualification_frames(font)

        model_started_at = time.monotonic()
        from admission_notice_ocr.pipeline import PaddleOcrPipeline

        pipeline = PaddleOcrPipeline(verified)
        model_init_ms = (time.monotonic() - model_started_at) * 1000.0
        cold_startup_ms = (time.monotonic() - _PROCESS_STARTED_AT) * 1000.0

        import paddle

        if paddle.device.is_compiled_with_cuda() or paddle.device.get_device() != "cpu":
            raise QualificationFailed("CPU_RUNTIME_INVALID")

        first_started_at = time.monotonic()
        first_batch = pipeline.recognize(frames[:1])
        first_inference_ms = (time.monotonic() - first_started_at) * 1000.0
        functional = _functional_observation(first_batch)
        if (
            not functional["chinese"]
            or not functional["latin"]
            or not functional["digits"]
            or not functional["polygon"]
            or not functional["score"]
            or not functional["span_count"]
        ):
            raise QualificationFailed("CONTROLLED_FIXTURE_RECOGNITION_FAILED")

        timings: dict[int, list[float]] = {1: [], 2: [], 3: []}
        determinism_batches: list[list[dict[str, Any]]] = []
        errors = 0
        maximum_rss = _rss_mb(os.getpid())
        cpu_before = _cpu_seconds(os.getpid())
        wall_before = time.monotonic()
        for frame_count in (1, 2, 3):
            for _ in range(samples):
                started_at = time.monotonic()
                try:
                    batch = pipeline.recognize(frames[:frame_count])
                except Exception:
                    errors += 1
                    continue
                timings[frame_count].append((time.monotonic() - started_at) * 1000.0)
                maximum_rss = max(maximum_rss, _rss_mb(os.getpid()))
                if frame_count == 1:
                    determinism_batches.append(batch)
        wall_seconds = time.monotonic() - wall_before
        cpu_seconds = _cpu_seconds(os.getpid()) - cpu_before
        if errors or any(len(values) != samples for values in timings.values()):
            raise QualificationFailed("WARMED_INFERENCE_FAILED")

        _, gpu_live_observation = _observe_gpu_during(
            os.getpid(),
            lambda: pipeline.recognize(frames[:3]),
        )
        loaded_libraries = _loaded_library_observation(os.getpid())
        if loaded_libraries["forbidden_loaded"]:
            raise QualificationFailed("GPU_LIBRARY_LOADED")
        cache_file_count, cache_model_file_count = _cache_observation(runtime_cache)
        if cache_model_file_count:
            raise QualificationFailed("RUNTIME_MODEL_CACHE_USED")

        thread_environment_match = all(
            os.environ.get(name) == str(verified.thread_count)
            for name in (
                "OMP_NUM_THREADS",
                "MKL_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
                "FLAGS_paddle_num_threads",
            )
        )
        if not thread_environment_match:
            raise QualificationFailed("THREAD_CONFIGURATION_INVALID")

        report.update(
            {
                "cache_environment_match": cache_environment_match,
                "cold_startup_ms": round(cold_startup_ms, 3),
                "compiled_with_cuda": False,
                "cpu_percent": round(
                    (cpu_seconds / wall_seconds * 100.0) if wall_seconds else 0.0,
                    3,
                ),
                "determinism": _determinism_observation(determinism_batches),
                "device": paddle.device.get_device(),
                "error_count": errors,
                "first_inference_ms": round(first_inference_ms, 3),
                "functional": functional,
                "gpu_live_observation": gpu_live_observation,
                "isolated_cache_file_count": cache_file_count,
                "isolated_cache_model_file_count": cache_model_file_count,
                "loaded_libraries": loaded_libraries,
                "model_init_ms": round(model_init_ms, 3),
                "one_frame": _percentiles(timings[1]),
                "result": "PASS",
                "rss_mb": round(maximum_rss, 3),
                "tcp_listener_count": _tcp_listener_count(os.getpid()),
                "thread_count": verified.thread_count,
                "thread_environment_match": thread_environment_match,
                "three_frame": _percentiles(timings[3]),
                "two_frame": _percentiles(timings[2]),
            }
        )
        if report["tcp_listener_count"] not in (0, None):
            raise QualificationFailed("TCP_LISTENER_OBSERVED")
        if _qualification_source_sha256() != initial_source_sha256:
            raise QualificationFailed("QUALIFICATION_SOURCE_CHANGED")
    except QualificationBlocked as error:
        report["blocker"] = error.code
        report["result"] = "BLOCKED"
    except QualificationFailed as error:
        report["failure"] = error.code
        report["result"] = "FAIL"
    except Exception:
        report["failure"] = "QUALIFICATION_INTERNAL_ERROR"
        report["result"] = "FAIL"
    _write_report(output_path, report)
    return report


def _clean_worker_environment(temporary_root: Path) -> dict[str, str]:
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


def _read_candidate_report(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise OSError
        raw = path.read_bytes()
        if not 1 <= len(raw) <= MAX_CANDIDATE_REPORT_BYTES:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise QualificationBlocked("CANDIDATE_REPORT_UNAVAILABLE") from None
    if (
        type(value) is not dict
        or value.get("schema_version") != CANDIDATE_REPORT_SCHEMA_VERSION
        or value.get("result") not in {"PASS", "BLOCKED", "FAIL"}
    ):
        raise QualificationBlocked("CANDIDATE_REPORT_INVALID")
    return value


def _run_candidate(
    *,
    manifest_path: Path,
    model_root: Path,
    thread_count: int,
    offline_prefix: tuple[str, ...],
    font_path: Path | None,
    samples: int,
) -> dict[str, Any]:
    initial_source_sha256 = _qualification_source_sha256()
    with tempfile.TemporaryDirectory(
        prefix="admission-ocr-sidecar-qualification-"
    ) as temporary:
        temporary_root = Path(temporary)
        candidate_manifest = temporary_root / "manifest.json"
        candidate_report = temporary_root / "candidate.json"
        _candidate_manifest(manifest_path, candidate_manifest, thread_count)
        command = (
            *offline_prefix,
            sys.executable,
            "-m",
            "admission_notice_ocr.qualify",
            "--candidate-worker",
            "--manifest",
            str(candidate_manifest),
            "--models-root",
            str(model_root),
            "--report",
            str(candidate_report),
            "--samples",
            str(samples),
        )
        if font_path is not None:
            command += ("--font", str(font_path))
        try:
            completed = subprocess.run(
                command,
                env=_clean_worker_environment(temporary_root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=CANDIDATE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise QualificationFailed("CANDIDATE_TIMEOUT") from None
        except OSError:
            raise QualificationBlocked("CANDIDATE_PROCESS_UNAVAILABLE") from None
        candidate = _read_candidate_report(candidate_report)
        if (
            candidate.get("sidecar_source_sha256") != initial_source_sha256
            or _qualification_source_sha256() != initial_source_sha256
        ):
            raise QualificationFailed("QUALIFICATION_SOURCE_CHANGED")
        if candidate["result"] == "BLOCKED":
            raise QualificationBlocked(candidate.get("blocker", "CANDIDATE_BLOCKED"))
        if candidate["result"] == "FAIL" or completed.returncode != 0:
            raise QualificationFailed(candidate.get("failure", "CANDIDATE_FAILED"))
        return candidate


def _select_thread(
    candidate_reports: list[dict[str, Any]],
    *,
    production_thread_count: int,
) -> int:
    try:
        candidate = next(
            report
            for report in candidate_reports
            if report["thread_count"] == production_thread_count
        )
        determinism = candidate["determinism"]
        production_candidate_is_stable = (
            candidate["result"] == "PASS"
            and candidate["error_count"] == 0
            and candidate["cache_environment_match"] is True
            and candidate["isolated_cache_model_file_count"] == 0
            and candidate["thread_environment_match"] is True
            and candidate["first_inference_ms"] < 30_000
            and candidate["three_frame"]["p95_ms"] < 30_000
            and determinism["polygon_max_abs_delta"] == 0.0
            and determinism["polygon_shape_stable"] is True
            and determinism["score_max_abs_delta"] == 0.0
            and determinism["score_shape_stable"] is True
            and determinism["span_count_stable"] is True
            and determinism["span_text_stable"] is True
        )
    except (KeyError, StopIteration, TypeError):
        production_candidate_is_stable = False
    if not production_candidate_is_stable:
        raise QualificationFailed("NO_STABLE_THREAD_CANDIDATE")
    return production_thread_count


def _cpu_description() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.partition(":")[2].strip()[:160]
    except OSError:
        pass
    return platform.processor()[:160] or "unavailable"


def qualify_sidecar(
    *,
    manifest_path: Path,
    model_root: Path,
    report_path: Path,
    font_path: Path | None,
    samples: int,
) -> dict[str, Any]:
    initial_source_sha256 = _qualification_source_sha256()
    report: dict[str, Any] = {
        "result": "BLOCKED",
        "schema_version": SIDECAR_REPORT_SCHEMA_VERSION,
        "scope": "sidecar_only",
        "sidecar_source_sha256": initial_source_sha256,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        verified = load_and_verify_manifest(manifest_path, model_root)
        _, font_source = _font_path(font_path)
        offline_prefix = _offline_prefix()
        package_audit = _package_audit()
        if (
            package_audit["forbidden_packages"]
            or package_audit["paddle_package"] != "paddlepaddle"
            or not package_audit["paddle_cpu_wheel_lock_enforced"]
            or package_audit["paddle_installed_record_files_verified"] < 1
        ):
            raise QualificationFailed("DEPENDENCY_AUDIT_FAILED")

        gpu_available_before, gpu_before = _gpu_processes()
        candidate_reports = [
            _run_candidate(
                manifest_path=manifest_path,
                model_root=model_root,
                thread_count=thread_count,
                offline_prefix=offline_prefix,
                font_path=font_path,
                samples=samples,
            )
            for thread_count in sorted(THREAD_CANDIDATES)
        ]
        gpu_available_after, gpu_after = _gpu_processes()
        live_gpu_samples = sum(
            candidate["gpu_live_observation"]["live_inference_samples"]
            for candidate in candidate_reports
        )
        gpu_sidecar_allocations = [
            {
                "memory_mb": memory_mb,
                "thread_count": candidate["thread_count"],
            }
            for candidate in candidate_reports
            for memory_mb in candidate["gpu_live_observation"][
                "sidecar_allocation_samples_mb"
            ]
        ]
        cache_isolated = all(
            candidate["cache_environment_match"]
            and candidate["isolated_cache_model_file_count"] == 0
            for candidate in candidate_reports
        )
        selected_thread_count = _select_thread(
            candidate_reports,
            production_thread_count=verified.thread_count,
        )
        selected = next(
            candidate
            for candidate in candidate_reports
            if candidate["thread_count"] == selected_thread_count
        )
        if not cache_isolated:
            raise QualificationFailed("DEVELOPER_CACHE_ISOLATION_FAILED")
        if gpu_sidecar_allocations:
            raise QualificationFailed("GPU_ALLOCATION_OBSERVED")
        if (
            gpu_available_before
            or gpu_available_after
            or any(
                candidate["gpu_live_observation"]["instrumentation_available"]
                for candidate in candidate_reports
            )
        ) and live_gpu_samples < 1:
            raise QualificationFailed("GPU_LIVE_OBSERVATION_FAILED")
        if _qualification_source_sha256() != initial_source_sha256:
            raise QualificationFailed("QUALIFICATION_SOURCE_CHANGED")

        report.update(
            {
                "backend": BACKEND,
                "clean_start_offline": {
                    "developer_cache_used": not cache_isolated,
                    "mechanism": (
                        "fresh_home_and_cache_roots_with_linux_user_and_"
                        "network_namespace"
                    ),
                    "passed": cache_isolated,
                    "runtime_model_download": any(
                        candidate["isolated_cache_model_file_count"]
                        for candidate in candidate_reports
                    ),
                },
                "device": DEVICE,
                "font_source": font_source,
                "gpu_observation": {
                    "available": gpu_available_before
                    or gpu_available_after
                    or any(
                        candidate["gpu_live_observation"]["instrumentation_available"]
                        for candidate in candidate_reports
                    ),
                    "before_process_count": len(gpu_before),
                    "after_process_count": len(gpu_after),
                    "live_inference_sample_count": live_gpu_samples,
                    "sidecar_allocations": gpu_sidecar_allocations,
                },
                "host": {
                    "cpu": _cpu_description(),
                    "logical_cpu_count": os.cpu_count(),
                    "platform": "linux-x86_64",
                },
                "manifest_thread_count": verified.thread_count,
                "model_manifest_sha256": verified.manifest_sha256,
                "package_audit": package_audit,
                "package_versions": dict(PACKAGE_VERSIONS),
                "python_version": platform.python_version(),
                "result": "PASS",
                "selected": selected,
                "selected_thread_count": selected_thread_count,
                "thread_candidates": candidate_reports,
            }
        )
    except QualificationBlocked as error:
        report["blocker"] = error.code
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
    service_root = _service_root()
    parser = argparse.ArgumentParser(
        description="Run isolated sidecar-only CPU PaddleOCR qualification"
    )
    lane = parser.add_mutually_exclusive_group(required=True)
    lane.add_argument(
        "--sidecar-only",
        action="store_true",
        help="run the isolated direct-Paddle thread qualification",
    )
    lane.add_argument(
        "--candidate-worker",
        action="store_true",
        help=argparse.SUPPRESS,
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
        default=service_root / "qualification" / "sidecar-qualification.json",
    )
    parser.add_argument("--font", type=Path)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if not 5 <= args.samples <= 50:
        raise SystemExit("BLOCKED: sample count must be between 5 and 50")
    if args.candidate_worker:
        report = _measure_candidate_worker(
            manifest_path=args.manifest,
            model_root=args.models_root,
            output_path=args.report,
            font_path=args.font,
            samples=args.samples,
        )
    else:
        report = qualify_sidecar(
            manifest_path=args.manifest,
            model_root=args.models_root,
            report_path=args.report,
            font_path=args.font,
            samples=args.samples,
        )
    print(report["result"])
    if report["result"] != "PASS":
        raise SystemExit(2)
