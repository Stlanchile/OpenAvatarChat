"""Offline, non-selecting CPU OCR qualification harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from certificate_ocr.manifest import (
    ManifestUnavailableV1,
    load_qualification_candidate_v1,
)
from certificate_ocr.pipeline import EngineSpanV1, PaddleCpuPipelineV1
from certificate_ocr.protocol import (
    MAX_OCR_JPEG_BYTES_V1,
    SidecarProtocolErrorV1,
    canonical_json_bytes_v1,
    exact_object_v1,
    require_sha256_v1,
    strict_json_object_v1,
)

FIXTURE_MANIFEST_SCHEMA_VERSION_V1 = "oac.ocr-fixtures.v1"
QUALIFICATION_RESULT_SCHEMA_VERSION_V1 = "oac.ocr-qualification-result.v1"
MAX_FIXTURE_MANIFEST_BYTES_V1 = 1024 * 1024
REQUIRED_FIXTURE_CATEGORIES_V1 = frozenset(
    {
        "chinese",
        "digits",
        "latin",
        "low_quality",
        "mixed",
        "orientation_normalized",
        "punctuation",
        "representative_1080p",
    }
)


@dataclass(frozen=True, slots=True)
class QualificationFixtureV1:
    name: str
    path: Path
    sha256: str
    width: int
    height: int
    categories: tuple[str, ...]
    expected_texts: tuple[str, ...]
    expected_polygons: tuple[
        tuple[tuple[float, float], ...],
        ...,
    ]
    polygon_tolerance: float


def _percentile_v1(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("measurement set is empty")
    ordered = sorted(values)
    rank = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[min(rank, len(ordered) - 1)]


def _fixture_path_v1(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("fixture path is invalid")
    try:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise ValueError("fixture path is invalid") from None
    if not path.is_file():
        raise ValueError("fixture path is invalid")
    return path


def _load_fixtures_v1(path: Path) -> tuple[QualificationFixtureV1, ...]:
    try:
        value = strict_json_object_v1(
            path.read_bytes(),
            maximum_bytes=MAX_FIXTURE_MANIFEST_BYTES_V1,
        )
    except (OSError, SidecarProtocolErrorV1):
        raise ValueError("fixture manifest is invalid") from None
    root = exact_object_v1(
        value,
        frozenset({"fixtures", "schema_version"}),
    )
    if root["schema_version"] != FIXTURE_MANIFEST_SCHEMA_VERSION_V1:
        raise ValueError("fixture manifest is invalid")
    values = root["fixtures"]
    if not isinstance(values, list) or not 1 <= len(values) <= 128:
        raise ValueError("fixture manifest is invalid")
    fixtures: list[QualificationFixtureV1] = []
    root_path = path.parent
    categories_seen: set[str] = set()
    names: set[str] = set()
    for value_item in values:
        item = exact_object_v1(
            value_item,
            frozenset(
                {
                    "categories",
                    "expected_polygons",
                    "expected_texts",
                    "height",
                    "name",
                    "path",
                    "polygon_tolerance",
                    "sha256",
                    "width",
                }
            ),
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or not name
            or name in names
            or len(name.encode("utf-8", errors="strict")) > 128
        ):
            raise ValueError("fixture manifest is invalid")
        names.add(name)
        fixture_path = _fixture_path_v1(root_path, item["path"])
        payload = fixture_path.read_bytes()
        if not 0 < len(payload) <= MAX_OCR_JPEG_BYTES_V1 or hashlib.sha256(
            payload
        ).hexdigest() != require_sha256_v1(item["sha256"]):
            raise ValueError("fixture manifest is invalid")
        categories = item["categories"]
        texts = item["expected_texts"]
        polygons = item["expected_polygons"]
        if (
            not isinstance(categories, list)
            or not categories
            or not all(isinstance(category, str) for category in categories)
            or len(set(categories)) != len(categories)
            or not isinstance(texts, list)
            or not all(isinstance(text, str) and text for text in texts)
            or not isinstance(polygons, list)
            or len(polygons) != len(texts)
        ):
            raise ValueError("fixture manifest is invalid")
        categories_seen.update(categories)
        parsed_polygons: list[tuple[tuple[float, float], ...]] = []
        for polygon in polygons:
            if not isinstance(polygon, list) or len(polygon) != 4:
                raise ValueError("fixture manifest is invalid")
            parsed_points: list[tuple[float, float]] = []
            for point in polygon:
                if not isinstance(point, list) or len(point) != 2:
                    raise ValueError("fixture manifest is invalid")
                x, y = point
                if (
                    isinstance(x, bool)
                    or isinstance(y, bool)
                    or not isinstance(x, (int, float))
                    or not isinstance(y, (int, float))
                    or not math.isfinite(x)
                    or not math.isfinite(y)
                    or not 0.0 <= float(x) <= 1.0
                    or not 0.0 <= float(y) <= 1.0
                ):
                    raise ValueError("fixture manifest is invalid")
                parsed_points.append((float(x), float(y)))
            parsed_polygons.append(tuple(parsed_points))
        tolerance = item["polygon_tolerance"]
        if (
            isinstance(tolerance, bool)
            or not isinstance(tolerance, (int, float))
            or not 0.0 <= float(tolerance) <= 0.25
        ):
            raise ValueError("fixture manifest is invalid")
        for dimension in (item["width"], item["height"]):
            if (
                isinstance(dimension, bool)
                or not isinstance(dimension, int)
                or dimension <= 0
            ):
                raise ValueError("fixture manifest is invalid")
        fixtures.append(
            QualificationFixtureV1(
                name=name,
                path=fixture_path,
                sha256=item["sha256"],
                width=item["width"],
                height=item["height"],
                categories=tuple(sorted(categories)),
                expected_texts=tuple(texts),
                expected_polygons=tuple(parsed_polygons),
                polygon_tolerance=float(tolerance),
            )
        )
    if not REQUIRED_FIXTURE_CATEGORIES_V1 <= categories_seen:
        raise ValueError("required OCR fixture categories are missing")
    if not any(
        fixture.width == 1920
        and fixture.height == 1080
        and "representative_1080p" in fixture.categories
        for fixture in fixtures
    ):
        raise ValueError("representative 1080p OCR fixture is missing")
    return tuple(fixtures)


def _fixture_correct_v1(
    fixture: QualificationFixtureV1,
    spans: tuple[EngineSpanV1, ...],
) -> tuple[bool, bool]:
    text_correct = tuple(span.text for span in spans) == fixture.expected_texts
    if len(spans) != len(fixture.expected_polygons):
        return text_correct, False
    geometry_correct = all(
        all(
            abs(observed_coordinate - expected_coordinate) <= fixture.polygon_tolerance
            for observed_point, expected_point in zip(
                observed.polygon,
                expected_polygon,
                strict=True,
            )
            for observed_coordinate, expected_coordinate in zip(
                observed_point,
                expected_point,
                strict=True,
            )
        )
        for observed, expected_polygon in zip(
            spans,
            fixture.expected_polygons,
            strict=True,
        )
    )
    return text_correct, geometry_correct


def _load_optional_metric_v1(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError("realtime metric input is invalid") from None
    expected = {
        "audio_deadline_misses",
        "first_text_latency_ms",
        "video_deadline_misses",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("realtime metric input is invalid")
    return value


def _realtime_delta_v1(
    baseline: dict[str, Any] | None,
    concurrent: dict[str, Any] | None,
) -> dict[str, object] | None:
    if baseline is None and concurrent is None:
        return None
    if baseline is None or concurrent is None:
        raise ValueError("both realtime metric inputs are required")
    baseline_latency = float(baseline["first_text_latency_ms"])
    concurrent_latency = float(concurrent["first_text_latency_ms"])
    if baseline_latency <= 0 or concurrent_latency <= 0:
        raise ValueError("realtime metric input is invalid")
    return {
        "audio_deadline_miss_delta": (
            int(concurrent["audio_deadline_misses"])
            - int(baseline["audio_deadline_misses"])
        ),
        "first_text_latency_change_percent": (
            (concurrent_latency - baseline_latency) / baseline_latency * 100.0
        ),
        "video_deadline_miss_delta": (
            int(concurrent["video_deadline_misses"])
            - int(baseline["video_deadline_misses"])
        ),
    }


def run_qualification_v1(
    *,
    candidate_manifest_path: Path,
    model_root: Path,
    fixture_manifest_path: Path,
    warm_runs: int,
    realtime_baseline_path: Path | None,
    realtime_concurrent_path: Path | None,
) -> dict[str, object]:
    if not 3 <= warm_runs <= 100:
        raise ValueError("warm_runs must be between 3 and 100")
    fixtures = _load_fixtures_v1(fixture_manifest_path)
    process = psutil.Process()
    process.cpu_percent(interval=None)
    start_rss = process.memory_info().rss
    startup_started = time.perf_counter()
    manifest = load_qualification_candidate_v1(
        manifest_path=candidate_manifest_path,
        model_root=model_root,
    )
    manifest_verified = time.perf_counter()
    if (
        manifest.backend["engine"] != "paddle_static"
        or manifest.backend["enable_hpi"] is not False
    ):
        raise ManifestUnavailableV1(
            "candidate adapter unavailable; no fallback permitted"
        )
    pipeline = PaddleCpuPipelineV1(manifest)
    backend_loaded = time.perf_counter()
    pipeline.warmup_v1()
    warmup_completed = time.perf_counter()

    start_cpu = process.cpu_times()
    measurement_started = time.perf_counter()
    latencies: list[float] = []
    maximum_rss = process.memory_info().rss
    maximum_threads = process.num_threads()
    repeatability_hashes: dict[str, set[str]] = {
        fixture.name: set() for fixture in fixtures
    }
    fixture_checks: dict[str, dict[str, object]] = {}
    for fixture in fixtures:
        fixture_checks[fixture.name] = {
            "categories": list(fixture.categories),
            "geometry_correct": True,
            "text_correct": True,
        }
    for _ in range(warm_runs):
        for fixture in fixtures:
            payload = fixture.path.read_bytes()
            buffer = bytearray(payload)
            del payload
            started = time.perf_counter()
            spans = pipeline.infer_v1(
                buffer,
                expected_width=fixture.width,
                expected_height=fixture.height,
            )
            latencies.append(time.perf_counter() - started)
            text_correct, geometry_correct = _fixture_correct_v1(
                fixture,
                spans,
            )
            fixture_checks[fixture.name]["text_correct"] = bool(
                fixture_checks[fixture.name]["text_correct"] and text_correct
            )
            fixture_checks[fixture.name]["geometry_correct"] = bool(
                fixture_checks[fixture.name]["geometry_correct"] and geometry_correct
            )
            repeatability_hashes[fixture.name].add(
                hashlib.sha256(
                    canonical_json_bytes_v1(
                        [
                            {
                                "polygon": span.polygon,
                                "raw_engine_score": span.raw_engine_score,
                                "text": span.text,
                            }
                            for span in spans
                        ]
                    )
                ).hexdigest()
            )
            del spans
            maximum_rss = max(maximum_rss, process.memory_info().rss)
            maximum_threads = max(maximum_threads, process.num_threads())

    sequential: dict[str, float] = {}
    for count in (1, 2, 3):
        selected = fixtures[:count]
        if len(selected) != count:
            continue
        started = time.perf_counter()
        for fixture in selected:
            buffer = bytearray(fixture.path.read_bytes())
            spans = pipeline.infer_v1(
                buffer,
                expected_width=fixture.width,
                expected_height=fixture.height,
            )
            del spans
            maximum_rss = max(maximum_rss, process.memory_info().rss)
            maximum_threads = max(
                maximum_threads,
                process.num_threads(),
            )
        sequential[str(count)] = time.perf_counter() - started

    end_cpu = process.cpu_times()
    measurement_elapsed = time.perf_counter() - measurement_started
    cpu_seconds = end_cpu.user + end_cpu.system - start_cpu.user - start_cpu.system
    all_correct = all(
        check["text_correct"] and check["geometry_correct"]
        for check in fixture_checks.values()
    )
    repeatable = all(len(hashes) == 1 for hashes in repeatability_hashes.values())
    realtime_delta = _realtime_delta_v1(
        _load_optional_metric_v1(realtime_baseline_path),
        _load_optional_metric_v1(realtime_concurrent_path),
    )
    return {
        "backend_candidate": manifest.backend["engine"],
        "benchmark_environment": {
            "cpu_count": os.cpu_count(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "configured_thread_count": manifest.backend["cpu_threads"],
        "correctness_passed": all_correct,
        "cpu_utilization_percent_of_one_core": (
            cpu_seconds / measurement_elapsed * 100.0
            if measurement_elapsed > 0
            else None
        ),
        "fixture_checks": fixture_checks,
        "identity_sha256": manifest.identity_sha256,
        "latency_seconds": {
            "p50": statistics.median(latencies),
            "p95": _percentile_v1(latencies, 0.95),
            "samples": len(latencies),
        },
        "model": "PP-OCRv6-medium",
        "observed_maximum_thread_count": maximum_threads,
        "peak_rss_bytes": maximum_rss,
        "realtime_impact": realtime_delta,
        "repeatability_passed": repeatable,
        "schema_version": QUALIFICATION_RESULT_SCHEMA_VERSION_V1,
        "sequential_frame_seconds": sequential,
        "startup_seconds": {
            "backend_load": backend_loaded - manifest_verified,
            "manifest_verification": manifest_verified - startup_started,
            "total_through_warmup": warmup_completed - startup_started,
            "warmup_inference": warmup_completed - backend_loaded,
        },
        "steady_rss_delta_bytes": process.memory_info().rss - start_rss,
        "status": ("measured-pass" if all_correct and repeatable else "measured-fail"),
    }


def _parser_v1() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure one explicit OCR candidate in a fresh process. "
            "This command records evidence and never selects a runtime backend."
        )
    )
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--model-root", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--warm-runs", type=int, default=5)
    parser.add_argument("--realtime-baseline", type=Path)
    parser.add_argument("--realtime-concurrent", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _parser_v1().parse_args()
    try:
        result = run_qualification_v1(
            candidate_manifest_path=arguments.candidate_manifest,
            model_root=arguments.model_root,
            fixture_manifest_path=arguments.fixtures,
            warm_runs=arguments.warm_runs,
            realtime_baseline_path=arguments.realtime_baseline,
            realtime_concurrent_path=arguments.realtime_concurrent,
        )
        output = canonical_json_bytes_v1(result)
        arguments.output.write_bytes(output)
    except (
        ManifestUnavailableV1,
        SidecarProtocolErrorV1,
        OSError,
        ValueError,
    ):
        print("certificate OCR qualification unavailable (INPUT_REJECTED)")
        raise SystemExit(2) from None
    raise SystemExit(0 if result["status"] == "measured-pass" else 1)


if __name__ == "__main__":
    main()
