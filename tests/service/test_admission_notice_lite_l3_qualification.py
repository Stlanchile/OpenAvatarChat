from __future__ import annotations

# ruff: noqa: E402

import ast
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAIN_SOURCE = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MAIN_SOURCE) not in sys.path:
    sys.path.insert(0, str(MAIN_SOURCE))

from scripts import admission_notice_lite_l3_qualify as integration_qualify
from service.admission_notice_lite_ocr import (
    AdmissionNoticeOcrProcessorLiteV1,
    build_qualified_admission_notice_ocr_processor_lite_v1,
)
from service.admission_notice_lite_ocr_qualification import (
    QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1,
)
from service.admission_notice_lite_routes import (
    register_admission_notice_lite_routes,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

APPROVED_MODEL_MANIFEST_SHA256 = (
    "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"
)
PREAPPROVAL_QUALIFICATION_SOURCE_SHA256 = (
    "e4bea8fafc4e2e2499f2b2fa2c1c667abc15261cc6ea29c404f215841f3b0463"
)


def _pass_sidecar_evidence() -> dict:
    manifest_path = (
        PROJECT_ROOT / "services" / "admission_notice_ocr" / "model_manifest.json"
    )
    manifest_sha256 = (
        __import__("hashlib").sha256(manifest_path.read_bytes()).hexdigest()
    )
    candidates = [
        {
            "cache_environment_match": True,
            "cold_startup_ms": 1000.0,
            "compiled_with_cuda": False,
            "cpu_percent": float(thread_count * 100),
            "determinism": {
                "polygon_max_abs_delta": 0.0,
                "polygon_shape_stable": True,
                "score_max_abs_delta": 0.0,
                "score_shape_stable": True,
                "span_count_stable": True,
                "span_text_stable": True,
            },
            "device": "cpu",
            "error_count": 0,
            "first_inference_ms": 1200.0,
            "functional": {
                "chinese": True,
                "digits": True,
                "latin": True,
                "polygon": True,
                "score": True,
                "span_count": 3,
            },
            "isolated_cache_model_file_count": 0,
            "loaded_libraries": {
                "bundled_openvino_loaded": [],
                "forbidden_loaded": [],
            },
            "model_init_ms": 800.0,
            "one_frame": {"p50_ms": 1000.0, "p95_ms": 1100.0, "samples": 5},
            "result": "PASS",
            "rss_mb": 700.0,
            "tcp_listener_count": 0,
            "thread_count": thread_count,
            "thread_environment_match": True,
            "three_frame": {
                "p50_ms": 3000.0,
                "p95_ms": 3300.0,
                "samples": 5,
            },
            "two_frame": {
                "p50_ms": 2000.0,
                "p95_ms": 2200.0,
                "samples": 5,
            },
        }
        for thread_count in (1, 2, 4, 6, 8)
    ]
    return {
        "backend": "paddle_static",
        "clean_start_offline": {
            "developer_cache_used": False,
            "passed": True,
            "runtime_model_download": False,
        },
        "device": "cpu",
        "font_source": "system-cjk",
        "gpu_observation": {
            "available": False,
            "live_inference_sample_count": 0,
            "sidecar_allocations": [],
        },
        "host": {
            "cpu": "synthetic-test-host",
            "logical_cpu_count": 8,
            "platform": "linux-x86_64",
        },
        "manifest_thread_count": 2,
        "model_manifest_sha256": manifest_sha256,
        "package_audit": {
            "forbidden_packages": [],
            "paddle_cpu_wheel_lock_enforced": True,
            "paddle_cpu_wheel_sha256": (
                "a4f2e0595e827c179b4fff4278fb41a24f4abe5927ffd5efb1ace26a916145f2"
            ),
            "paddle_cpu_wheel_size": 193_703_893,
            "paddle_installed_record_files_verified": 1,
            "paddle_package": "paddlepaddle",
        },
        "package_versions": {
            "paddleocr": "3.7.0",
            "paddlepaddle": "3.3.0",
            "paddlex": "3.7.2",
        },
        "python_version": "3.11.16",
        "result": "PASS",
        "schema_version": 1,
        "scope": "sidecar_only",
        "selected": candidates[1],
        "selected_thread_count": 2,
        "sidecar_source_sha256": integration_qualify._sidecar_source_sha256(),
        "thread_candidates": candidates,
        "timestamp": "2026-08-30T00:00:00+00:00",
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_sidecar_source_import_graph_has_no_main_or_http_framework() -> None:
    sidecar_source = PROJECT_ROOT / "services" / "admission_notice_ocr" / "src"
    forbidden = ("service", "src", "chat_engine", "fastapi", "starlette")
    for path in sorted(sidecar_source.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.append(node.module)
        assert not any(
            module == prefix or module.startswith(f"{prefix}.")
            for module in imported
            for prefix in forbidden
        ), path


def test_isolated_sidecar_python_generates_frames_without_fastapi() -> None:
    sidecar_python = integration_qualify._sidecar_python_path()
    code = """
import sys
from admission_notice_ocr.qualify import _font_path, _qualification_frames
frames = _qualification_frames(_font_path(None)[0])
assert len(frames) == 3
assert "fastapi" not in sys.modules
assert not any(name.startswith("service") for name in sys.modules)
print("PASS")
"""
    completed = subprocess.run(
        (str(sidecar_python), "-c", code),
        env={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == "PASS"


def test_main_and_sidecar_agree_on_sidecar_source_hash() -> None:
    completed = subprocess.run(
        (
            str(integration_qualify._sidecar_python_path()),
            "-c",
            (
                "from admission_notice_ocr.qualify import "
                "_qualification_source_sha256; "
                "print(_qualification_source_sha256())"
            ),
        ),
        env={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == integration_qualify._sidecar_source_sha256()


def test_sidecar_lock_excludes_http_server_dependencies() -> None:
    lock = (PROJECT_ROOT / "services" / "admission_notice_ocr" / "uv.lock").read_text(
        encoding="utf-8"
    )
    for package in ("fastapi", "starlette", "uvicorn", "gunicorn"):
        assert f'name = "{package}"' not in lock.lower()


def test_main_controller_does_not_import_or_require_paddle() -> None:
    source = (
        PROJECT_ROOT / "scripts" / "admission_notice_lite_l3_qualify.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.append(node.module)
    assert not any(
        module == package or module.startswith(f"{package}.")
        for module in imported
        for package in ("paddle", "paddleocr", "paddlex")
    )
    assert integration_qualify._main_environment_is_paddle_free()


def test_sidecar_pass_requires_exact_locked_cpu_wheel_identity() -> None:
    evidence = _pass_sidecar_evidence()
    evidence["package_audit"]["paddle_cpu_wheel_sha256"] = "0" * 64
    assert not integration_qualify._valid_pass_sidecar_evidence(evidence)


def test_sidecar_pass_requires_live_samples_when_gpu_instrumentation_exists() -> None:
    evidence = _pass_sidecar_evidence()
    evidence["gpu_observation"]["available"] = True
    evidence["gpu_observation"]["live_inference_sample_count"] = 0
    assert not integration_qualify._valid_pass_sidecar_evidence(evidence)


def test_sidecar_command_and_environment_are_explicit_and_sanitized(
    tmp_path: Path,
) -> None:
    sidecar_python = integration_qualify._sidecar_python_path()
    command = integration_qualify._sidecar_command(
        sidecar_python=sidecar_python,
        socket_path=tmp_path / "ocr.sock",
        manifest_path=tmp_path / "manifest.json",
        model_root=tmp_path / "models",
        ready_file=tmp_path / "ready.json",
        offline_prefix=("unshare", "--user", "--map-root-user", "--net", "--"),
    )
    assert command == (
        "unshare",
        "--user",
        "--map-root-user",
        "--net",
        "--",
        str(sidecar_python),
        "-m",
        "admission_notice_ocr.app",
        "--socket-path",
        str(tmp_path / "ocr.sock"),
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--models-root",
        str(tmp_path / "models"),
        "--ready-file",
        str(tmp_path / "ready.json"),
    )
    environment = integration_qualify._sidecar_environment(tmp_path)
    assert "PYTHONPATH" not in environment
    assert str(PROJECT_ROOT / "src") not in "\n".join(environment.values())
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_af_unix_permission_denial_is_a_blocked_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeniedSocket:
        def bind(self, path: str) -> None:
            del path
            raise PermissionError

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        integration_qualify.socket,
        "socket",
        lambda *args: DeniedSocket(),
    )
    assert (
        integration_qualify._probe_af_unix(tmp_path) == "AF_UNIX_BIND_PERMISSION_DENIED"
    )


def test_sidecar_startup_failure_uses_explicit_argv_without_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = {}

    class FailedProcess:
        def poll(self):
            return 1

    def fake_popen(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return FailedProcess()

    monkeypatch.setattr(integration_qualify.subprocess, "Popen", fake_popen)
    with pytest.raises(
        integration_qualify.QualificationFailed,
        match="SIDECAR_STARTUP_FAILED",
    ):
        integration_qualify._start_sidecar(
            temporary_root=tmp_path,
            sidecar_python=integration_qualify._sidecar_python_path(),
            manifest_path=tmp_path / "manifest.json",
            model_root=tmp_path / "models",
            offline_prefix=(),
        )
    assert type(observed["command"]) is tuple
    assert "shell" not in observed["kwargs"]
    assert "PYTHONPATH" not in observed["kwargs"]["env"]


def test_sidecar_startup_timeout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StalledProcess:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            del timeout
            return 0

    process = StalledProcess()
    monkeypatch.setattr(
        integration_qualify.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )
    monkeypatch.setattr(integration_qualify, "SIDECAR_STARTUP_TIMEOUT_SECONDS", 0)
    with pytest.raises(
        integration_qualify.QualificationFailed,
        match="SIDECAR_STARTUP_TIMEOUT",
    ):
        integration_qualify._start_sidecar(
            temporary_root=tmp_path,
            sidecar_python=integration_qualify._sidecar_python_path(),
            manifest_path=tmp_path / "manifest.json",
            model_root=tmp_path / "models",
            offline_prefix=(),
        )
    assert process.terminated


@pytest.mark.asyncio
async def test_sidecar_pass_without_af_unix_produces_combined_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "sidecar.json"
    report_path = tmp_path / "combined.json"
    _write_json(evidence_path, _pass_sidecar_evidence())
    monkeypatch.setattr(
        integration_qualify,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        None,
    )
    monkeypatch.setattr(
        integration_qualify,
        "_probe_af_unix",
        lambda directory: "AF_UNIX_BIND_PERMISSION_DENIED",
    )
    report = await integration_qualify.qualify_full_integration(
        sidecar_report_path=evidence_path,
        manifest_path=(
            PROJECT_ROOT / "services" / "admission_notice_ocr" / "model_manifest.json"
        ),
        model_root=PROJECT_ROOT / "services" / "admission_notice_ocr" / "models",
        report_path=report_path,
        sidecar_python=integration_qualify._sidecar_python_path(),
        font_path=None,
    )
    assert report["result"] == "BLOCKED"
    assert report["blocker"] == "AF_UNIX_BIND_PERMISSION_DENIED"
    assert report["blocked_gates"] == [
        "real_af_unix_integration",
        "production_processor_completed_path",
    ]
    assert QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256


@pytest.mark.asyncio
async def test_stale_sidecar_evidence_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integration_qualify,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        None,
    )
    evidence = _pass_sidecar_evidence()
    evidence["sidecar_source_sha256"] = "0" * 64
    evidence_path = tmp_path / "sidecar.json"
    _write_json(evidence_path, evidence)
    report = await integration_qualify.qualify_full_integration(
        sidecar_report_path=evidence_path,
        manifest_path=(
            PROJECT_ROOT / "services" / "admission_notice_ocr" / "model_manifest.json"
        ),
        model_root=PROJECT_ROOT / "services" / "admission_notice_ocr" / "models",
        report_path=tmp_path / "combined.json",
        sidecar_python=integration_qualify._sidecar_python_path(),
        font_path=None,
    )
    assert report["result"] == "BLOCKED"
    assert report["blocker"] == "SIDECAR_EVIDENCE_STALE"
    assert QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256


@pytest.mark.asyncio
async def test_malformed_sidecar_pass_evidence_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integration_qualify,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        None,
    )
    evidence = _pass_sidecar_evidence()
    evidence["thread_candidates"][0]["one_frame"]["p50_ms"] = "not-a-number"
    evidence_path = tmp_path / "sidecar.json"
    _write_json(evidence_path, evidence)
    report = await integration_qualify.qualify_full_integration(
        sidecar_report_path=evidence_path,
        manifest_path=(
            PROJECT_ROOT / "services" / "admission_notice_ocr" / "model_manifest.json"
        ),
        model_root=PROJECT_ROOT / "services" / "admission_notice_ocr" / "models",
        report_path=tmp_path / "combined.json",
        sidecar_python=integration_qualify._sidecar_python_path(),
        font_path=None,
    )
    assert report["result"] == "BLOCKED"
    assert report["blocker"] == "SIDECAR_EVIDENCE_INVALID"
    assert QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256


@pytest.mark.asyncio
async def test_combined_pass_requires_integration_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "sidecar.json"
    _write_json(evidence_path, _pass_sidecar_evidence())
    monkeypatch.setattr(
        integration_qualify,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        None,
    )

    class Process:
        def poll(self):
            return 0

    running = integration_qualify.RunningSidecar(
        process=Process(),
        socket_path=tmp_path / "ocr.sock",
        ready={},
    )
    monkeypatch.setattr(integration_qualify, "_probe_af_unix", lambda directory: None)
    monkeypatch.setattr(
        integration_qualify, "_validated_frames", lambda font: (1, 2, 3)
    )
    monkeypatch.setattr(
        integration_qualify, "_font_path", lambda font: tmp_path / "font"
    )
    monkeypatch.setattr(integration_qualify, "_offline_prefix", lambda: ())
    monkeypatch.setattr(integration_qualify, "_start_sidecar", lambda **kwargs: running)
    monkeypatch.setattr(integration_qualify, "_stop_process", lambda process: None)

    async def integration_observation(**kwargs):
        return {
            "backend_event_loop_max_lag_ms": 1.0,
            "builder_gate_enabled": False,
            "frame_count": 3,
            "passed": True,
            "span_count": 3,
            "terminal_state": "COMPLETED",
            "typed_batch_valid": True,
        }

    monkeypatch.setattr(
        integration_qualify,
        "_integration_observation",
        integration_observation,
    )
    report = await integration_qualify.qualify_full_integration(
        sidecar_report_path=evidence_path,
        manifest_path=(
            PROJECT_ROOT / "services" / "admission_notice_ocr" / "model_manifest.json"
        ),
        model_root=PROJECT_ROOT / "services" / "admission_notice_ocr" / "models",
        report_path=tmp_path / "combined.json",
        sidecar_python=integration_qualify._sidecar_python_path(),
        font_path=None,
    )
    assert report["result"] == "PASS"
    assert report["af_unix_integration"]["passed"] is True
    assert report["production_processor_path"]["terminal_state"] == "COMPLETED"
    assert QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256


def test_production_gate_contains_only_the_exact_reviewed_manifest() -> None:
    assert QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256
    gate_source = (
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ocr_qualification.py"
    ).read_text(encoding="utf-8")
    assert gate_source == (
        '"""Reviewed real-runtime qualification gate for '
        'Admission Notice Lite L3."""\n'
        "\n"
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 = (\n"
        f'    "{APPROVED_MODEL_MANIFEST_SHA256}"\n'
        ")\n"
    )
    assert gate_source.count(APPROVED_MODEL_MANIFEST_SHA256) == 1
    assert "os.environ" not in gate_source
    assert "getenv" not in gate_source
    assert "qualification.json" not in gate_source


@pytest.mark.admission_notice_ocr_integration
@pytest.mark.asyncio
async def test_real_production_builder_multipart_sidecar_integration(
    tmp_path: Path,
) -> None:
    if os.environ.get("ADMISSION_NOTICE_OCR_RUN_REAL") != "1":
        pytest.skip("set ADMISSION_NOTICE_OCR_RUN_REAL=1 for real integration")

    blocker = integration_qualify._probe_af_unix(tmp_path)
    if blocker is not None:
        pytest.skip(f"BLOCKED: {blocker}")

    service_root = PROJECT_ROOT / "services" / "admission_notice_ocr"
    report = json.loads(
        (service_root / "qualification" / "qualification.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["result"] == "PASS"
    assert (
        report["qualification_source_sha256"] == PREAPPROVAL_QUALIFICATION_SOURCE_SHA256
    )
    assert report["model_manifest_sha256"] == APPROVED_MODEL_MANIFEST_SHA256

    sidecar = integration_qualify._start_sidecar(
        temporary_root=tmp_path,
        sidecar_python=integration_qualify._sidecar_python_path(),
        manifest_path=service_root / "model_manifest.json",
        model_root=service_root / "models",
        offline_prefix=integration_qualify._offline_prefix(),
    )
    service = None
    try:
        config = AdmissionNoticeLiteFeatureConfigV1(
            enabled=True,
            ocr_socket_path=str(sidecar.socket_path),
        )
        processor = build_qualified_admission_notice_ocr_processor_lite_v1(config)
        assert isinstance(processor, AdmissionNoticeOcrProcessorLiteV1)

        class Engine:
            def __init__(self) -> None:
                self.sessions = {"owner": object()}
                self.observers = []

            def add_session_stop_observer(self, observer) -> None:
                self.observers.append(observer)

        app = FastAPI()
        service = register_admission_notice_lite_routes(
            app=app,
            chat_engine=Engine(),
            config=config,
            processor=processor,
        )
        assert service is not None
        frames = integration_qualify._validated_frames(
            integration_qualify._font_path(None)
        )
        files = [
            (
                f"frame_{frame.frame_index}",
                (
                    f"synthetic-{frame.frame_index}.jpg",
                    frame.jpeg_bytes,
                    "image/jpeg",
                ),
            )
            for frame in frames
        ]
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/sessions/owner/admission-notice/recognitions",
                files=files,
            )
            assert response.status_code == 202
            recognition_id = response.json()["recognition_id"]
            deadline = asyncio.get_running_loop().time() + 60
            while True:
                response = await client.get(
                    "/api/v1/sessions/owner/admission-notice/recognitions/"
                    f"{recognition_id}"
                )
                status = response.json()
                if status["status"] not in {"created", "processing"}:
                    break
                if asyncio.get_running_loop().time() >= deadline:
                    pytest.fail("real production recognition did not terminate")
                await asyncio.sleep(0.05)
        assert status == {
            "recognition_id": recognition_id,
            "status": "completed",
        }
        assert service.retained_frame_count == 0
    finally:
        if service is not None:
            await service.shutdown()
        integration_qualify._stop_process(sidecar.process)
