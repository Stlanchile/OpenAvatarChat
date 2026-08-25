from __future__ import annotations

import importlib
import logging
import os
import sys
from pathlib import Path

import pytest
import yaml
from loguru import logger

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.ocr.client import (
    MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1,
    OcrDeploymentConfigV1,
    OcrSocketPolicyV1,
    OcrTimeoutsV1,
)
from certificate_capture.ocr.deployment import (
    OCR_DEPLOYMENT_MANIFEST_SCHEMA_VERSION_V1,
    OcrDeploymentUnavailableV1,
    load_ocr_deployment_config_v1,
)
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.session_info_data import SessionInfoData
from handlers.agent.memory.write_behind_queue import LocalWriteBackQueue
from handlers.agent.prompt.prompt_compiler import PromptCompiler
from tests.chat_engine.milestone_4b.test_isolation_cleanup_and_smoke import (
    ChatAgentHandler,
    ChatData,
    HandlerDataTool,
    HandlerTTS,
    PerceptionHandler,
    RtcStream,
    SessionHistory,
    SignalManager,
    StreamManager,
    WorkingMemory,
    WsClientHandler,
)
from tests.chat_engine.milestone_5a.conftest import (
    SYNTHETIC_SHA256_C_V1,
    synthetic_inference_identity_v1,
)
from tests.chat_engine.milestone_6a.conftest import (
    OCR_CANARY_V1,
    SyntheticOcrClientV1,
)

ROOT_V1 = Path(__file__).resolve().parents[3]
SIDECAR_ROOT_V1 = ROOT_V1 / "services" / "certificate_ocr"


@pytest.mark.asyncio
async def test_ocr_canary_never_reaches_generic_paths_or_logs(
    milestone_6a_harness_factory,
    caplog,
    monkeypatch,
):
    calls: list[str] = []

    def deny(name):
        def denied(*args, **kwargs):
            del args, kwargs
            calls.append(name)
            raise AssertionError(f"private OCR reached {name}")

        return denied

    instrumented = (
        (ChatData, "__init__", "ChatData"),
        (StreamManager, "create_streamer", "StreamManager"),
        (SignalManager, "enqueue_signal_v1", "SignalManager"),
        (PerceptionHandler, "handle", "Perception"),
        (ChatAgentHandler, "handle", "ChatAgent"),
        (HandlerDataTool, "handle", "HandlerDataTool"),
        (SessionHistory, "add_event", "SessionHistory"),
        (
            SessionHistory,
            "accumulate_stream_data",
            "SessionHistoryAccumulator",
        ),
        (WorkingMemory, "add_turn", "WorkingMemory"),
        (LocalWriteBackQueue, "enqueue", "writeback"),
        (PromptCompiler, "compile", "PromptCompiler"),
        (HandlerTTS, "handle", "generic TTS"),
        (WsClientHandler, "handle", "WS generic output"),
        (RtcStream, "emit", "RTC audio output"),
        (RtcStream, "video_emit", "RTC video output"),
    )
    for owner, method, name in instrumented:
        monkeypatch.setattr(owner, method, deny(name))

    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    caplog.set_level(logging.DEBUG)
    loguru_messages: list[str] = []
    loguru_sink = logger.add(lambda message: loguru_messages.append(str(message)))
    try:
        receipt = (await harness.process(grant, 1))[0]
        coordinator = harness.protocol.coordinator
        partition = coordinator._private_evidence_store_v1._partition
        assert partition is not None
        assert all(
            OCR_CANARY_V1.encode() not in record.ciphertext
            for record in partition.records.values()
        )
        assert OCR_CANARY_V1 not in repr(receipt)
        assert OCR_CANARY_V1 not in repr(coordinator)
        await coordinator.end_capture_v1(grant.capture_epoch)
    finally:
        logger.remove(loguru_sink)

    assert OCR_CANARY_V1 not in caplog.text
    assert OCR_CANARY_V1 not in "".join(loguru_messages)
    assert calls == []


def test_main_process_has_no_ocr_backend_dependency_or_import():
    root_pyproject = (ROOT_V1 / "pyproject.toml").read_text(encoding="utf-8")
    lowered = root_pyproject.casefold()
    assert "paddleocr" not in lowered
    assert "paddlepaddle" not in lowered
    assert "openvino" not in lowered

    importlib.import_module("certificate_capture.coordinator")
    importlib.import_module("certificate_capture.ocr")

    assert not {
        "paddle",
        "paddleocr",
        "paddlex",
        "openvino",
    } & set(sys.modules)


def test_reviewed_deployment_config_constructs_one_fixed_uds_client(
    tmp_path,
):
    identity = synthetic_inference_identity_v1()
    deployment = OcrDeploymentConfigV1(
        socket_policy=OcrSocketPolicyV1(
            path=tmp_path / "ocr.sock",
        ),
        expected_identity=identity,
        expected_qualification_record_sha256=(SYNTHETIC_SHA256_C_V1),
        timeouts=OcrTimeoutsV1(),
    )

    client = deployment.create_client_v1()

    assert client.expected_identity_v1 is identity
    assert client.expected_qualification_record_sha256_v1 == SYNTHETIC_SHA256_C_V1
    assert (
        client.work_fence_timeout_seconds_v1
        == deployment.timeouts.work_fence_timeout_seconds_v1
    )


def test_transport_budget_is_bounded_and_includes_cancellation():
    timeouts = OcrTimeoutsV1(
        connect_seconds=2.0,
        write_seconds=3.0,
        processing_seconds=40.0,
        response_read_seconds=4.0,
    )

    assert timeouts.work_fence_timeout_seconds_v1 == 61.0
    assert (
        timeouts.work_fence_timeout_seconds_v1 <= MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1
    )
    with pytest.raises(ValueError, match="timeout budget"):
        OcrTimeoutsV1(
            connect_seconds=300.0,
            write_seconds=300.0,
            processing_seconds=300.0,
            response_read_seconds=300.0,
        )


def _deployment_manifest_v1(tmp_path):
    identity = synthetic_inference_identity_v1()
    value = {
        "expected_identity": identity.canonical_object_v1(),
        "expected_qualification_record_sha256": SYNTHETIC_SHA256_C_V1,
        "schema_version": OCR_DEPLOYMENT_MANIFEST_SCHEMA_VERSION_V1,
        "socket": {
            "expected_gid": os.getgid(),
            "expected_uid": os.getuid(),
            "maximum_permissions": 0o660,
            "path": str(tmp_path / "ocr.sock"),
        },
        "timeouts": {
            "connect_seconds": 1.0,
            "processing_seconds": 30.0,
            "response_read_seconds": 5.0,
            "write_seconds": 5.0,
        },
    }
    manifest_path = tmp_path / "deployment.json"
    manifest_path.write_bytes(canonical_json_bytes_v1(value))
    manifest_path.chmod(0o600)
    return manifest_path, value


def test_local_deployment_manifest_is_strict_bounded_and_cpu_only(tmp_path):
    manifest_path, value = _deployment_manifest_v1(tmp_path)

    deployment = load_ocr_deployment_config_v1(manifest_path)

    assert deployment.expected_identity.execution.device == "cpu"
    assert deployment.socket_policy.path == tmp_path / "ocr.sock"
    assert deployment.timeouts.processing_seconds == 30.0

    value["unexpected"] = True
    manifest_path.write_bytes(canonical_json_bytes_v1(value))
    with pytest.raises(OcrDeploymentUnavailableV1):
        load_ocr_deployment_config_v1(manifest_path)


@pytest.mark.asyncio
async def test_secure_session_composes_reviewed_ocr_once_and_disabled_rejects(
    tmp_path,
    monkeypatch,
):
    manifest_path, _ = _deployment_manifest_v1(tmp_path)
    deployment = load_ocr_deployment_config_v1(manifest_path)
    client = SyntheticOcrClientV1()
    monkeypatch.setattr(
        OcrDeploymentConfigV1,
        "create_client_v1",
        lambda self: client,
    )
    enabled_context = SessionContext(
        SessionInfoData(session_id="m6a-owner", timestamp_base=16_000),
        session_admission=object(),
        certificate_capture_enabled_v1=True,
    )
    session = ChatSession(
        enabled_context,
        ChatEngineConfigModel(),
        _certificate_ocr_deployment_v1=deployment,
    )
    try:
        await session._bootstrap_certificate_ocr_v1(deployment)
        await session._bootstrap_certificate_ocr_v1(deployment)
        assert client.health_count == 1
        assert session._capture_coordinator_v1._ocr_service_v1 is not None
    finally:
        await session.stop_async()

    disabled_context = SessionContext(
        SessionInfoData(session_id="m6a-disabled", timestamp_base=16_000)
    )
    with pytest.raises(RuntimeError, match="deployment unavailable"):
        ChatSession(
            disabled_context,
            ChatEngineConfigModel(),
            _certificate_ocr_deployment_v1=deployment,
        )


def test_sidecar_dependency_and_container_are_literal_cpu_only():
    pyproject = (SIDECAR_ROOT_V1 / "pyproject.toml").read_text(encoding="utf-8")
    dockerfile = (SIDECAR_ROOT_V1 / "Dockerfile").read_text(encoding="utf-8")
    lowered = (pyproject + dockerfile).casefold()

    assert '"paddlepaddle==3.2.0"' in pyproject
    assert '"paddleocr==3.7.0"' in pyproject
    assert '"paddlex==3.7.0"' in pyproject
    assert "paddlepaddle-gpu" not in lowered
    assert "nvidia/cuda" not in lowered
    assert "cudnn" not in lowered
    assert "tensorrt" not in lowered
    assert "python:3.11.11-slim-bookworm" in dockerfile


def test_sidecar_compose_has_no_network_port_or_project_mount():
    compose = yaml.safe_load(
        (ROOT_V1 / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["certificate-ocr"]

    assert service["network_mode"] == "none"
    assert "ports" not in service
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    volumes = tuple(service["volumes"])
    assert all(
        ":ro" in item or item.startswith("certificate_ocr_runtime:") for item in volumes
    )
    assert not any(item.startswith(".:/") for item in volumes)
    assert service["depends_on"]["certificate-ocr-runtime-init"]["condition"] == (
        "service_completed_successfully"
    )

    initializer = compose["services"]["certificate-ocr-runtime-init"]
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["user"] == "0:0"
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN", "FOWNER"]
    assert initializer["security_opt"] == ["no-new-privileges:true"]
    assert initializer["volumes"] == ["certificate_ocr_runtime:/run/openavatarchat-ocr"]


def test_sidecar_source_has_no_remote_or_automatic_runtime_path():
    source_files = tuple((SIDECAR_ROOT_V1 / "certificate_ocr").glob("*.py"))
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_files)
    lowered = source.casefold()

    assert "start_unix_server" in source
    assert "asyncio.start_server" not in source
    assert "socket.af_inet" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "requests." not in lowered
    assert "huggingface" not in lowered
    assert 'device="cpu"' in source
    assert 'engine="paddle_static"' in source
    assert "enable_hpi=false" in lowered
    assert "automatic_backend_fallback" in source
    assert "automatic_backend_selection" in source


def test_cuda_visible_environment_cannot_select_gpu(monkeypatch):
    monkeypatch.syspath_prepend(str(SIDECAR_ROOT_V1))
    manifest = importlib.import_module("certificate_ocr.manifest")
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    monkeypatch.setenv("NVIDIA_VISIBLE_DEVICES", "all")

    environment_sha256 = manifest.apply_cpu_environment_v1(4)

    assert len(environment_sha256) == 64
    assert __import__("os").environ["CUDA_VISIBLE_DEVICES"] == ""
    assert __import__("os").environ["NVIDIA_VISIBLE_DEVICES"] == "void"
    for name in (
        "FLAGS_paddle_num_threads",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        assert __import__("os").environ[name] == "4"


def test_missing_unqualified_manifest_fails_closed(monkeypatch):
    monkeypatch.syspath_prepend(str(SIDECAR_ROOT_V1))
    manifest = importlib.import_module("certificate_ocr.manifest")

    with pytest.raises(manifest.ManifestUnavailableV1):
        manifest.load_verified_manifest_v1(
            manifest_path=(SIDECAR_ROOT_V1 / "model_manifest.example.json"),
            model_root=SIDECAR_ROOT_V1 / "models",
        )


def test_no_downstream_extractor_query_or_identifier_runtime_was_added():
    added_runtime = tuple(
        path.relative_to(ROOT_V1).as_posix()
        for base in (
            ROOT_V1 / "src" / "certificate_capture",
            SIDECAR_ROOT_V1 / "certificate_ocr",
        )
        for path in base.rglob("*.py")
        if "ocr" in path.as_posix().casefold()
    )
    joined = "\n".join(added_runtime).casefold()
    assert "admission_notice" not in joined
    assert "sanitized_admission" not in joined
    assert "field_hypothesis" not in joined
    assert "assertion" not in joined
    assert "certificate_query" not in joined
    assert "barcode" not in joined
    assert "document_number" not in joined
