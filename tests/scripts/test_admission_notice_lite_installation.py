from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import install
from scripts import admission_notice_lite_install as lite_install
from scripts import download_models

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE_PRESET = (
    PROJECT_ROOT / "config" / "chat_with_openai_compatible_bailian_cosyvoice.yaml"
)
LITE_PRESET = (
    PROJECT_ROOT
    / "config"
    / "chat_with_openai_compatible_bailian_cosyvoice_admission_notice_lite.yaml"
)
EXPECTED_HANDLERS = {
    "CosyVoice",
    "InterruptHandler",
    "LLMOpenAICompatible",
    "LiteAvatar",
    "RtcClient",
    "SenseVoice",
    "SileroVad",
}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_lite_preset_differs_only_by_approved_feature_block() -> None:
    base = _load(BASE_PRESET)
    lite = _load(LITE_PRESET)

    assert lite["default"]["service"]["admission_notice_lite"] == {
        "enabled": True,
        "recognition_ttl_seconds": 120,
        "max_global_recognition_jobs": 1,
        "ocr_socket_path": "/run/openavatarchat-admission-lite/ocr.sock",
        "ocr_connect_timeout_seconds": 1.0,
        "ocr_timeout_seconds": 30.0,
    }
    normalized = copy.deepcopy(lite)
    normalized["default"]["service"].pop("admission_notice_lite")
    assert normalized == base


def test_feature_resolution_uses_typed_service_config() -> None:
    assert lite_install.resolve_features(_load(BASE_PRESET)) == frozenset()
    assert lite_install.resolve_features(_load(LITE_PRESET)) == frozenset(
        (lite_install.InstallFeature.ADMISSION_NOTICE_LITE,)
    )

    invalid = _load(LITE_PRESET)
    invalid["default"]["service"]["admission_notice_lite"]["enabled"] = "true"
    with pytest.raises(ValueError):
        lite_install.resolve_features(invalid)


def test_base_and_lite_presets_resolve_the_same_handlers_and_dependencies() -> None:
    base_handlers = install.get_handler_dirs_from_config(_load(BASE_PRESET))
    lite_handlers = install.get_handler_dirs_from_config(_load(LITE_PRESET))

    assert set(base_handlers) == EXPECTED_HANDLERS
    assert lite_handlers == base_handlers
    assert sorted(install.collect_and_merge_deps(lite_handlers)) == sorted(
        install.collect_and_merge_deps(base_handlers)
    )


def test_model_downloader_resolves_same_handlers_plus_lite_feature() -> None:
    assert download_models.get_handlers_from_config(BASE_PRESET) == {"liteavatar"}
    assert download_models.get_handlers_from_config(LITE_PRESET) == {"liteavatar"}
    assert download_models.get_features_from_config(BASE_PRESET) == set()
    assert download_models.get_features_from_config(LITE_PRESET) == {
        lite_install.InstallFeature.ADMISSION_NOTICE_LITE
    }


def test_lite_root_dependency_plan_contains_no_paddle_packages() -> None:
    handlers = install.get_handler_dirs_from_config(_load(LITE_PRESET))
    requirements = install.collect_and_merge_deps(handlers)
    names = {
        install.normalize_pkg_name(install.split_dep(requirement)[0].split("[")[0])
        for requirement in requirements
    }
    assert names.isdisjoint(
        {"paddle", "paddleocr", "paddlex", "paddlepaddle", "paddlepaddle-gpu"}
    )


def test_sidecar_lock_remains_cpu_only_and_root_metadata_has_no_paddle() -> None:
    lock = (PROJECT_ROOT / "services" / "admission_notice_ocr" / "uv.lock").read_text(
        encoding="utf-8"
    )
    root_metadata = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "paddleocr"' in lock
    assert 'name = "paddlex"' in lock
    assert "paddlepaddle-3.3.0-cp311-cp311-linux_x86_64.whl" in lock
    for forbidden in (
        "paddlepaddle-gpu",
        "cuda",
        "cudnn",
        "tensorrt",
        "nvidia",
        "fastapi",
        "starlette",
    ):
        assert forbidden not in lock.lower()
    for forbidden in ("paddle", "paddleocr", "paddlex", "paddlepaddle-gpu"):
        assert forbidden not in root_metadata.lower()


def test_installer_uses_locked_isolated_sidecar_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], bool]] = []

    def fake_run_cmd(command, *, check=True, **_kwargs):
        calls.append((command, check))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(install, "run_cmd", fake_run_cmd)
    install.install_admission_notice_lite()

    assert calls[0] == (
        [
            "uv",
            "sync",
            "--locked",
            "--project",
            str(PROJECT_ROOT / "services" / "admission_notice_ocr"),
            "--no-dev",
            "--python",
            "3.11",
        ],
        True,
    )
    assert calls[1][0][-1] == "--verify-only"
    assert all(isinstance(command, list) for command, _check in calls)
    flattened = {part for command, _check in calls for part in command}
    assert not flattened.intersection(
        {"sudo", "systemctl", "chown", "firewall-cmd", "ufw", "shell=True"}
    )
    assert not any(command[:3] == ["uv", "pip", "install"] for command, _ in calls)


def test_installer_combines_config_feature_with_explicit_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feature_calls = 0
    explicit_handler_calls: list[list[str]] = []
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "install.py",
            "--dry-run",
            "--config",
            str(LITE_PRESET),
            "--config",
            str(LITE_PRESET),
            "--handler",
            "avatar/lam",
        ],
    )

    original_get_handlers = install.get_handler_dirs_from_names

    def get_handlers(names: list[str]):
        explicit_handler_calls.append(names)
        return original_get_handlers(names)

    def install_feature(*, dry_run: bool):
        nonlocal feature_calls
        assert dry_run is True
        feature_calls += 1

    monkeypatch.setattr(install, "is_venv_active", lambda: True)
    monkeypatch.setattr(install, "get_handler_dirs_from_names", get_handlers)
    monkeypatch.setattr(install, "install_admission_notice_lite", install_feature)

    assert install.main() is None
    assert explicit_handler_calls == [["avatar/lam"]]
    assert feature_calls == 1


def test_model_preparation_reuses_valid_models_without_provisioning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = lite_install.validate_sidecar_layout(PROJECT_ROOT)
    calls: list[list[str]] = []

    def execute(command: list[str], _description: str) -> int:
        calls.append(command)
        return 0

    assert lite_install.prepare_admission_notice_lite_models(layout, execute)
    assert len(calls) == 1
    assert calls[0][-1] == "--verify-only"


def test_model_preparation_provisions_once_then_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = lite_install.validate_sidecar_layout(PROJECT_ROOT)
    results = iter((1, 0, 0))
    calls: list[list[str]] = []

    def execute(command: list[str], _description: str) -> int:
        calls.append(command)
        return next(results)

    assert lite_install.prepare_admission_notice_lite_models(layout, execute)
    provision_calls = [command for command in calls if "--verify-only" not in command]
    assert len(provision_calls) == 1
    assert provision_calls[0][-2:] == ["--thread-count", "2"]
    assert calls[-1][-1] == "--verify-only"


@pytest.mark.parametrize("failed_step", ("provision", "final_verify"))
def test_model_preparation_propagates_failure(
    failed_step: str,
) -> None:
    layout = lite_install.validate_sidecar_layout(PROJECT_ROOT)
    results = iter((1, 1) if failed_step == "provision" else (1, 0, 1))

    assert not lite_install.prepare_admission_notice_lite_models(
        layout,
        lambda _command, _description: next(results),
    )


def test_unapproved_manifest_fails_without_running_provisioner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = lite_install.validate_sidecar_layout(PROJECT_ROOT)
    monkeypatch.setattr(
        lite_install, "approved_manifest_is_current", lambda _layout: False
    )

    def unexpected_execute(_command, _description):
        raise AssertionError("an unapproved manifest must fail before provisioning")

    assert not lite_install.prepare_admission_notice_lite_models(
        layout,
        unexpected_execute,
    )


def test_installer_sidecar_sync_failure_is_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_run(_command, **_kwargs):
        raise SystemExit(1)

    monkeypatch.setattr(install, "run_cmd", failed_run)
    with pytest.raises(SystemExit) as exc:
        install.install_admission_notice_lite()
    assert exc.value.code == 1


def test_download_models_selects_lite_feature_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "download_models.py",
            "--config",
            str(LITE_PRESET),
            "--config",
            str(LITE_PRESET),
        ],
    )
    monkeypatch.setattr(
        download_models, "get_handlers_from_config", lambda _path: set()
    )

    def prepare(**_kwargs):
        nonlocal calls
        calls += 1
        return True

    monkeypatch.setattr(download_models, "download_admission_notice_lite", prepare)
    with pytest.raises(SystemExit) as exc:
        download_models.main()
    assert exc.value.code == 0
    assert calls == 1


def test_download_models_base_preset_does_not_select_lite_feature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["download_models.py", "--config", str(BASE_PRESET)],
    )
    monkeypatch.setattr(
        download_models, "get_handlers_from_config", lambda _path: set()
    )

    def unexpected_prepare(**_kwargs):
        raise AssertionError("the base preset must not prepare Admission Notice OCR")

    monkeypatch.setattr(
        download_models,
        "download_admission_notice_lite",
        unexpected_prepare,
    )
    assert download_models.main() is None


def test_download_models_lite_feature_failure_is_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["download_models.py", "--config", str(LITE_PRESET)],
    )
    monkeypatch.setattr(
        download_models, "get_handlers_from_config", lambda _path: set()
    )
    monkeypatch.setattr(
        download_models,
        "download_admission_notice_lite",
        lambda **_kwargs: False,
    )
    with pytest.raises(SystemExit) as exc:
        download_models.main()
    assert exc.value.code == 1


def test_download_models_explicit_handler_keeps_existing_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "download_models.py",
            "--config",
            str(LITE_PRESET),
            "--handler",
            "liteavatar",
        ],
    )
    monkeypatch.setattr(
        download_models,
        "get_features_from_config",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("explicit --handler mode must continue to ignore --config")
        ),
    )
    monkeypatch.setitem(
        download_models.DOWNLOAD_FUNCTIONS,
        "liteavatar",
        lambda **_kwargs: True,
    )
    with pytest.raises(SystemExit) as exc:
        download_models.main()
    assert exc.value.code == 0
