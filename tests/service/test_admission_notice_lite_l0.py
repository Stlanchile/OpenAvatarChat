import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from dynaconf.vendor.ruamel.yaml.constructor import DuplicateKeyError
from pydantic import ValidationError

from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)
from service.service_data_models.service_config_data import ServiceConfigData
from service.service_utils.service_config_loader import load_configs

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DOCUMENT_PATH = (
    PROJECT_ROOT / "docs" / "en" / "reference" / "admission-notice-lite-v1.md"
)
DEMO_PATH = PROJECT_ROOT / "src" / "demo.py"
PRODUCTION_CONFIG_PATHS = (
    PROJECT_ROOT
    / "src"
    / "service"
    / "service_data_models"
    / "admission_notice_lite_config.py",
    PROJECT_ROOT / "src" / "service" / "service_data_models" / "service_config_data.py",
)

PARSEABLE_PRESETS = (
    "chat_with_lam.yaml",
    "chat_with_lam_bailian_asr_duplex.yaml",
    "chat_with_lam_duplex.yaml",
    "chat_with_openai_compatible.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_duplex.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_flashhead.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_flashhead_duplex.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_flashhead_duplex_agent.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_musetalk.yaml",
    "chat_with_openai_compatible_bailian_cosyvoice_musetalk_duplex.yaml",
    "chat_with_openai_compatible_edge_tts.yaml",
)
KNOWN_BASELINE_INVALID_PRESET = "chat_with_qwen_omni.yaml"
ADMISSION_NOTICE_LITE_PRESET = (
    "chat_with_openai_compatible_bailian_cosyvoice_admission_notice_lite.yaml"
)

REQUIRED_DOCUMENT_HEADINGS = (
    "Status and Normative Language",
    "Fixed Product Contract",
    "Threat Model",
    "Network Boundary",
    "Target Architecture",
    "Data Lifecycle and Resource Bounds",
    "Session and Recognition Ownership",
    "L1 Recognition API and Control Plane",
    "OCR Process Boundary",
    "L4 Semantic Recognition",
    "Structured Result and Persistent Frontend Context",
    "Privacy, Logging, and Authenticity",
    "Migration and Reuse Boundaries",
    "Milestone Sequence",
    "L0 and L1 Configuration",
    "L0 Non-Goals",
)


def _load_preset(preset_name: str):
    return load_configs(
        SimpleNamespace(env="default", config=str(CONFIG_DIR / preset_name))
    )


def _resolve_local_document_link(target: str) -> tuple[Path, ...]:
    target_without_fragment = target.split("#", maxsplit=1)[0]
    target_path = target_without_fragment.split("?", maxsplit=1)[0]
    if target_path.startswith("/"):
        candidate = PROJECT_ROOT / "docs" / target_path.removeprefix("/")
    else:
        candidate = DOCUMENT_PATH.parent / target_path

    if candidate.suffix:
        return (candidate,)
    return (candidate, candidate.with_suffix(".md"), candidate / "index.md")


def _collect_imported_names(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported_names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names.extend(alias.name for alias in node.names)
            imported_names.extend(
                alias.asname for alias in node.names if alias.asname is not None
            )
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None:
                imported_names.append(node.module)
            imported_names.extend(alias.name for alias in node.names)
            imported_names.extend(
                alias.asname for alias in node.names if alias.asname is not None
            )
    return tuple(imported_names)


def test_feature_defaults_to_disabled() -> None:
    config = AdmissionNoticeLiteFeatureConfigV1()

    assert config.enabled is False
    assert config.model_dump() == {
        "enabled": False,
        "recognition_ttl_seconds": 120,
        "max_global_recognition_jobs": 1,
        "ocr_socket_path": "/run/openavatarchat-admission-lite/ocr.sock",
        "ocr_connect_timeout_seconds": 1.0,
        "ocr_timeout_seconds": 30.0,
    }
    assert config.model_config["extra"] == "forbid"
    assert config.model_config["frozen"] is True
    assert config.model_config["hide_input_in_errors"] is True


def test_lite_enabled_suppresses_session_bearing_uvicorn_request_logs() -> None:
    tree = ast.parse(DEMO_PATH.read_text(encoding="utf-8"))
    uvicorn_config_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "uvicorn"
        and node.func.attr == "Config"
    ]
    assert len(uvicorn_config_calls) == 1
    access_log_keywords = [
        keyword
        for keyword in uvicorn_config_calls[0].keywords
        if keyword.arg == "access_log"
    ]
    assert len(access_log_keywords) == 1
    assert ast.unparse(access_log_keywords[0].value) == (
        "not service_config.admission_notice_lite.enabled"
    )
    log_level_keywords = [
        keyword
        for keyword in uvicorn_config_calls[0].keywords
        if keyword.arg == "log_level"
    ]
    assert len(log_level_keywords) == 1
    assert ast.unparse(log_level_keywords[0].value) == (
        "'warning' if service_config.admission_notice_lite.enabled else 'info'"
    )

    document = DOCUMENT_PATH.read_text(encoding="utf-8")
    assert "target access logging MUST be disabled or redacted" in document


def test_explicit_false_is_accepted() -> None:
    config = AdmissionNoticeLiteFeatureConfigV1.model_validate({"enabled": False})

    assert config.enabled is False


def test_explicit_true_is_available_for_l1() -> None:
    config = AdmissionNoticeLiteFeatureConfigV1.model_validate({"enabled": True})

    assert config.enabled is True


@pytest.mark.parametrize(
    "invalid_value",
    (0, 1, "false", "true", None),
    ids=("zero", "one", "false-string", "true-string", "null"),
)
def test_non_boolean_enabled_values_are_rejected(invalid_value: object) -> None:
    with pytest.raises(ValidationError):
        AdmissionNoticeLiteFeatureConfigV1.model_validate({"enabled": invalid_value})


@pytest.mark.parametrize(
    ("unknown_key", "value"),
    (
        ("fake_processor", True),
        ("ocr_backend", "auto"),
        ("ocr_model_family", "other"),
        ("unknown", "value"),
    ),
)
def test_unknown_lite_keys_are_rejected(unknown_key: str, value: object) -> None:
    with pytest.raises(ValidationError):
        AdmissionNoticeLiteFeatureConfigV1.model_validate(
            {"enabled": False, unknown_key: value}
        )


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("recognition_ttl_seconds", True),
        ("recognition_ttl_seconds", 0),
        ("recognition_ttl_seconds", 3601),
        ("max_global_recognition_jobs", True),
        ("max_global_recognition_jobs", 0),
        ("max_global_recognition_jobs", 33),
    ),
)
def test_l1_control_plane_limits_are_strict_and_bounded(
    key: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        AdmissionNoticeLiteFeatureConfigV1.model_validate({key: value})


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("ocr_socket_path", "relative.sock"),
        ("ocr_socket_path", "/tmp/\x00bad.sock"),
        ("ocr_socket_path", "/" + "x" * 101),
        ("ocr_connect_timeout_seconds", True),
        ("ocr_connect_timeout_seconds", 0.01),
        ("ocr_connect_timeout_seconds", 2.01),
        ("ocr_timeout_seconds", True),
        ("ocr_timeout_seconds", 0.99),
        ("ocr_timeout_seconds", 60.01),
    ),
)
def test_l3_ocr_configuration_is_strict_and_bounded(
    key: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        AdmissionNoticeLiteFeatureConfigV1.model_validate({key: value})


def test_feature_config_is_frozen() -> None:
    config = AdmissionNoticeLiteFeatureConfigV1()

    with pytest.raises(ValidationError) as error:
        config.enabled = False

    assert error.value.errors()[0]["type"] == "frozen_instance"


def test_service_config_uses_a_fresh_disabled_default() -> None:
    first = ServiceConfigData()
    second = ServiceConfigData()

    assert first.admission_notice_lite.enabled is False
    assert second.admission_notice_lite.enabled is False
    assert first.admission_notice_lite is not second.admission_notice_lite


def test_service_fields_are_preserved_when_lite_section_is_absent() -> None:
    config = ServiceConfigData.model_validate(
        {
            "host": "0.0.0.0",
            "port": 8282,
            "cert_file": "ssl_certs/localhost.crt",
            "cert_key": "ssl_certs/localhost.key",
        }
    )

    assert config.host == "0.0.0.0"
    assert config.port == 8282
    assert config.cert_file == "ssl_certs/localhost.crt"
    assert config.cert_key == "ssl_certs/localhost.key"
    assert config.admission_notice_lite.enabled is False


def test_real_loader_parses_minimal_explicitly_disabled_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "admission_notice_lite_l0.yaml"
    config_path.write_text(
        "default:\n"
        "  logger:\n"
        '    log_level: "DEBUG"\n'
        "  service:\n"
        '    host: "127.0.0.2"\n'
        "    admission_notice_lite:\n"
        "      enabled: false\n"
        "  chat_engine: {}\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("ENV_FOR_DYNACONF", raising=False)

    logger_config, service_config, engine_config = load_configs(
        SimpleNamespace(env="default", config=str(config_path))
    )

    assert logger_config.log_level == "DEBUG"
    assert service_config.host == "127.0.0.2"
    assert service_config.port == 8080
    assert service_config.admission_notice_lite.enabled is False
    assert engine_config.model_root == ""


def test_preset_inventory_matches_the_clean_base() -> None:
    preset_names = tuple(path.name for path in sorted(CONFIG_DIR.glob("*.yaml")))

    assert preset_names == (
        *PARSEABLE_PRESETS[:5],
        ADMISSION_NOTICE_LITE_PRESET,
        *PARSEABLE_PRESETS[5:],
        KNOWN_BASELINE_INVALID_PRESET,
    )


@pytest.mark.parametrize("preset_name", PARSEABLE_PRESETS)
def test_parseable_presets_default_lite_to_disabled(
    preset_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ENV_FOR_DYNACONF", raising=False)

    _, service_config, _ = _load_preset(preset_name)

    assert service_config.admission_notice_lite.enabled is False


def test_known_qwen_omni_duplicate_key_remains_a_baseline_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENV_FOR_DYNACONF", raising=False)

    with pytest.raises(DuplicateKeyError, match="connection_ttl"):
        _load_preset(KNOWN_BASELINE_INVALID_PRESET)


def test_normative_document_has_exact_required_headings() -> None:
    lines = DOCUMENT_PATH.read_text(encoding="utf-8").splitlines()
    headings = tuple(
        line.removeprefix("## ") for line in lines if line.startswith("## ")
    )

    assert headings == REQUIRED_DOCUMENT_HEADINGS


def test_normative_document_has_balanced_fenced_code_blocks() -> None:
    lines = DOCUMENT_PATH.read_text(encoding="utf-8").splitlines()
    fences = tuple(line for line in lines if line.startswith("```"))

    assert fences
    assert len(fences) % 2 == 0


def test_normative_document_local_links_resolve() -> None:
    document = DOCUMENT_PATH.read_text(encoding="utf-8")
    link_targets = re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", document)

    for target in link_targets:
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        candidates = _resolve_local_document_link(target)
        assert any(candidate.exists() for candidate in candidates), (
            f"unresolved local link {target!r}"
        )


def test_production_config_models_have_no_runtime_boundary_imports() -> None:
    forbidden_fragments = (
        "ocr",
        "route",
        "process",
        "socket",
        "chatagent",
        "chat_agent",
        "frontend",
    )

    for path in PRODUCTION_CONFIG_PATHS:
        imported_names = " ".join(_collect_imported_names(path)).lower()
        for fragment in forbidden_fragments:
            assert fragment not in imported_names, (
                f"{path.name} imports forbidden runtime boundary {fragment!r}"
            )
