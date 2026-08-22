from __future__ import annotations

import builtins
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# The repository is run from source and has no installed src-layout package.
from chat_engine.data_models.chat_engine_config_data import (
    ChatEngineConfigModel,
)
from engine_utils.directory_info import DirectoryInfo
from service.service_data_models.logger_config_data import (
    LoggerConfigData,
)
from service.service_data_models.service_config_data import (
    ServiceConfigData,
)
from service.service_utils import ssl_helpers
from service.service_utils.service_config_loader import (
    CertificateCaptureConfigurationError,
    load_configs,
)
from service.service_utils.ssl_helpers import (
    CertificateCaptureStartupError,
    create_ssl_context,
)


def _oidc_config() -> dict:
    return {
        "issuer": "https://issuer.example.test",
        "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
        "audience": "open-avatar-chat",
        "allowed_algorithms": ["RS256"],
        "required_scope": "certificate:capture",
    }


def _enabled_service(
    cert_file: str | None,
    cert_key: str | None,
    *,
    workers: int = 1,
) -> ServiceConfigData:
    return ServiceConfigData.model_validate(
        {
            "cert_file": cert_file,
            "cert_key": cert_key,
            "workers": workers,
            "certificate_capture": {
                "enabled": True,
                "oidc": _oidc_config(),
            },
        }
    )


def _args() -> SimpleNamespace:
    return SimpleNamespace(host=None, port=None)


def _write_tls_pair(
    directory: Path,
    name: str,
) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.example.test")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(f"{name}.example.test")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory) -> dict[str, Path]:
    directory = tmp_path_factory.mktemp("certificate-capture-tls")
    cert_path, key_path = _write_tls_pair(directory, "primary")
    _, other_key_path = _write_tls_pair(directory, "other")
    return {
        "cert": cert_path,
        "key": key_path,
        "other_key": other_key_path,
        "directory": directory,
    }


def test_omitted_and_explicit_disabled_configs_keep_legacy_defaults():
    omitted = ServiceConfigData()
    explicit = ServiceConfigData.model_validate(
        {"certificate_capture": {"enabled": False}}
    )

    assert omitted.certificate_capture.enabled is False
    assert omitted.certificate_capture.oidc is None
    assert explicit.certificate_capture.enabled is False
    assert explicit.certificate_capture.oidc is None
    assert omitted.workers == explicit.workers == 1


def test_disabled_mode_retains_legacy_tls_fallback(tmp_path):
    service_config = ServiceConfigData.model_validate(
        {
            "cert_file": str(tmp_path / "missing.crt"),
            "cert_key": str(tmp_path / "missing.key"),
        }
    )

    assert create_ssl_context(_args(), service_config) == {}


def test_disabled_mode_does_not_parse_existing_tls_material(tmp_path):
    cert_path = tmp_path / "legacy.crt"
    key_path = tmp_path / "legacy.key"
    cert_path.write_text("not a certificate", encoding="utf-8")
    key_path.write_text("not a private key", encoding="utf-8")
    service_config = ServiceConfigData.model_validate(
        {
            "cert_file": str(cert_path),
            "cert_key": str(key_path),
            "certificate_capture": {"enabled": False},
        }
    )

    assert create_ssl_context(_args(), service_config) == {
        "ssl_certfile": str(cert_path),
        "ssl_keyfile": str(key_path),
    }


def test_enabled_mode_requires_oidc_configuration():
    with pytest.raises(ValidationError) as exception:
        ServiceConfigData.model_validate(
            {"certificate_capture": {"enabled": True}}
        )

    assert "OIDC resource-server configuration is required" in str(
        exception.value
    )


@pytest.mark.parametrize(
    "missing_field",
    [
        "issuer",
        "jwks_url",
        "audience",
        "allowed_algorithms",
        "required_scope",
    ],
)
def test_enabled_mode_rejects_incomplete_oidc_configuration(missing_field):
    oidc = _oidc_config()
    del oidc[missing_field]

    with pytest.raises(ValidationError):
        ServiceConfigData.model_validate(
            {
                "certificate_capture": {
                    "enabled": True,
                    "oidc": oidc,
                }
            }
        )


@pytest.mark.parametrize("url_field", ["issuer", "jwks_url"])
def test_oidc_endpoints_must_use_https(url_field):
    secret_marker = "oidc-secret-marker"
    oidc = _oidc_config()
    oidc[url_field] = f"http://{secret_marker}.example.test/path"

    with pytest.raises(ValidationError) as exception:
        ServiceConfigData.model_validate(
            {
                "certificate_capture": {
                    "enabled": True,
                    "oidc": oidc,
                }
            }
        )

    assert secret_marker not in str(exception.value)
    assert "absolute HTTPS URL" in str(exception.value)


@pytest.mark.parametrize(
    "allowed_algorithms",
    [
        [],
        ["none"],
        ["HS256"],
        ["RS256", "RS256"],
    ],
)
def test_oidc_algorithms_are_nonempty_asymmetric_and_unique(
    allowed_algorithms,
):
    oidc = _oidc_config()
    oidc["allowed_algorithms"] = allowed_algorithms

    with pytest.raises(ValidationError):
        ServiceConfigData.model_validate(
            {
                "certificate_capture": {
                    "enabled": True,
                    "oidc": oidc,
                }
            }
        )


def test_oidc_scope_is_fixed():
    oidc = _oidc_config()
    oidc["required_scope"] = "ordinary:chat"

    with pytest.raises(ValidationError):
        ServiceConfigData.model_validate(
            {
                "certificate_capture": {
                    "enabled": True,
                    "oidc": oidc,
                }
            }
        )


def test_certificate_config_loader_errors_are_redacted(tmp_path, capsys):
    secret_marker = "do-not-log-this-oidc-secret"
    config_path = tmp_path / "invalid-certificate-config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "default:",
                "  service:",
                "    certificate_capture:",
                "      enabled: true",
                "      oidc:",
                "        issuer: https://issuer.example.test",
                "        jwks_url: https://issuer.example.test/jwks",
                "        audience: open-avatar-chat",
                "        allowed_algorithms: [RS256]",
                "        required_scope: certificate:capture",
                f"        client_secret: {secret_marker}",
            ]
        ),
        encoding="utf-8",
    )
    args = SimpleNamespace(
        env="default",
        config=str(config_path),
    )

    with pytest.raises(CertificateCaptureConfigurationError) as exception:
        load_configs(args)

    captured = capsys.readouterr()
    visible_output = (
        str(exception.value)
        + repr(exception.value)
        + captured.out
        + captured.err
    )
    assert secret_marker not in visible_output
    assert exception.value.__cause__ is None
    assert exception.value.__context__ is None


def test_valid_dynaconf_oidc_and_tls_configuration_passes_preflight(
    tls_material,
    tmp_path,
):
    config_path = tmp_path / "valid-certificate-config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "default:",
                "  service:",
                f"    cert_file: {tls_material['cert']}",
                f"    cert_key: {tls_material['key']}",
                "    workers: 1",
                "    certificate_capture:",
                "      enabled: true",
                "      oidc:",
                "        issuer: https://issuer.example.test",
                "        jwks_url: https://issuer.example.test/jwks",
                "        audience: open-avatar-chat",
                "        allowed_algorithms: [RS256]",
                "        required_scope: certificate:capture",
            ]
        ),
        encoding="utf-8",
    )
    config_args = SimpleNamespace(
        env="default",
        config=str(config_path),
    )

    _, service_config, _ = load_configs(config_args)
    ssl_options = create_ssl_context(_args(), service_config)

    assert service_config.certificate_capture.enabled is True
    assert service_config.certificate_capture.oidc is not None
    assert ssl_options == {
        "ssl_certfile": str(tls_material["cert"]),
        "ssl_keyfile": str(tls_material["key"]),
    }


@pytest.mark.parametrize(
    ("cert_file", "cert_key", "reason_code"),
    [
        (None, "unused.key", "TLS_CERTIFICATE_REQUIRED"),
        ("unused.crt", None, "TLS_PRIVATE_KEY_REQUIRED"),
    ],
)
def test_enabled_mode_requires_both_tls_paths(
    cert_file,
    cert_key,
    reason_code,
):
    service_config = _enabled_service(cert_file, cert_key)

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("missing_side", "reason_code"),
    [
        ("cert", "TLS_CERTIFICATE_UNREADABLE"),
        ("key", "TLS_PRIVATE_KEY_UNREADABLE"),
    ],
)
def test_enabled_mode_rejects_missing_tls_files(
    tls_material,
    missing_side,
    reason_code,
):
    cert_path = tls_material["cert"]
    key_path = tls_material["key"]
    if missing_side == "cert":
        cert_path = tls_material["directory"] / "absent.crt"
    else:
        key_path = tls_material["directory"] / "absent.key"
    service_config = _enabled_service(str(cert_path), str(key_path))

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("unreadable_side", "reason_code"),
    [
        ("cert", "TLS_CERTIFICATE_UNREADABLE"),
        ("key", "TLS_PRIVATE_KEY_UNREADABLE"),
    ],
)
def test_enabled_mode_rejects_unreadable_tls_files(
    tls_material,
    unreadable_side,
    reason_code,
    monkeypatch,
):
    blocked_path = tls_material[unreadable_side]
    real_open = builtins.open

    def permission_denied(path, *args, **kwargs):
        if Path(path) == blocked_path:
            raise PermissionError
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(
        ssl_helpers,
        "open",
        permission_denied,
        raising=False,
    )
    service_config = _enabled_service(
        str(tls_material["cert"]),
        str(tls_material["key"]),
    )

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == reason_code


@pytest.mark.parametrize("malformed_side", ["cert", "key"])
def test_enabled_mode_rejects_malformed_tls_material(
    tls_material,
    malformed_side,
    tmp_path,
):
    secret_marker = "tls-secret-marker"
    malformed_path = tmp_path / f"malformed.{malformed_side}"
    malformed_path.write_text(secret_marker, encoding="utf-8")
    cert_path = (
        malformed_path
        if malformed_side == "cert"
        else tls_material["cert"]
    )
    key_path = (
        malformed_path
        if malformed_side == "key"
        else tls_material["key"]
    )
    service_config = _enabled_service(str(cert_path), str(key_path))

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == "TLS_MATERIAL_INVALID"
    assert secret_marker not in str(exception.value)
    assert exception.value.__cause__ is None
    assert exception.value.__context__ is None


def test_enabled_mode_rejects_mismatched_certificate_and_key(tls_material):
    service_config = _enabled_service(
        str(tls_material["cert"]),
        str(tls_material["other_key"]),
    )

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == "TLS_MATERIAL_INVALID"


def test_enabled_mode_validates_relative_matching_tls_pair(
    tls_material,
    monkeypatch,
):
    directory = tls_material["directory"]
    monkeypatch.setattr(
        DirectoryInfo,
        "get_project_dir",
        classmethod(lambda cls: str(directory)),
    )
    service_config = _enabled_service("primary.crt", "primary.key")

    result = create_ssl_context(_args(), service_config)

    assert result == {
        "ssl_certfile": str(tls_material["cert"]),
        "ssl_keyfile": str(tls_material["key"]),
    }


@pytest.mark.parametrize(
    ("workers", "environment_workers", "reason_code"),
    [
        (2, None, "MULTI_WORKER_UNSUPPORTED"),
        (1, "2", "MULTI_WORKER_UNSUPPORTED"),
        (1, "not-an-integer", "WORKER_CONFIGURATION_INVALID"),
    ],
)
def test_enabled_mode_rejects_non_single_worker_configuration(
    tls_material,
    workers,
    environment_workers,
    reason_code,
    monkeypatch,
):
    if environment_workers is None:
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("WEB_CONCURRENCY", environment_workers)
    service_config = _enabled_service(
        str(tls_material["cert"]),
        str(tls_material["key"]),
        workers=workers,
    )

    with pytest.raises(CertificateCaptureStartupError) as exception:
        create_ssl_context(_args(), service_config)

    assert exception.value.reason_code == reason_code


def test_enabled_mode_accepts_explicit_single_worker_environment(
    tls_material,
    monkeypatch,
):
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    service_config = _enabled_service(
        str(tls_material["cert"]),
        str(tls_material["key"]),
    )

    result = create_ssl_context(_args(), service_config)

    assert result["ssl_certfile"] == str(tls_material["cert"])
    assert result["ssl_keyfile"] == str(tls_material["key"])


def test_main_preflight_fails_before_setup_or_engine_initialization(
    tmp_path,
    monkeypatch,
):
    import demo

    service_config = _enabled_service(
        str(tmp_path / "missing.crt"),
        str(tmp_path / "missing.key"),
    )
    parse_args = SimpleNamespace(
        host=None,
        port=None,
        config="unused.yaml",
        env="default",
    )
    setup_demo = Mock()
    chat_engine = Mock()
    config_loggers = Mock()

    monkeypatch.delenv("OPEN_AVATAR_CHAT_CONFIG", raising=False)
    monkeypatch.setattr(demo, "parse_args", lambda: parse_args)
    monkeypatch.setattr(
        demo,
        "load_configs",
        lambda args: (
            LoggerConfigData(),
            service_config,
            ChatEngineConfigModel(model_root="models"),
        ),
    )
    monkeypatch.setattr(demo, "setup_demo", setup_demo)
    monkeypatch.setattr(demo, "ChatEngine", chat_engine)
    monkeypatch.setattr(demo, "config_loggers", config_loggers)

    with pytest.raises(CertificateCaptureStartupError):
        demo.main()

    config_loggers.assert_not_called()
    setup_demo.assert_not_called()
    chat_engine.assert_not_called()


def test_main_disabled_mode_retains_legacy_ssl_resolution_order(monkeypatch):
    import demo

    events = []
    parse_args = SimpleNamespace(
        host=None,
        port=None,
        config="unused.yaml",
        env="default",
    )
    engine = Mock()
    engine.initialize.side_effect = lambda *args, **kwargs: events.append(
        "initialize"
    )
    chat_engine = Mock(return_value=engine)
    setup_demo = Mock(return_value=("app", "ui", "parent"))
    setup_demo.side_effect = lambda: (
        events.append("setup_demo")
        or ("app", "ui", "parent")
    )
    create_context = Mock(
        side_effect=lambda *args, **kwargs: (
            events.append("create_ssl_context") or {}
        )
    )
    install_session_control = Mock(
        side_effect=AssertionError(
            "disabled mode must not initialize session authority"
        )
    )
    server = Mock()

    monkeypatch.delenv("OPEN_AVATAR_CHAT_CONFIG", raising=False)
    monkeypatch.setattr(demo, "parse_args", lambda: parse_args)
    monkeypatch.setattr(
        demo,
        "load_configs",
        lambda args: (
            LoggerConfigData(),
            ServiceConfigData(),
            ChatEngineConfigModel(model_root="models"),
        ),
    )
    monkeypatch.setattr(
        demo,
        "config_loggers",
        lambda config: events.append("config_loggers"),
    )
    monkeypatch.setattr(demo, "setup_demo", setup_demo)
    monkeypatch.setattr(demo, "ChatEngine", chat_engine)
    monkeypatch.setattr(demo, "create_ssl_context", create_context)
    monkeypatch.setattr(
        demo,
        "install_certificate_session_control_v1",
        install_session_control,
    )
    monkeypatch.setattr(demo.uvicorn, "Config", Mock(return_value="config"))
    monkeypatch.setattr(
        demo,
        "OpenAvatarChatWebServer",
        Mock(return_value=server),
    )

    demo.main()

    assert events == [
        "config_loggers",
        "setup_demo",
        "initialize",
        "create_ssl_context",
    ]
    install_session_control.assert_not_called()
    server.run.assert_called_once_with()


def test_main_enabled_mode_installs_control_plane_before_engine_initialization(
    monkeypatch,
):
    import demo

    events = []
    parse_args = SimpleNamespace(
        host=None,
        port=None,
        config="unused.yaml",
        env="default",
    )
    service_config = ServiceConfigData.model_validate(
        {
            "cert_file": "unused.crt",
            "cert_key": "unused.key",
            "certificate_capture": {
                "enabled": True,
                "oidc": _oidc_config(),
            },
        }
    )
    engine = Mock()
    engine.initialize.side_effect = lambda *args, **kwargs: events.append(
        "initialize"
    )
    setup_demo = Mock(
        side_effect=lambda: (
            events.append("setup_demo") or ("app", "ui", "parent")
        )
    )
    install_session_control = Mock(
        side_effect=lambda *args, **kwargs: events.append(
            "install_session_control"
        )
    )
    create_context = Mock(
        side_effect=lambda *args, **kwargs: (
            events.append("create_ssl_context")
            or {
                "ssl_certfile": "unused.crt",
                "ssl_keyfile": "unused.key",
            }
        )
    )
    server = Mock()

    monkeypatch.delenv("OPEN_AVATAR_CHAT_CONFIG", raising=False)
    monkeypatch.setattr(demo, "parse_args", lambda: parse_args)
    monkeypatch.setattr(
        demo,
        "load_configs",
        lambda args: (
            LoggerConfigData(),
            service_config,
            ChatEngineConfigModel(model_root="models"),
        ),
    )
    monkeypatch.setattr(
        demo,
        "config_loggers",
        lambda config: events.append("config_loggers"),
    )
    monkeypatch.setattr(demo, "setup_demo", setup_demo)
    monkeypatch.setattr(demo, "ChatEngine", Mock(return_value=engine))
    monkeypatch.setattr(demo, "create_ssl_context", create_context)
    monkeypatch.setattr(
        demo,
        "install_certificate_session_control_v1",
        install_session_control,
    )
    monkeypatch.setattr(demo.uvicorn, "Config", Mock(return_value="config"))
    monkeypatch.setattr(
        demo,
        "OpenAvatarChatWebServer",
        Mock(return_value=server),
    )

    demo.main()

    assert events == [
        "create_ssl_context",
        "config_loggers",
        "setup_demo",
        "install_session_control",
        "initialize",
    ]
    install_session_control.assert_called_once_with(
        "app",
        service_config.certificate_capture,
    )
    server.run.assert_called_once_with()
