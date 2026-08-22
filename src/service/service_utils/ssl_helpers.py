import os
import ssl

from loguru import logger

from engine_utils.directory_info import DirectoryInfo
from service.service_data_models.service_config_data import ServiceConfigData


class CertificateCaptureStartupError(RuntimeError):
    """A fail-closed, value-free certificate-capture startup error."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(
            f"Certificate capture startup preflight failed ({reason_code})."
        )


def _resolve_service_path(path: str | None) -> str | None:
    if not path:
        return None
    if os.path.isabs(path):
        return path
    return os.path.join(DirectoryInfo.get_project_dir(), path)


def _readable_file_prefix(path: str, reason_code: str) -> bytes:
    if not os.path.isfile(path):
        raise CertificateCaptureStartupError(reason_code)
    try:
        with open(path, "rb") as file:
            return file.read(4096)
    except OSError:
        pass
    raise CertificateCaptureStartupError(reason_code)


def _validate_single_worker(in_service_config: ServiceConfigData) -> None:
    if in_service_config.workers != 1:
        raise CertificateCaptureStartupError("MULTI_WORKER_UNSUPPORTED")

    environment_workers = os.environ.get("WEB_CONCURRENCY")
    if environment_workers is None:
        return
    try:
        parsed_workers = int(environment_workers)
    except ValueError:
        worker_configuration_invalid = True
    else:
        worker_configuration_invalid = False

    if worker_configuration_invalid:
        raise CertificateCaptureStartupError(
            "WORKER_CONFIGURATION_INVALID"
        )
    if parsed_workers != 1:
        raise CertificateCaptureStartupError("MULTI_WORKER_UNSUPPORTED")


def _validate_certificate_capture_tls(
    ssl_cert_path: str | None,
    ssl_key_path: str | None,
) -> None:
    if ssl_cert_path is None:
        raise CertificateCaptureStartupError("TLS_CERTIFICATE_REQUIRED")
    if ssl_key_path is None:
        raise CertificateCaptureStartupError("TLS_PRIVATE_KEY_REQUIRED")

    _readable_file_prefix(ssl_cert_path, "TLS_CERTIFICATE_UNREADABLE")
    key_prefix = _readable_file_prefix(
        ssl_key_path,
        "TLS_PRIVATE_KEY_UNREADABLE",
    )
    if b"ENCRYPTED" in key_prefix.upper():
        raise CertificateCaptureStartupError(
            "ENCRYPTED_PRIVATE_KEY_UNSUPPORTED"
        )

    validation_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        validation_context.load_cert_chain(
            certfile=ssl_cert_path,
            keyfile=ssl_key_path,
        )
    except (OSError, ssl.SSLError):
        tls_material_invalid = True
    else:
        tls_material_invalid = False

    if tls_material_invalid:
        raise CertificateCaptureStartupError("TLS_MATERIAL_INVALID")


def create_ssl_context(in_args, in_service_config: ServiceConfigData):
    out_ssl_context = {}
    if in_args.host:
        in_service_config.host = in_args.host
    if in_args.port:
        in_service_config.port = in_args.port

    ssl_cert_path = _resolve_service_path(in_service_config.cert_file)
    ssl_key_path = _resolve_service_path(in_service_config.cert_key)

    if in_service_config.certificate_capture.enabled:
        _validate_single_worker(in_service_config)
        _validate_certificate_capture_tls(ssl_cert_path, ssl_key_path)
        out_ssl_context["ssl_certfile"] = ssl_cert_path
        out_ssl_context["ssl_keyfile"] = ssl_key_path
        logger.info(
            f"Service will be started on "
            f"{in_service_config.host}:{in_service_config.port}"
        )
        logger.info("SSL enabled.")
        return out_ssl_context

    if ssl_cert_path and not os.path.isfile(ssl_cert_path):
        logger.warning(f"Cert file {ssl_cert_path} not found")
        ssl_cert_path = None
    if ssl_key_path and not os.path.isfile(ssl_key_path):
        logger.warning(f"Key file {ssl_key_path} not found")
        ssl_key_path = None

    logger.info(f"Service will be started on {in_service_config.host}:{in_service_config.port}")
    if ssl_cert_path and ssl_key_path:
        out_ssl_context["ssl_certfile"] = ssl_cert_path
        out_ssl_context["ssl_keyfile"] = ssl_key_path
        logger.info("SSL enabled.")
    return out_ssl_context
