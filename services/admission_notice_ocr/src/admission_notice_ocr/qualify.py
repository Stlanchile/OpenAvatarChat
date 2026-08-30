"""CLI compatibility wrapper for isolated sidecar-only qualification."""

from admission_notice_ocr.sidecar_qualify import (
    CANDIDATE_REPORT_SCHEMA_VERSION,
    DEFAULT_SAMPLES,
    SIDECAR_REPORT_SCHEMA_VERSION,
    QualificationBlocked,
    QualificationFailed,
    _font_path,
    _offline_prefix,
    _qualification_frames,
    _qualification_source_sha256,
    _service_root,
    main,
    qualify_sidecar,
)

__all__ = [
    "CANDIDATE_REPORT_SCHEMA_VERSION",
    "DEFAULT_SAMPLES",
    "SIDECAR_REPORT_SCHEMA_VERSION",
    "QualificationBlocked",
    "QualificationFailed",
    "_font_path",
    "_offline_prefix",
    "_qualification_frames",
    "_qualification_source_sha256",
    "_service_root",
    "qualify_sidecar",
]


if __name__ == "__main__":
    main()
