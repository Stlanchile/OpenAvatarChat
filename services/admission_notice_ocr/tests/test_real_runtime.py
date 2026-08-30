from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from admission_notice_ocr.qualify import (
    _service_root,
    qualify_sidecar,
)


def test_sidecar_qualification_fixture_needs_no_main_or_fastapi_import() -> None:
    code = """
import sys
from admission_notice_ocr.qualify import _font_path, _qualification_frames
frames = _qualification_frames(_font_path(None)[0])
forbidden = tuple(
    name
    for name in sys.modules
    if name == "fastapi"
    or name.startswith("service")
    or name.startswith("chat_engine")
)
assert len(frames) == 3
assert forbidden == ()
print("PASS")
"""
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
    }
    completed = subprocess.run(
        (sys.executable, "-c", code),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == "PASS"


@pytest.mark.admission_notice_ocr_qualification
def test_complete_sidecar_only_qualification_reports_pass(tmp_path: Path) -> None:
    if os.environ.get("ADMISSION_NOTICE_OCR_RUN_QUALIFICATION") != "1":
        pytest.skip("set ADMISSION_NOTICE_OCR_RUN_QUALIFICATION=1 for the full matrix")

    service_root = _service_root()
    report = qualify_sidecar(
        manifest_path=service_root / "model_manifest.json",
        model_root=service_root / "models",
        report_path=tmp_path / "sidecar-qualification.json",
        font_path=None,
        samples=5,
    )
    assert report["result"] == "PASS"
    assert report["scope"] == "sidecar_only"
