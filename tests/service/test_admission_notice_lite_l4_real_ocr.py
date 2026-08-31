from __future__ import annotations

import asyncio
import io
import os
import sys
import time
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import admission_notice_lite_l3_qualify as integration_qualify
from service.admission_notice_lite_contracts import (
    RecognitionJobContextLiteV1,
)
from service.admission_notice_lite_ingestion import _validate_admission_jpeg
from service.admission_notice_lite_major_catalog import (
    SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1,
)
from service.admission_notice_lite_ocr import (
    AdmissionNoticeOcrProcessorLiteV1,
    build_qualified_admission_notice_ocr_processor_lite_v1,
)
from service.admission_notice_lite_semantics import (
    recognize_admission_notice_semantics,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)


def _synthetic_notice_frame(
    *,
    font_path: Path,
    major: str,
):
    font = ImageFont.truetype(str(font_path), 30)
    title_font = ImageFont.truetype(str(font_path), 44)
    with Image.new("RGB", (1080, 1500), "white") as image:
        draw = ImageDraw.Draw(image)
        draw.text((270, 70), "湖北交通职业技术学院", font=title_font, fill="black")
        draw.text((100, 290), "测试同学", font=font, fill="black")
        draw.text(
            (100, 510),
            "经湖北省（市、自治区）高等学校招生委员会批准",
            font=font,
            fill="black",
        )
        draw.text(
            (70, 820),
            f"你被录取到我校交通信息学院{major}专业学习",
            font=font,
            fill="black",
        )
        with io.BytesIO() as output:
            image.save(output, format="JPEG", quality=96)
            jpeg_bytes = output.getvalue()
    return _validate_admission_jpeg(frame_index=1, jpeg_bytes=jpeg_bytes)


@pytest.mark.admission_notice_ocr_integration
@pytest.mark.asyncio
async def test_real_l2_l3_l4_pipeline_recognizes_all_seven_major_names(
    tmp_path: Path,
) -> None:
    """Opt-in host lane: no fabricated OCR batch and no ChatAgent call."""

    if os.environ.get("ADMISSION_NOTICE_OCR_RUN_REAL") != "1":
        pytest.skip("set ADMISSION_NOTICE_OCR_RUN_REAL=1 for real L4 integration")
    blocker = integration_qualify._probe_af_unix(tmp_path)
    if blocker is not None:
        pytest.skip(f"BLOCKED: {blocker}")
    try:
        font_path = integration_qualify._font_path(None)
        offline_prefix = integration_qualify._offline_prefix()
    except integration_qualify.QualificationBlocked as error:
        pytest.skip(f"BLOCKED: {error.code}")

    service_root = PROJECT_ROOT / "services/admission_notice_ocr"
    sidecar = integration_qualify._start_sidecar(
        temporary_root=tmp_path,
        sidecar_python=integration_qualify._sidecar_python_path(),
        manifest_path=service_root / "model_manifest.json",
        model_root=service_root / "models",
        offline_prefix=offline_prefix,
    )
    try:
        processor = build_qualified_admission_notice_ocr_processor_lite_v1(
            AdmissionNoticeLiteFeatureConfigV1(
                enabled=True,
                ocr_socket_path=str(sidecar.socket_path),
            )
        )
        assert isinstance(processor, AdmissionNoticeOcrProcessorLiteV1)
        for major in SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1:
            frame = _synthetic_notice_frame(font_path=font_path, major=major)
            context = RecognitionJobContextLiteV1(
                recognition_id="arn1_real_l4",
                expires_at_monotonic=time.monotonic() + 60,
                cancel_event=asyncio.Event(),
            )
            batch = await processor.recognize_batch(context, (frame,))
            result = recognize_admission_notice_semantics(batch)
            assert result.institution_name == "湖北交通职业技术学院"
            assert result.college == "交通信息学院"
            assert result.source_province == "湖北"
            assert result.major == major
    finally:
        integration_qualify._stop_process(sidecar.process)
