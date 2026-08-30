from __future__ import annotations

import io
import math
import warnings
from dataclasses import dataclass
from typing import Any

import numpy as np
from PIL import Image

from admission_notice_ocr.manifest import (
    BACKEND,
    DEVICE,
    MODEL_IDENTITIES,
    RUNTIME_FLAGS,
    VerifiedManifest,
)
from admission_notice_ocr.protocol import FrameRequest

MAX_SPANS_PER_FRAME = 128
MAX_CHARACTERS_PER_SPAN = 512
MAX_UTF8_BYTES_PER_SPAN = 2_048
MAX_AGGREGATE_CHARACTERS = 8_192
MAX_AGGREGATE_UTF8_BYTES = 32_768

_ORIENTATION_TRANSPOSE = {
    2: Image.Transpose.FLIP_LEFT_RIGHT,
    3: Image.Transpose.ROTATE_180,
    4: Image.Transpose.FLIP_TOP_BOTTOM,
    5: Image.Transpose.TRANSPOSE,
    6: Image.Transpose.ROTATE_270,
    7: Image.Transpose.TRANSVERSE,
    8: Image.Transpose.ROTATE_90,
}


class PipelineError(Exception):
    def __init__(self) -> None:
        super().__init__("OCR_RUNTIME_ERROR")


@dataclass(frozen=True, slots=True)
class DecodedFrame:
    frame_index: int
    width: int
    height: int
    bgr_pixels: np.ndarray


def decode_frame(frame: FrameRequest) -> DecodedFrame:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with (
                io.BytesIO(frame.jpeg_bytes) as source,
                Image.open(source) as image,
            ):
                if image.format != "JPEG":
                    raise PipelineError()
                expected_source_size = (
                    (frame.logical_height, frame.logical_width)
                    if frame.exif_orientation in (5, 6, 7, 8)
                    else (frame.logical_width, frame.logical_height)
                )
                if image.size != expected_source_size:
                    raise PipelineError()
                image.load()
                transpose = _ORIENTATION_TRANSPOSE.get(frame.exif_orientation)
                if transpose is not None:
                    oriented = image.transpose(transpose)
                else:
                    oriented = image.copy()
            try:
                if oriented.size != (frame.logical_width, frame.logical_height):
                    raise PipelineError()
                with oriented.convert("RGB") as rgb:
                    rgb_pixels = np.asarray(rgb, dtype=np.uint8)
                    bgr_pixels = np.ascontiguousarray(rgb_pixels[:, :, ::-1])
            finally:
                oriented.close()
    except PipelineError:
        raise
    except Exception:
        raise PipelineError() from None
    return DecodedFrame(
        frame_index=frame.frame_index,
        width=frame.logical_width,
        height=frame.logical_height,
        bgr_pixels=bgr_pixels,
    )


def _result_payload(result: Any) -> dict[str, Any]:
    try:
        value = result.json
        if callable(value):
            value = value()
    except Exception:
        raise PipelineError() from None
    if (
        type(value) is not dict
        or set(value) != {"res"}
        or type(value["res"]) is not dict
    ):
        raise PipelineError()
    return value["res"]


def _bounded_text(value: Any) -> str | None:
    if type(value) is not str:
        raise PipelineError()
    text = value.strip()
    if not text:
        return None
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise PipelineError() from None
    if (
        "\x00" in text
        or len(text) > MAX_CHARACTERS_PER_SPAN
        or len(encoded) > MAX_UTF8_BYTES_PER_SPAN
    ):
        raise PipelineError()
    return text


def _normalized_polygon(value: Any, *, width: int, height: int) -> list[list[float]]:
    try:
        points = np.asarray(value)
    except Exception:
        raise PipelineError() from None
    if points.shape != (4, 2):
        raise PipelineError()
    normalized: list[list[float]] = []
    try:
        for raw_x, raw_y in points:
            x = float(raw_x)
            y = float(raw_y)
            if (
                not math.isfinite(x)
                or not math.isfinite(y)
                or not 0.0 <= x <= width
                or not 0.0 <= y <= height
            ):
                raise PipelineError()
            normalized.append([x / width, y / height])
    except Exception:
        normalized.clear()
        raise PipelineError() from None
    return normalized


def _bounded_score(value: Any) -> float:
    if isinstance(value, bool):
        raise PipelineError()
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        raise PipelineError() from None
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise PipelineError()
    return score


def _convert_result(
    result: Any,
    *,
    frame_index: int,
    width: int,
    height: int,
) -> dict[str, Any]:
    payload = _result_payload(result)
    try:
        texts = payload["rec_texts"]
        scores = payload["rec_scores"]
        polygons = payload["rec_polys"]
        count = len(texts)
        # Every raw engine candidate counts toward the bound, including blank
        # recognition strings that will not be transported.
        if (
            count > MAX_SPANS_PER_FRAME
            or len(scores) != count
            or len(polygons) != count
        ):
            raise PipelineError()
    except (KeyError, TypeError):
        raise PipelineError() from None

    spans: list[dict[str, Any]] = []
    aggregate_characters = 0
    aggregate_utf8_bytes = 0
    try:
        for text_value, score_value, polygon_value in zip(
            texts, scores, polygons, strict=True
        ):
            text = _bounded_text(text_value)
            if text is None:
                continue
            aggregate_characters += len(text)
            aggregate_utf8_bytes += len(text.encode("utf-8"))
            if (
                len(spans) >= MAX_SPANS_PER_FRAME
                or aggregate_characters > MAX_AGGREGATE_CHARACTERS
                or aggregate_utf8_bytes > MAX_AGGREGATE_UTF8_BYTES
            ):
                raise PipelineError()
            spans.append(
                {
                    "polygon": _normalized_polygon(
                        polygon_value,
                        width=width,
                        height=height,
                    ),
                    "score": _bounded_score(score_value),
                    "text": text,
                }
            )
    except Exception:
        spans.clear()
        raise
    return {"frame_index": frame_index, "spans": spans}


class PaddleOcrPipeline:
    def __init__(self, manifest: VerifiedManifest):
        try:
            from paddleocr import PaddleOCR
            from paddlex.utils.logging import setup_logging

            setup_logging("WARNING")

            self._pipeline = PaddleOCR(
                text_detection_model_name=MODEL_IDENTITIES["text_detection"][0],
                text_detection_model_dir=str(
                    manifest.model_directory("text_detection")
                ),
                text_recognition_model_name=MODEL_IDENTITIES["text_recognition"][0],
                text_recognition_model_dir=str(
                    manifest.model_directory("text_recognition")
                ),
                use_doc_orientation_classify=RUNTIME_FLAGS[
                    "use_doc_orientation_classify"
                ],
                use_doc_unwarping=RUNTIME_FLAGS["use_doc_unwarping"],
                use_textline_orientation=RUNTIME_FLAGS["use_textline_orientation"],
                device=DEVICE,
                engine=BACKEND,
                enable_hpi=RUNTIME_FLAGS["enable_hpi"],
                use_tensorrt=RUNTIME_FLAGS["use_tensorrt"],
                enable_mkldnn=RUNTIME_FLAGS["enable_mkldnn"],
                cpu_threads=manifest.thread_count,
            )
        except Exception:
            raise PipelineError() from None

    def recognize(self, frames: tuple[FrameRequest, ...]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        try:
            for frame in frames:
                decoded = decode_frame(frame)
                try:
                    results = list(self._pipeline.predict(decoded.bgr_pixels))
                    if len(results) != 1:
                        raise PipelineError()
                    output.append(
                        _convert_result(
                            results[0],
                            frame_index=decoded.frame_index,
                            width=decoded.width,
                            height=decoded.height,
                        )
                    )
                finally:
                    del decoded
        except Exception:
            output.clear()
            raise PipelineError() from None
        return output
