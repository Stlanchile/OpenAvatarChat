"""Fixed PP-OCRv6 medium CPU pipeline with bounded in-memory image handling."""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from numbers import Real
from typing import Any

from certificate_ocr.manifest import (
    ManifestUnavailableV1,
    QualificationCandidateManifestV1,
    VerifiedManifestV1,
    verify_no_prohibited_loaded_libraries_v1,
)
from certificate_ocr.protocol import (
    MAX_OCR_JPEG_BYTES_V1,
    SidecarProtocolErrorV1,
    require_finite_normalized_v1,
)

MAX_CANONICAL_PIXELS_V1 = 1920 * 1080
MAX_OCR_SPANS_PER_PAGE_V1 = 128
MAX_OCR_CHARACTERS_PER_SPAN_V1 = 512
MAX_OCR_UTF8_BYTES_PER_SPAN_V1 = 2 * 1024
MAX_OCR_AGGREGATE_CHARACTERS_V1 = 8 * 1024
MAX_OCR_AGGREGATE_UTF8_BYTES_V1 = 32 * 1024


@dataclass(frozen=True, slots=True)
class EngineSpanV1:
    text: str
    polygon: tuple[tuple[float, float], ...]
    raw_engine_score: float

    def ordering_key_v1(self) -> tuple[object, ...]:
        xs = tuple(point[0] for point in self.polygon)
        ys = tuple(point[1] for point in self.polygon)
        return (
            min(ys),
            min(xs),
            max(ys),
            max(xs),
            self.text,
            self.raw_engine_score,
        )


class PaddleCpuPipelineV1:
    """Exactly one explicit Paddle Static CPU backend; no fallback exists."""

    __slots__ = (
        "_cv2",
        "_manifest",
        "_numpy",
        "_pipeline",
        "_process",
    )

    def __init__(
        self,
        manifest: VerifiedManifestV1 | QualificationCandidateManifestV1,
    ) -> None:
        if not isinstance(
            manifest,
            (VerifiedManifestV1, QualificationCandidateManifestV1),
        ):
            raise TypeError("manifest must be a verified CPU manifest")
        self._manifest = manifest
        try:
            import cv2
            import numpy
            import psutil
            from paddleocr import PaddleOCR
        except Exception:  # noqa: BLE001 - third-party import boundary
            raise ManifestUnavailableV1("OCR CPU backend unavailable") from None
        backend = manifest.backend
        try:
            pipeline = PaddleOCR(
                ocr_version="PP-OCRv6",
                device="cpu",
                engine="paddle_static",
                enable_hpi=False,
                cpu_threads=backend["cpu_threads"],
                use_doc_orientation_classify=False,
                use_doc_unwarping=False,
                use_textline_orientation=False,
                text_detection_model_dir=str(
                    (manifest.root / backend["text_detection_model_dir"]).resolve(
                        strict=True
                    )
                ),
                text_recognition_model_dir=str(
                    (manifest.root / backend["text_recognition_model_dir"]).resolve(
                        strict=True
                    )
                ),
            )
        except Exception:  # noqa: BLE001 - third-party construction boundary
            raise ManifestUnavailableV1("OCR CPU backend unavailable") from None
        self._cv2 = cv2
        self._numpy = numpy
        self._process = psutil.Process()
        self._pipeline = pipeline
        verify_no_prohibited_loaded_libraries_v1()
        self._verify_thread_cap_v1()

    def _verify_thread_cap_v1(self) -> None:
        cap = self._manifest.identity["execution"]["cpu_runtime"]["process_thread_cap"]
        try:
            observed = self._process.num_threads()
        except Exception:  # noqa: BLE001 - process inspection boundary
            raise ManifestUnavailableV1("OCR thread proof unavailable") from None
        if (
            isinstance(cap, bool)
            or not isinstance(cap, int)
            or cap <= 0
            or observed > cap
        ):
            raise ManifestUnavailableV1("OCR thread cap exceeded")

    def _decode_v1(
        self,
        jpeg_buffer: bytearray,
        *,
        expected_width: int | None,
        expected_height: int | None,
    ) -> Any:
        if (
            not isinstance(jpeg_buffer, bytearray)
            or not 0 < len(jpeg_buffer) <= MAX_OCR_JPEG_BYTES_V1
        ):
            raise SidecarProtocolErrorV1("image rejected")
        encoded = self._numpy.frombuffer(jpeg_buffer, dtype=self._numpy.uint8)
        try:
            image = self._cv2.imdecode(encoded, self._cv2.IMREAD_COLOR)
        finally:
            del encoded
        if image is None or getattr(image, "ndim", None) != 3 or image.shape[2] != 3:
            raise SidecarProtocolErrorV1("image rejected")
        height = int(image.shape[0])
        width = int(image.shape[1])
        if (
            width <= 0
            or height <= 0
            or width * height > MAX_CANONICAL_PIXELS_V1
            or (expected_width is not None and width != expected_width)
            or (expected_height is not None and height != expected_height)
        ):
            del image
            raise SidecarProtocolErrorV1("image rejected")
        return image

    @staticmethod
    def _result_object_v1(value: object) -> dict[str, Any]:
        if isinstance(value, dict):
            result = value
        else:
            result = getattr(value, "json", None)
            if callable(result):
                result = result()
        if not isinstance(result, dict):
            raise SidecarProtocolErrorV1("OCR result rejected")
        nested = result.get("res", result)
        if not isinstance(nested, dict):
            raise SidecarProtocolErrorV1("OCR result rejected")
        return nested

    def _extract_spans_v1(
        self,
        value: object,
        *,
        width: int,
        height: int,
    ) -> tuple[EngineSpanV1, ...]:
        result = self._result_object_v1(value)
        texts = result.get("rec_texts")
        scores = result.get("rec_scores")
        polygons = result.get("rec_polys")
        for sequence in (texts, scores, polygons):
            if (
                not hasattr(sequence, "__len__")
                or len(sequence) > MAX_OCR_SPANS_PER_PAGE_V1
            ):
                raise SidecarProtocolErrorV1("OCR result rejected")
        if not (len(texts) == len(scores) == len(polygons)):
            raise SidecarProtocolErrorV1("OCR result rejected")
        spans: list[EngineSpanV1] = []
        aggregate_characters = 0
        aggregate_utf8_bytes = 0
        for text, score, polygon_value in zip(
            texts,
            scores,
            polygons,
            strict=True,
        ):
            if (
                not isinstance(text, str)
                or not text
                or len(text) > MAX_OCR_CHARACTERS_PER_SPAN_V1
                or any(unicodedata.category(character) == "Cc" for character in text)
            ):
                raise SidecarProtocolErrorV1("OCR result rejected")
            try:
                encoded_text = text.encode("utf-8", errors="strict")
            except UnicodeError:
                raise SidecarProtocolErrorV1("OCR result rejected") from None
            if len(encoded_text) > MAX_OCR_UTF8_BYTES_PER_SPAN_V1:
                raise SidecarProtocolErrorV1("OCR result rejected")
            aggregate_characters += len(text)
            aggregate_utf8_bytes += len(encoded_text)
            if (
                aggregate_characters > MAX_OCR_AGGREGATE_CHARACTERS_V1
                or aggregate_utf8_bytes > MAX_OCR_AGGREGATE_UTF8_BYTES_V1
            ):
                raise SidecarProtocolErrorV1("OCR result rejected")
            if (
                isinstance(score, bool)
                or not isinstance(score, Real)
                or not math.isfinite(score)
            ):
                raise SidecarProtocolErrorV1("OCR result rejected")
            normalized_score = require_finite_normalized_v1(score)
            try:
                polygon_list = polygon_value.tolist()
            except AttributeError:
                polygon_list = polygon_value
            if not isinstance(polygon_list, (list, tuple)) or len(polygon_list) != 4:
                raise SidecarProtocolErrorV1("OCR result rejected")
            normalized_points: list[tuple[float, float]] = []
            for point in polygon_list:
                if not isinstance(point, (list, tuple)) or len(point) != 2:
                    raise SidecarProtocolErrorV1("OCR result rejected")
                x, y = point
                if (
                    isinstance(x, bool)
                    or isinstance(y, bool)
                    or not isinstance(x, Real)
                    or not isinstance(y, Real)
                    or not math.isfinite(x)
                    or not math.isfinite(y)
                ):
                    raise SidecarProtocolErrorV1("OCR result rejected")
                normalized_points.append(
                    (
                        require_finite_normalized_v1(float(x) / width),
                        require_finite_normalized_v1(float(y) / height),
                    )
                )
            spans.append(
                EngineSpanV1(
                    text=text,
                    polygon=tuple(normalized_points),
                    raw_engine_score=normalized_score,
                )
            )
        return tuple(sorted(spans, key=EngineSpanV1.ordering_key_v1))

    def _infer_image_v1(self, image: Any) -> tuple[EngineSpanV1, ...]:
        height = int(image.shape[0])
        width = int(image.shape[1])
        try:
            output_iterator = iter(self._pipeline.predict(image))
            first = next(output_iterator)
            try:
                next(output_iterator)
            except StopIteration:
                pass
            else:
                raise SidecarProtocolErrorV1("OCR result rejected")
            spans = self._extract_spans_v1(
                first,
                width=width,
                height=height,
            )
        except StopIteration:
            spans = ()
        except SidecarProtocolErrorV1:
            raise
        except Exception:  # noqa: BLE001 - third-party inference boundary
            raise SidecarProtocolErrorV1("OCR inference failed") from None
        finally:
            del image
        verify_no_prohibited_loaded_libraries_v1()
        self._verify_thread_cap_v1()
        return spans

    def infer_v1(
        self,
        jpeg_buffer: bytearray,
        *,
        expected_width: int,
        expected_height: int,
    ) -> tuple[EngineSpanV1, ...]:
        try:
            image = self._decode_v1(
                jpeg_buffer,
                expected_width=expected_width,
                expected_height=expected_height,
            )
        finally:
            jpeg_buffer.clear()
        return self._infer_image_v1(image)

    def warmup_v1(self) -> None:
        try:
            payload = self._manifest.warmup_path.read_bytes()
        except OSError:
            raise ManifestUnavailableV1("OCR warmup unavailable") from None
        buffer = bytearray(payload)
        del payload
        try:
            image = self._decode_v1(
                buffer,
                expected_width=None,
                expected_height=None,
            )
        finally:
            buffer.clear()
        spans = self._infer_image_v1(image)
        try:
            if len(spans) < self._manifest.warmup_expected_minimum_spans:
                raise ManifestUnavailableV1("OCR warmup failed")
        finally:
            del spans


__all__ = ["EngineSpanV1", "PaddleCpuPipelineV1"]
