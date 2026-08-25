FROM python:3.11.11-slim-bookworm

ARG OCR_SOURCE_REVISION
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    OCR_SOURCE_REVISION=${OCR_SOURCE_REVISION} \
    OCR_DEPENDENCY_LOCK_PATH=/opt/certificate-ocr/uv.lock \
    OCR_MODEL_ROOT=/opt/certificate-ocr/models \
    OCR_MANIFEST_PATH=/opt/certificate-ocr/models/model_manifest.json \
    OCR_SOCKET_PATH=/run/openavatarchat-ocr/ocr.sock \
    OCR_EXPECTED_CLIENT_UID=0 \
    OCR_EXPECTED_CLIENT_GID=0 \
    CUDA_VISIBLE_DEVICES="" \
    NVIDIA_VISIBLE_DEVICES=void \
    FLAGS_selected_gpus=""

RUN groupadd --gid 10001 certificate-ocr \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --shell /usr/sbin/nologin certificate-ocr \
    && apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/certificate-ocr

COPY services/certificate_ocr/pyproject.toml \
     services/certificate_ocr/uv.lock \
     /opt/certificate-ocr/
COPY services/certificate_ocr/certificate_ocr \
     /opt/certificate-ocr/certificate_ocr
RUN pip install --no-cache-dir uv==0.8.13 \
    && uv sync --frozen --no-dev

COPY services/certificate_ocr/models /opt/certificate-ocr/models

RUN mkdir -p /run/openavatarchat-ocr \
    && chown -R certificate-ocr:certificate-ocr \
        /run/openavatarchat-ocr /opt/certificate-ocr \
    && chmod 0750 /run/openavatarchat-ocr \
    && chmod -R a-w /opt/certificate-ocr/models

USER 10001:10001

ENTRYPOINT ["/opt/certificate-ocr/.venv/bin/certificate-ocr-sidecar"]
