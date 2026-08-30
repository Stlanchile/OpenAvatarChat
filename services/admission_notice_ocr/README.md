# Admission Notice Lite CPU OCR Sidecar

This service is the private L3 OCR process for Admission Notice Lite v1. It
loads exactly one PP-OCRv6 medium detection/recognition pipeline, listens on one
local Unix Domain Socket, processes one request at a time, and exposes no TCP,
HTTP, REST, WebSocket, or public OCR endpoint.

## Fixed runtime

The production-approved runtime tuple is:

```text
Python       3.11.16
Paddle       paddlepaddle 3.3.0 CPU wheel
wheel SHA256 a4f2e0595e827c179b4fff4278fb41a24f4abe5927ffd5efb1ace26a916145f2
PaddleOCR    3.7.0
PaddleX      3.7.2 (required by PaddleOCR 3.7)
engine       paddle_static
device       cpu
threads      2
models       PP-OCRv6_medium_det + PP-OCRv6_medium_rec
manifest     1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b
```

`enable_hpi`, TensorRT, document orientation, document unwarping, text-line
orientation, and MKL-DNN are disabled. An earlier real Paddle 3.3.0 run showed
that the MKL-DNN path cannot execute an array-valued PP-OCRv6 model attribute.
The fixed `paddle_static` CPU path with MKL-DNN disabled passed the current
schema-v2 host qualification. Manifest
`1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b`
is explicitly production-approved. There is no device, backend, or model
fallback.

The lock resolves the Linux x86-64 `paddlepaddle`, not `paddlepaddle-gpu`, CPU
wheel from Paddle's official package host by direct URL and verifies the wheel
SHA-256 above. PaddleX and OpenCV are required transitive OCR dependencies. The
locked tree contains no NVIDIA, CUDA, cuDNN, TensorRT, OpenVINO, ONNX Runtime,
FastAPI, Starlette, or web-server package. Paddle's CPU wheel may map bundled
`libopenvino` implementation libraries internally; that does not select HPI or
an OpenVINO backend. The configured engine remains `paddle_static`.

## Create the locked environment

From the repository root:

```bash
uv sync \
  --frozen \
  --project services/admission_notice_ocr \
  --no-dev \
  --python 3.11
```

This creates only
`services/admission_notice_ocr/.venv`. Paddle packages are not added to the
OpenAvatarChat root environment.

## Provision and verify models

Provisioning is an explicit build/operator action:

```bash
uv run \
  --frozen \
  --project services/admission_notice_ocr \
  --no-dev \
  python -m admission_notice_ocr.provision_models
```

The provisioner fetches only `inference.json`, `inference.pdiparams`, and
`inference.yml` from immutable revisions of the official PaddlePaddle
Hugging Face repositories:

```text
PaddlePaddle/PP-OCRv6_medium_det
revision 8e0f56fb2ef86b461d99cfc7ac5c137738985f61

PaddlePaddle/PP-OCRv6_medium_rec
revision e5a92bcbc5cc1b494628e458d267778f0704fd7c
```

Every source size and SHA-256 is pinned in `provision_models.py`. The generated
`model_manifest.json` repeats the six installed artifact hashes and fixes the
runtime tuple. Verify without network access:

```bash
uv run \
  --frozen \
  --project services/admission_notice_ocr \
  --no-dev \
  python -m admission_notice_ocr.provision_models --verify-only
```

The binaries under `models/` are intentionally gitignored. Normal sidecar
startup contains no downloader. A missing, extra, symlinked, or hash-mismatched
model file, package-version mismatch, non-CPU device, or runtime-flag mismatch
fails startup before the socket is created.

## Start the sidecar

The deployment supervisor owns the process and its run directory. Prepare
`/run/openavatarchat-admission-lite` as a sidecar-owned directory with mode
`0750` (or tighter). The shared backend group may traverse the directory but
MUST NOT have directory write permission. Run the sidecar with that shared
group so the backend can open the socket:

```bash
uv run \
  --frozen \
  --project services/admission_notice_ocr \
  --no-dev \
  python -m admission_notice_ocr.app \
  --socket-path /run/openavatarchat-admission-lite/ocr.sock
```

The socket path is configurable and defaults to the path above. The created
AF_UNIX node has mode `0660`; owner/group follow the sidecar process and parent
directory policy. Startup refuses a symlinked, foreign-owned, group-writable,
or other-writable parent because write access would allow socket replacement
and disclosure of submitted JPEGs. It removes only an owned, confirmed-stale
Unix socket and refuses regular files, symlinks, foreign sockets, live sockets,
missing parents, and unsafe paths.

Start the sidecar before OpenAvatarChat. The backend performs its bounded
identity ping during service construction. If that initial gate fails, it keeps
the processor absent and returns pre-body `503 SERVICE_UNAVAILABLE`. If a
previously ready sidecar later disappears, the current job fails coarsely and
marks OCR unavailable. Before accepting the next upload, the backend performs
one bounded identity ping: it returns pre-body `503` while the sidecar is down
or an earlier timed-out native inference is still active, and resumes when the
exact qualified sidecar is reachable and its single inference worker is ready.
There is no background health monitor.

The sidecar replaces `HOME`, XDG, Paddle, PaddleX, Hugging Face, and ModelScope
cache roots with private directories under `ocr-runtime` beside the socket
before importing Paddle. Explicit model directories are always supplied. A
developer cache cannot satisfy a missing production model; the runtime cache
must not contain model artifacts and may be placed on an ephemeral runtime
filesystem.

Run exactly one sidecar worker. Recommended deployment policy is:

- enforce no outbound network and deny all sidecar network access;
- provide no GPU device;
- allow one process and the fixed two CPU inference threads;
- budget about 0.8 GiB RSS plus supervisor margin;
- use the bounded socket backlog already configured by the service; and
- let the supervisor restart the sidecar independently of OpenAvatarChat.

One daemon inference thread owns calls into the one warmed Paddle pipeline;
the asyncio listener remains responsive while native OCR runs. SIGINT/SIGTERM
stops new accepts, closes the server, waits at most five seconds for client
handlers, abandons an unfinished native call at process exit, and removes only
the socket node created by this process. After an ordinary backend disconnect,
Paddle C++ inference may finish and its result is discarded before the warmed
pipeline serves the next request.

## Tests and qualification lanes

Ordinary unit/protocol tests do not import Paddle or require model binaries:

```bash
PYTHONPATH=src \
  /home/xs/projects/OpenAvatarChat/.venv/bin/pytest \
  -q tests/service/test_admission_notice_lite_l3.py
```

Sidecar-only qualification runs entirely in this locked environment. It imports
only `admission_notice_ocr`, stdlib, and locked sidecar dependencies. It
generates sidecar-native synthetic JPEG frames, launches each `1, 2, 4, 6, 8`
candidate in a fresh user/network namespace and cache tree, and directly
measures real Paddle inference:

```bash
cd /home/xs/projects/OpenAvatarChat-admission-lite/services/admission_notice_ocr
.venv/bin/python -m admission_notice_ocr.qualify --sidecar-only
```

This writes the ignored intermediate
`qualification/sidecar-qualification.json`. A sidecar-only `PASS` is not a
production qualification and cannot enable the production gate.

Full integration qualification runs from the OpenAvatarChat environment. It
uses the real L2 JPEG validator and typed frame contract, launches
`services/admission_notice_ocr/.venv/bin/python` with a sanitized environment,
opens a real AF_UNIX connection through the production backend client, validates
the real `OcrBatchLiteV1`, and requires the production processor/service path
to reach coarse `COMPLETED`:

```bash
cd /home/xs/projects/OpenAvatarChat-admission-lite
/home/xs/projects/OpenAvatarChat/.venv/bin/python \
  scripts/admission_notice_lite_l3_qualify.py
```

The sidecar lane owns the package/model/cache/CPU/thread matrix and real direct
Paddle measurements. The main lane consumes only its bounded evidence file,
adds real AF_UNIX/backend-client/processor evidence, and alone may write the
final tracked `qualification/qualification.json`. Both commands print exactly
`PASS`, `BLOCKED`, or `FAIL`. Neither command changes the reviewed production
gate.

The opt-in real integration test launches the isolated sidecar, constructs the
real processor through the production builder, submits synthetic JPEGs through
the public multipart route, and requires coarse `COMPLETED`:

```bash
cd /home/xs/projects/OpenAvatarChat-admission-lite
ADMISSION_NOTICE_OCR_RUN_REAL=1 \
  /home/xs/projects/OpenAvatarChat/.venv/bin/pytest \
  -q -m admission_notice_ocr_integration \
  tests/service/test_admission_notice_lite_l3_qualification.py
```

The current `qualification/qualification.json` is a schema-v2 host `PASS`.
It records real AF_UNIX bind/connect, the backend client and isolated sidecar,
typed `OcrBatchLiteV1`, CPU-only Paddle inference, offline model use, the
`1, 2, 4, 6, 8` thread matrix, and coarse processor `COMPLETED`. The selected
production tuple is `paddle_static`, CPU, two threads. The earlier schema-v1
`PASS` remains stale and is not accepted.
Reports contain no OCR transcript, image, student data, private path, or
private fixture identifier. Optional private fixtures belong only in the
ignored `qualification/private-fixtures/` directory with opaque filenames.

`src/service/admission_notice_lite_ocr_qualification.py` is the reviewed
production gate. It now approves only manifest
`1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b`.
Production construction still requires the exact qualified runtime identity
and a reachable sidecar; approval adds no fallback. The pre-approval
qualification controller requires the gate to be `None` and must not be rerun
as post-approval evidence. The PASS report retains its original pre-approval
source hash; approval is verified separately and does not rewrite that
provenance.
