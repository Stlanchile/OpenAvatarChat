# Admission Notice Lite v1

## Status and Normative Language

This document is the normative architecture, privacy boundary, and threat model
for Admission Notice Lite v1. It freezes the target behavior for milestones
L0–L7. L0 provided the disabled configuration surface, L1 provided the
process-local recognition control plane, L2 provided bounded memory-only
multipart JPEG ingress, and L3 now implements a separately locked local CPU
PaddleOCR sidecar over AF_UNIX. The current schema-v2 real-host qualification
passed and its exact manifest is production-approved. When the matching
sidecar is reachable, L3 performs bounded OCR and discards the validated
result. It does not recognize an admission notice semantically.
Template/college matching, field extraction, major handling, ChatAgent
generation, and WebUI behavior remain requirements for later milestones, not
claims about current runtime behavior.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be
interpreted as normative requirements. An implementation MUST preserve the
fixed values and boundaries in this document. Any change requires a new
protocol version and a corresponding normative revision.

## Fixed Product Contract

Admission Notice Lite v1 supports one fixed institution, one fixed college, and
one internal template:

```text
institution_name = "湖北交通职业技术学院"
college = "交通信息学院"
internal_template_id = "hbtc_traffic_information_admission_notice_v1"
```

The institution and college are application-controlled constants. They MUST
NOT be taken from OCR. The template identifier is internal-only and MUST NOT be
exposed through configuration, an API, headers, status responses, logs, or the
WebUI.

OCR may contribute only these values:

```text
name?
source_province?
major
```

`name` and `source_province` are optional. A successful personalization
requires `major` to match exactly one entry in this closed catalog:

1. `人工智能技术应用`
2. `计算机网络技术`
3. `物联网应用技术`
4. `计算机网络技术(3+2)`
5. `智能交通技术(专本联合培养)`
6. `智能交通技术`
7. `电子商务(3+2)`

Major normalization is a closed structural allowlist. It MUST:

- map `（` to `(` and `）` to `)`;
- map `３` to `3`, `２` to `2`, and `＋` to `+`;
- trim outer whitespace;
- remove whitespace only when it is directly adjacent to `(`, `)`, `+`, `3`,
  or `2`; and
- preserve every other character and every other whitespace occurrence.

General NFKC or other broad Unicode normalization is prohibited. Matching MUST
compare the complete normalized candidate with a complete normalized catalog
entry.

Extraction MUST continue through the structural end of a major qualifier.
Wrapped or split qualifiers remain attached. `startswith`, substring,
first-valid-prefix, shortest-match, and base-major fallback are prohibited.
Observable truncation, unbalanced parentheses, conflicting candidates, or an
unsupported suffix MUST cause abstention.

These prefix-collision pairs are permanent regression cases:

```text
计算机网络技术
计算机网络技术(3+2)

智能交通技术
智能交通技术(专本联合培养)
```

The student roster is qualification input only. No production package,
artifact, test fixture shipped with production, or runtime path may load,
query, or match it.

Admission Notice Lite v1 is not a generic certificate or OCR platform. It does
not support other institutions or colleges, generic templates, authenticity or
enrollment verification, roster lookup, student number, class, gender,
archives, barcode recognition, fuzzy matching, embeddings, LLM/VLM
correction, or multi-template selection.

## Threat Model

The following threats are in scope:

- malformed, truncated, polyglot, oversized, or decompression-bomb JPEGs;
- malformed multipart boundaries, duplicate or unknown fields, excessive
  headers, and oversized bodies;
- malformed or oversized OCR Unix Domain Socket responses;
- bounded CPU or memory exhaustion;
- concurrent submissions across sessions;
- cross-session status, cancellation, or result association;
- stale session associations and recognition identifiers;
- transport replacement or disconnect during recognition;
- OCR failure, timeout, ambiguity, and unsupported majors;
- accidental image, OCR, extracted-context, or prompt persistence or logging;
- document-originated prompt or tool injection;
- ordinary ChatAgent turn contention;
- unapproved outbound application traffic;
- misleading authenticity or enrollment language; and
- cleanup after success, failure, cancellation, disconnect, or expiry.

The following threats are out of scope:

- a malicious root user, operator, or application administrator;
- arbitrary hostile Python already running in the backend process;
- hostile process-memory inspection;
- a compromised operating system, browser, dependency, hypervisor, or
  hardware;
- high-assurance hostile multi-tenancy;
- allocator-level zeroization;
- cryptographic erasure;
- hardware memory isolation;
- distributed denial of service beyond the documented single-process bounds;
  and
- authenticity, issuer, enrollment, or roster verification.

The deployment MUST preserve these invariants:

- the frontend is controlled and same-origin;
- exactly one backend process and worker serves Lite;
- there are no horizontal Lite replicas and no shared recognition-job store;
- the ChatAgent and LLM are local;
- OCR runs in a local CPU-only sidecar; and
- deployment policy enforces the outbound egress allowlist in this document.

## Network Boundary

The target network boundary is:

```text
Frontend ──HTTPS/WSS/RTC──> OpenAvatarChat backend
                                  │
                                  ├── local in-process ChatAgent/LLM
                                  │
                                  ├── UDS ──> CPU OCR sidecar
                                  │
                                  └── approved local TTS endpoint
```

The controlled frontend MAY communicate with its designated backend. The
backend MAY communicate with OCR only through a local Unix Domain Socket and
MAY communicate with one deployment-approved TTS host and port. Only final
assistant response text may be submitted to TTS.

The TTS request MUST NOT contain:

- frames or JPEG bytes;
- OCR text, polygons, or scores;
- extracted fields as a separate payload;
- typed admission context;
- prompts or tool configuration;
- recognition identifiers or states; or
- session correlation values or secrets.

Deployment policy MUST implement this effective allowlist:

```text
ALLOW backend -> approved TTS host/port
DENY  backend -> other outbound destinations
DENY  OCR sidecar -> all network interfaces
ALLOW backend <-> OCR UDS
```

Existing OpenAvatarChat presets are remote-capable and are not automatically
qualified for this boundary. L0 documents the policy only. It does not add
firewall manifests, mTLS, or new PKI. L7 MUST validate the actual deployment
and its selected TTS endpoint.

## Target Architecture

The target data path is:

```text
Controlled WebUI
  explicit action
  1–3 JPEG Blobs in memory
          │
          ▼
Global Lite admission permits, configured capacity (default 1)
  acquired before any request body byte is read
          │
          ▼
Memory-only multipart parser
  exact fields, size and header limits
          │
          ▼
Strict JPEG validation
          │
          ▼
One bounded 1–3-frame UDS request
  sequential CPU OCR in the sidecar
          │
          ▼
Transient bounded OCR spans
          │
          ▼
Fixed HBTC + 交通信息学院 matcher
          │
          ▼
name? / source_province? / exact supported major
          │
          ▼
AdmissionNoticeContextLiteV1
          │
          ▼
Existing per-ChatSession ChatAgent generation lock
  one round, tools disabled
          │
          ▼
AVATAR_TEXT / normal history / Avatar / WS / RTC
          │
          └── assistant response text only -> TTS
```

The global recognition gate is one process-local owner-to-permit registry with
the configured recognition capacity, default one. A permit MUST be claimed
before any request body byte is consumed and held until all frame, OCR,
extraction, and context buffers are released and processing has unwound. It is
not `CaptureCoordinator`, global quiescence, a `WorkFence`, subsystem
suspension, or a generation hierarchy.

## Data Lifecycle and Resource Bounds

All personal input and intermediate recognition data are memory-only:

| Stage | Representation | Maximum lifetime |
|---|---|---|
| Browser | `Blob` and ObjectURL | Revoked on removal, retake, close, completion, and teardown |
| HTTP | Bounded bytearrays | Until validation; never `UploadFile`, `request.form()`, or temporary-file spooling |
| JPEG validation | Immutable encoded bytes plus transient decoded pixels | Decoded pixels released immediately after validation; source bytes released when processor work unwinds |
| OCR | One bounded 1–3-frame UDS request | Request buffers released after the response or disconnect |
| OCR spans | `OcrBatchLiteV1` | Validated and discarded when the L3 processor returns |
| Extracted fields | Local values | Until typed context is built or the job fails |
| Typed context | `AdmissionNoticeContextLiteV1` | Exactly one ChatAgent turn |
| Job record | Identifier, owner, state, times, cancellation handle | In-memory TTL only |
| Assistant response | Existing `AVATAR_TEXT` and normal history | Existing OpenAvatarChat behavior |

The following v1 bounds are frozen:

```text
max_encoded_frame_bytes            = 2,097,152
max_frames                          = 3
max_multipart_overhead_bytes        = 65,536
max_multipart_body_bytes            = 6,356,992
max_part_header_bytes               = 16,384
max_multipart_fields                = 3
max_ocr_request_metadata_bytes      = 8,192
max_ocr_request_jpeg_bytes          = 2,097,152
max_ocr_response_bytes              = 65,536
max_ocr_spans_per_page              = 128
max_ocr_polygon_points              = 4
max_ocr_characters_per_span         = 512
max_ocr_utf8_bytes_per_span         = 2,048
max_ocr_aggregate_characters        = 8,192
max_ocr_aggregate_utf8_bytes        = 32,768
ocr_connect_timeout_seconds         = 1
ocr_timeout_seconds                 = 30
recognition_ttl_seconds             = 120
max_global_recognition_jobs         = 1
```

L2 enforces a long edge of at most 1,920 pixels, a short edge of at most 1,080
pixels, and at most 2,073,600 total pixels. It never resizes or transcodes an
accepted image. Cleanup MUST clear owned containers and drop references on
every terminal path. The implementation MUST NOT claim allocator zeroization
or cryptographic erasure.

## Session and Recognition Ownership

The baseline has no HTTP cookie, request state, or server-owned transport token
that identifies the current `ChatSession`. Its WebSocket `session_id` is
browser-visible and client-selected, while RTC uses its browser-visible
`webrtc_id` or a server fallback. Both identifiers correlate to the exact live
object in `ChatEngine.sessions`, and live duplicates are rejected.

L1 therefore uses the identifier only as a route correlation key. Every
operation resolves it again through `ChatEngine.sessions`. A job retains the
exact owning `ChatSession` object as its in-process identity, so a later object
that reuses the same string cannot read, cancel, or inherit the old job.
`ChatEngine.stop_session()` notifies the Lite service before session cleanup;
the service cancels that exact object's active job. This is the smallest
baseline-supported Case B association. It is not authentication, a capability,
a generation, or a high-assurance multi-tenant boundary.

The deployment's controlled same-origin frontend MUST use only its current
session correlation value. The POST body cannot select an owner or result
target. `target_session_id`, `owner_session_id`, `reply_to_session`,
`chat_session_override`, and equivalent fields are rejected because L2 accepts
only the three fixed frame fields described below.

## L1 Recognition API and Control Plane

Because the baseline has no HTTP-to-session association, L1 uses this narrow
session-prefixed form:

```http
POST   /api/v1/sessions/{session_id}/admission-notice/recognitions
GET    /api/v1/sessions/{session_id}/admission-notice/recognitions/{recognition_id}
DELETE /api/v1/sessions/{session_id}/admission-notice/recognitions/{recognition_id}
```

No unprefixed alternative or additional endpoint is registered. GET and DELETE
retain the payload-free L1 control-plane shape. Query parameters remain
prohibited on every route.

### L2 POST Image Ingestion

The POST now has its final Lite v1 body:

```http
Content-Type: multipart/form-data; boundary=<valid MIME boundary>

frame_1  required  Content-Type: image/jpeg
frame_2  optional  Content-Type: image/jpeg
frame_3  optional  Content-Type: image/jpeg
```

Only these contiguous forms are valid: `frame_1`, `frame_1` plus `frame_2`, or
all three fields. Physical multipart order has no meaning; the processor always
receives canonical `frame_1`, `frame_2`, `frame_3` order. Missing `frame_1`,
gaps, duplicate parts or MIME parameters, `frame_4`, unknown image parts, text
fields, JSON metadata, client-selected recognition identifiers, and owner,
profile, institution, college, or major fields are rejected. Uploaded
filenames are ignored and never enter a contract, status, or log.

Each encoded frame is from 1 through 2,097,152 bytes. The complete multipart
body is at most 6,356,992 bytes, including at most 65,536 bytes of framing
overhead, and each part's aggregate headers are at most 16,384 bytes. A valid
decimal `Content-Length` is used for early rejection and MUST match the actual
byte count, but it is not required. The streamed byte count remains
authoritative. The decimal representation itself is capped at 16 digits before
numeric conversion. Duplicate, overlong, or malformed content lengths, any
`Transfer-Encoding`, and a declared or actual body above the limit are
rejected.

L2 reads `Request.stream()` directly and feeds bounded chunks to
`python-multipart` callbacks. It does not call Starlette `request.form()` or
`request.body()`, construct `UploadFile`, or use spooled or named temporary
files. Exactly one mutable accumulator exists for the current part; it becomes
immutable `bytes` at the narrow parse boundary. No admission-notice payload is
intentionally written to `/tmp`, the repository, a cache, a database, or
manager storage.

Pillow performs strict validation in two passes: open and structural
`verify()`, then reopen and full pixel `load()`. The decoded format must be
JPEG as well as the part media type `image/jpeg`. A bounded JPEG marker/entropy
scan requires the first syntactically valid end-of-image marker to be the final
byte before Pillow is trusted to decode. Missing end-of-image, truncation,
corruption, decoder warnings or errors, malformed metadata detected by Pillow,
decompression-bomb warnings or errors, concatenated images, and any trailing
data are rejected. `image/jpg`, PNG, WebP, and `application/octet-stream` are
not compatibility aliases.

L2 reads only EXIF orientation. Orientations 5–8 swap the logical axes before
the dimensions are recorded and checked. Accepted source bytes are not
transcoded: `ValidatedAdmissionFrameLiteV1` carries the original transient
JPEG, its encoded size, logical width and height, and the validated
`exif_orientation` value so L3 can apply the same orientation before OCR.
GPS, camera model, timestamps, comments, XMP, ICC details, and filenames are
not application state and are never published.

The server creates an opaque identifier in the bounded form
`arn1_<24 base64url characters>`. The identifier contains no session value,
student data, or timestamp. With a trusted injected processor, POST returns
`202`:

```json
{
  "recognition_id": "<opaque server-generated id>",
  "status": "created"
}
```

GET returns only the identifier, a lowercase coarse state, and an allowlisted
reason when one applies:

```json
{"recognition_id": "<opaque server-generated id>", "status": "processing"}
```

The complete L1 state vocabulary is:

```text
CREATED
PROCESSING
COMPLETED
FAILED
CANCELLED
EXPIRED
```

Active transitions are `CREATED -> PROCESSING -> COMPLETED|FAILED`,
`CREATED|PROCESSING -> CANCELLED`, or
`CREATED|PROCESSING -> EXPIRED`. Terminal states never transition. DELETE
atomically cancels the exact owned active job and returns `204 No Content`;
repeating DELETE as the same exact owner is a safe no-op while the retained
record exists. Unknown and cross-session identifiers return the same
`404 RECOGNITION_NOT_FOUND` response.

The process-local `AdmissionNoticeLiteService` owns the registry and all tasks.
One exact session owns at most one active job. The configured global active-job
limit defaults to one, rejects excess work with `SERVICE_BUSY`, and has no
queue. The monotonic 120-second TTL begins at creation and never slides.
Cancellation sets the job event and cancels its owned tasks. A completion that
arrives after cancellation, expiry, session stop, or shutdown is discarded.
Terminal records are retained for at most 30 seconds, capped at 64 records, and
are never persisted. Cleanup is opportunistic plus task-driven; there is no
disabled-mode cleanup loop.

Shutdown closes admission, marks active work cancelled, signals and cancels
owned tasks, waits at most one second, and clears the registry. Processor code
that temporarily ignores cancellation remains unable to publish a late state
transition.

L2 adds only `INVALID_IMAGE`, `IMAGE_TOO_LARGE`,
`IMAGE_DIMENSIONS_UNSUPPORTED`, `TOO_MANY_FRAMES`, and
`UNSUPPORTED_MEDIA_TYPE` to the stable L1 reasons. The HTTP mapping is:

| HTTP | Stable reason and use |
|---:|---|
| 400 | `INVALID_REQUEST` for malformed multipart, fields, gaps, duplicates, query input, or framing; `TOO_MANY_FRAMES` for `frame_4` or a fourth part |
| 413 | `IMAGE_TOO_LARGE` for a declared or actual request/frame byte overflow |
| 415 | `UNSUPPORTED_MEDIA_TYPE` for a non-multipart request, non-`image/jpeg` part, or decoded non-JPEG |
| 422 | `INVALID_IMAGE` for failed strict JPEG validation; `IMAGE_DIMENSIONS_UNSUPPORTED` for a decoded bound violation |
| 409 | `RECOGNITION_ALREADY_ACTIVE` |
| 404 | indistinguishable `RECOGNITION_NOT_FOUND` |
| 503 | `SERVICE_BUSY` or `SERVICE_UNAVAILABLE` |
| 500 | sanitized `INTERNAL_ERROR` |

Pillow, parser, and unexpected processor exception text is neither logged nor
returned.

When `enabled` is false, routes, service, registry, observer, processor, and
tasks are absent. When enabled in production L3, construction performs a
bounded UDS `ping`. It installs `AdmissionNoticeOcrProcessorLiteV1` only when
the sidecar returns the exact protocol, CPU package versions, two-thread tuple,
and qualified model-manifest hash frozen below. If the socket is absent or the
identity differs, the processor remains absent and POST returns
`503 SERVICE_UNAVAILABLE` before consuming the body or creating a job. A
sidecar failure after startup fails only the current job with the existing
coarse `INTERNAL_ERROR` and marks the processor unavailable. Before accepting
the next upload, the service performs one bounded identity ping. It returns a
pre-body `503` while the sidecar is still unavailable or its previous timed-out
native inference is active, and resumes only when the exact qualified identity
is reachable and the one inference worker is ready. This is request-driven
readiness, not a background health monitor; Paddle exception text is never
public.

Tests may still inject a `RecognitionProcessorLiteV1` directly into trusted
construction. No HTTP value, header, environment variable, or production
configuration key can select that fake, and production never uses it as a
fallback.

Before consuming a body byte, the service claims a transient exact-session
admission permit from the configured global recognition capacity. The permit
also prevents concurrent validation for the same live session. Validation
finishes before a job is created, then the service re-resolves the exact
`ChatSession` object and atomically transfers the permit and frame tuple to the
job. A malformed image therefore creates no job. The permit remains held until
the supervisor and processor have actually unwound, including a processor that
temporarily ignores cancellation.

Terminal transition clears the job record's frame tuple immediately. The
processor's call-local tuple may remain only until that task unwinds; then the
last service-owned references and admission permit are released. Success,
processor failure, cancellation, expiry, session teardown, validation failure,
and shutdown use this same bounded ownership rule. Terminal-retention records
contain no frame bytes or image metadata.

If exact-session teardown occurs during a stalled upload, the service cancels
that request task, stops consuming body chunks, returns the same
`404 RECOGNITION_NOT_FOUND` when a response remains possible, and releases the
partial parser buffers and permit. Shutdown and external request cancellation
also release partial multipart ownership in `finally`.

## OCR Process Boundary

L3 uses a deployment-managed process under
`services/admission_notice_ocr/`. The OpenAvatarChat environment imports no
`paddle`, `paddleocr`, `paddlex`, or OpenVINO package. Its stdlib-only
`AdmissionNoticeOcrClientLiteV1` opens one connection to the configurable
`/run/openavatarchat-admission-lite/ocr.sock`, sends the complete 1–3-frame
batch, reads one response, and closes on every path.

Request framing is:

```text
"ANLQ" | uint8 version=1 | uint32 JSON header length
UTF-8 JSON header (maximum 8,192 bytes)
repeat frame_count times:
    uint32 JPEG length
    exact JPEG bytes
EOF on the client write side
```

The strict header contains only `schema_version`, `operation="ocr"`,
`frame_count`, and contiguous per-frame `frame_index`, `encoded_size`,
`logical_width`, `logical_height`, and `exif_orientation`. It contains no
session, recognition, filename, student, college, major, or ChatAgent value.
The sidecar independently enforces 1–3 frames, 2 MiB per JPEG, exact sizes and
indices, the L2 logical dimension/pixel bounds, complete framing, and no
trailing bytes.

The response uses `"ANLR"`, version 1, a bounded uint32 JSON length, and at most
65,536 UTF-8 bytes. A successful OCR response contains only:

```text
OcrSpanLiteV1 {
    text: non-empty UTF-8 string, <= 512 characters and <= 2,048 bytes
    polygon: exactly four [x, y] points normalized to [0, 1]
    score: finite raw Paddle recognition score in [0, 1]
}

OcrFrameLiteV1 {
    frame_index: 1..3
    spans: tuple[OcrSpanLiteV1, ...], <= 128
}

OcrBatchLiteV1 {
    frames: unique contiguous tuple[OcrFrameLiteV1, ...], 1..3
}
```

Each frame is bounded to 8,192 aggregate characters and 32,768 aggregate UTF-8
bytes. Text receives only surrounding transport-whitespace stripping; L3 does
not perform NFKC, punctuation conversion, dictionary correction, province or
major correction, or other semantic normalization. `score` is an uncalibrated
engine scalar, not a probability of field or document correctness. Polygons
are normalized against the explicitly oriented logical image dimensions for
future L4 reading order.

The sidecar decodes the already validated JPEG, applies the supplied EXIF
orientation deterministically, requires the resulting dimensions to match L2,
converts transient pixels for Paddle, and processes frames sequentially through
one warmed model instance. It retains no image or result store. The backend
strictly reparses the bounded response into the immutable contracts, verifies
the exact requested frame set and every text/score/polygon bound, then discards
the `OcrBatchLiteV1`.

The request also permits a payload-free `ping`. Its response contains only this
diagnostic, non-authorizing summary:

```text
OcrRuntimeIdentityLiteV1 {
    backend = "paddle_static"
    device = "cpu"
    thread_count = 2
    paddle_version = "3.3.0"
    paddleocr_version = "3.7.0"
    paddlex_version = "3.7.2"
    model_manifest_sha256 =
      "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"
}
```

This identity is only a startup/qualification diagnostic. It is not an
authority, capability, attestation, calibration identity, or evidence lineage.

The locked sidecar contains the Linux x86-64 `paddlepaddle==3.3.0` CPU wheel,
content-pinned as
`a4f2e0595e827c179b4fff4278fb41a24f4abe5927ffd5efb1ace26a916145f2`,
plus `paddleocr==3.7.0` and the required `paddlex==3.7.2`. It uses the official
`PP-OCRv6_medium_det` and `PP-OCRv6_medium_rec` inference files provisioned from
immutable official PaddlePaddle repository revisions. The tracked
`model_manifest.json` records the SHA-256 and byte size of every
`inference.json`, `inference.pdiparams`, and `inference.yml`. Model binaries are
gitignored. Startup verifies the complete exact file inventory, hashes, package
versions, CPU device, two-thread setting, and runtime flags before importing
the pipeline or creating the socket.

The fixed engine is native `paddle_static` CPU. `enable_hpi`, TensorRT,
document orientation, document unwarping, text-line orientation, and MKL-DNN
are disabled. The selected stack's MKL-DNN path failed real PP-OCRv6 inference
on an unsupported oneDNN array attribute; disabling it is the smallest
evidence-backed correction and preserves the required model family. There is
no backend/device/model auto-selection or fallback.

Normal startup has no model acquisition code. Before Paddle import, the
sidecar replaces `HOME`, XDG, Paddle, PaddleX, Hugging Face, and ModelScope
cache roots with private directories below an explicit ephemeral runtime
directory beside the socket. A developer cache cannot satisfy missing
production assets. Qualification starts each candidate with fresh launch and
runtime cache roots and checks that no model artifact appears there. Deployment
MUST deny all sidecar network access.

The sidecar:

- exposes only a local Unix Domain Socket and no TCP listener;
- requires a sidecar-owned, non-group/non-other-writable runtime directory
  (normally mode `0750` or tighter) and creates the AF_UNIX node with mode `0660`;
- runs one process, one warmed pipeline, and one active inference;
- uses no GPU, CUDA, remote OCR, fallback, or runtime model download;
- uses strict, bounded request framing and JSON response parsing;
- remains independently restartable so a crash does not crash the backend; and
- omits images, OCR text, and personal fields from logs.

One daemon inference thread serializes calls into the warmed Paddle pipeline,
so the asyncio listener and signal handlers remain responsive during native
OCR. SIGINT/SIGTERM stops accepts, waits up to five seconds, removes its owned
socket, and abandons an unfinished native call when the sidecar process exits.
Backend task cancellation closes the connection and stops waiting. During
ordinary continued service, Paddle C++ may finish an already-running inference;
the disconnected result is discarded before the single warmed pipeline serves
the next request. No generation fence or cross-process cleanup handshake is
added.

The OCR boundary enforces every request, response, span, polygon, character,
byte, and timeout bound listed here. Lite does not carry
`CaptureEpoch`, `WorkFence`, encrypted evidence stores, receipts, private
authorities, HMAC request authority, or hardened inference lineage into this
boundary.

### L3 Runtime Qualification

The machine-readable
[`qualification.json`](../../../services/admission_notice_ocr/qualification/qualification.json)
currently records `PASS`. Its source hash remains the exact hash produced by
the real pre-approval host run. The later approval constant is intentionally
the only differing source byte-set and is verified separately; the report hash
was not rewritten to imply that the run used an enabled gate. The approved
model manifest SHA-256 is
`1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b`;
the selected backend is `paddle_static`, the device is CPU, and the selected
thread count is two. The report records successful real AF_UNIX integration,
the real backend client and isolated sidecar, typed `OcrBatchLiteV1`, offline
model use, and a production-shaped processor path reaching `COMPLETED`. GPU
instrumentation collected live samples and observed no sidecar allocation.
The earlier schema-v1 `PASS` remains stale and is not accepted.

Qualification has two explicit dependency lanes. The sidecar-only command runs
inside `services/admission_notice_ocr/.venv`, imports no FastAPI or
OpenAvatarChat module, generates sidecar-native non-sensitive
Chinese/English/digit JPEGs, and directly qualifies the real Paddle pipeline:

```bash
cd /home/xs/projects/OpenAvatarChat-admission-lite/services/admission_notice_ocr
.venv/bin/python -m admission_notice_ocr.qualify --sidecar-only
```

It verifies the exact hashed CPU wheel and installed RECORD files, model
manifest, fresh offline cache roots, CPU device, loaded libraries, GPU
observation where available, determinism, startup, model initialization,
first/warmed latency, RSS, CPU, errors, and the `1, 2, 4, 6, 8` thread matrix.
Its ignored `qualification/sidecar-qualification.json` is intermediate
evidence only. A sidecar-only `PASS` cannot produce a final qualification or
enable production.

The main-environment controller consumes that bounded evidence, generates the
same class of synthetic JPEGs through the actual L2 validator, and launches the
sidecar with its own Python executable and a sanitized environment:

```bash
cd /home/xs/projects/OpenAvatarChat-admission-lite
/home/xs/projects/OpenAvatarChat/.venv/bin/python \
  scripts/admission_notice_lite_l3_qualify.py
```

It exercised the real backend client, AF_UNIX listener, framed request
and response, typed `OcrBatchLiteV1`, production processor/service lifecycle,
and terminal `COMPLETED` path, then combined both lanes into the tracked
schema-v2 report. It never imported Paddle into the main environment, and the
sidecar never imported the main service.

The reviewed production gate now approves exactly the qualified manifest above.
Production construction is eligible only when the sidecar ping also matches
`paddle_static`, CPU, two threads, PaddlePaddle 3.3.0, PaddleOCR 3.7.0,
PaddleX 3.7.2, and the exact manifest hash. Missing service, stale or invalid
qualification evidence, or any runtime identity mismatch remains fail-closed.
The approval constant is not a model registry, fallback, or dynamic artifact
authorization mechanism. A representative Avatar/RTC workload was not
available during qualification.
Operational commands and all six model artifact hashes are documented in the
[`sidecar README`](../../../services/admission_notice_ocr/README.md).

In L3, a successful processor return and job `COMPLETED` mean only:

> The configured local OCR pipeline successfully processed the submitted
> frames.

It does not mean the document is an HBTC admission notice, the college is
交通信息学院, any name/province/major was extracted, any major is supported, or
personalization occurred. No template/college matcher or field recognition
exists in production L3.

## ChatAgent Turn Boundary

The future one-turn context is:

```text
AdmissionNoticeContextLiteV1 {
    institution_name = "湖北交通职业技术学院"
    college = "交通信息学院"
    name?
    source_province?
    major
}
```

`major` is mandatory and exact-catalog validated. Institution and college are
server-owned constants. The context is frozen, server-owned, and redacted in
representations. Document values MUST be represented explicitly as untrusted
data. The context is not `HUMAN_TEXT`, synthetic history, WorkingMemory
writeback, or manager state.

The Lite entry method MUST omit tools and run exactly one generation round.
Subsequent ordinary turns restore normal tool behavior. Final output follows
the existing `AVATAR_TEXT`, history, Avatar, WebSocket/RTC, and TTS paths.

Lite MUST reuse the clean baseline `ChatAgentContext._generate_lock` through a
narrow ChatAgent entry method:

- the method acquires the same per-session lock used by ordinary generation;
- it MUST NOT use the baseline ordinary-turn force-continue behavior after a
  lock timeout;
- if the lock cannot be acquired within the remaining recognition deadline,
  the job fails before the typed context is constructed;
- while Lite owns the lock, no ordinary or proactive generation starts;
- cancellation or expiry becomes terminal only after locked generation has
  stopped and context references have been dropped; and
- this ordering remains per-session and MUST NOT suspend ChatAgent globally.

Prompts, tests, and output policy MUST prohibit claims such as `verified`,
`authentic`, `official verification passed`, `genuine admission notice`,
`enrollment confirmed`, `已验证`, `真伪核验通过`, and `录取资格已确认`.

## Privacy, Logging, and Authenticity

Images, OCR text, polygons, scores, extracted fields, typed context, prompts,
and session correlation values MUST NOT enter persistent storage, ordinary
history, telemetry payloads, or TTS as separate data. Logs may contain an
opaque recognition identifier, payload-free reason codes, counts, coarse
states, and durations. Logs MUST NOT contain filenames, session identifiers,
prompts, OCR, extracted personal fields, image content, request bodies, or raw
exception text.

All success, failure, cancellation, disconnect, replacement, and expiry paths
MUST release transient references. Document-originated instructions MUST remain
untrusted data and MUST NOT enable tools or alter system policy.

Admission Notice Lite personalizes an assistant response from a narrowly
matched document. It does not verify authenticity, issuer identity, enrollment,
eligibility, or roster membership. User-facing text MUST NOT imply any such
verification.

## Migration and Reuse Boundaries

The Lite branch is rooted at
`8b7b3b45bca28ae9ab5fa72ee31bc03c5a99b08b`, the final commit before the
certificate architecture. Hardened certificate commits MUST NOT be
cherry-picked into Lite. Reuse is manual and focused:

| Area | Decision | Lite boundary |
|---|---|---|
| Image and multipart ingress | Rewrite | Strict JPEG validation and memory-only bounded parsing; no capture routes or capabilities |
| Frozen image limits | Port values | Lite constants only; no capture lifecycle limits |
| OCR contracts and UDS | Rewrite | Bounded page spans and sequential CPU-only requests; no epochs, identities, receipts, or authority |
| Reading order | Port algorithm | Remove hardened imports and provenance |
| Institution, college, name, province, and major matching | Rewrite | One fixed HBTC/交通信息学院 extractor and the closed seven-major catalog |
| Typed context and one-turn generation | Rewrite narrowly | Reuse only the baseline per-session generation lock; no release authority or declassification envelope |
| Browser image preparation and camera handoff | Manual later port | Rewrite protocol vocabulary and cleanup for Lite in L6 |
| Hardened frontend API and state machine | Drop | Build the asynchronous Lite API/composable in L6 |
| Authentication, lineage, fencing, coordination, encrypted evidence, and release authority | Drop | No OIDC/JWKS, security envelopes, `WorkFence`, `CaptureCoordinator`, private store, or declassification framework |
| Generic profiles, Q&A, certificates, and TTS concepts | Drop | Fixed product contract only |

The frontend remains at its clean pre-certificate gitlink until L6. L0 MUST NOT
create a nested frontend branch or change the gitlink.

## Milestone Sequence

Implementation is divided into these hard boundaries:

| Milestone | Deliverable |
|---|---|
| L0 | Isolated branch/worktree, this normative document, and disabled-only configuration |
| L1 | Process-local job/ownership service, empty-body `POST`/`GET`/`DELETE`, fail-closed processor seam, and test-only fake |
| L2 | Global body-admission gate plus memory-only multipart/JPEG ingress on the L1 routes |
| L3 | CPU OCR sidecar and real qualification |
| L4 | Fixed matcher, extractors, normalization, and seven-major catalog |
| L5 | Typed one-turn ChatAgent personalization and per-session ordering |
| L6 | Manual WebUI port |
| L7 | Fixtures, end-to-end tests, and deployment qualification |

L1 is limited to `RecognitionJobLiteV1`, server-generated recognition
identifiers, exact live-session correlation, one active job per session,
bounded global capacity and terminal retention, TTL, cancellation, the coarse
state model, three empty-body routes, a fail-closed processor seam, and a
dependency-injected test fake. It MUST NOT parse multipart, decode JPEG, start
OCR, recognize an admission notice, or change ChatAgent, TTS, WebSocket, RTC,
history, or WebUI behavior.

L2 replaces only the POST's historical empty body with the bounded multipart
contract above, adds `ValidatedAdmissionFrameLiteV1`, and passes its frame tuple
through the processor seam. L3 adds only the qualified CPU OCR sidecar,
protocol, typed transient OCR batch, client, and real processor described
above. Admission Notice Lite can now perform real local CPU OCR, but it cannot
understand the admission notice semantically.

Later regression suites MUST permanently cover prefix collisions, cross-session
isolation, stale identifiers, admission before body reads, global and
per-session capacity, sequential OCR, resource bounds, tool suppression,
per-session turn ordering, cleanup/privacy, and prohibited authenticity
wording.

## L0 and L1 Configuration

L0 introduced the section with `enabled: false`. L1 activated its two
control-plane limits, and L3 now accepts only the three operational OCR
connection values it needs:

```yaml
default:
  service:
    admission_notice_lite:
      enabled: false
      recognition_ttl_seconds: 120
      max_global_recognition_jobs: 1
      ocr_socket_path: /run/openavatarchat-admission-lite/ocr.sock
      ocr_connect_timeout_seconds: 1.0
      ocr_timeout_seconds: 30.0
```

Omitting `admission_notice_lite` produces a fresh disabled default. L1 accepts
strict boolean `enabled`; numeric, string, and null substitutes are rejected.
TTL is a strict integer from 1 through 3600. The configured global active-job
limit is a strict integer from 1 through 32. Unknown Lite keys are rejected
with the ordinary Pydantic `ValidationError`. Existing YAML presets remain
unchanged and default to disabled by omission.

`ocr_socket_path` is a bounded absolute Unix path. The connect timeout is a
strict float from 0.05 through 2 seconds and defaults to 1 second. The overall
write/inference/read timeout is a strict float from 1 through 60 seconds and
defaults to 30 seconds. School, college, profile, template, catalog, backend,
device, model-family, thread-count, and fake-processor configuration remain
prohibited; the production tuple comes only from the qualified manifest and
startup identity.

The following are fixed v1 invariants, not configuration:

- at most three frames;
- one active job per session;
- one backend process and worker;
- the exact JPEG, multipart, OCR, and lifetime bounds in this document; and
- institution, college, internal template identity, and the major catalog.

School, college, profile, template, and catalog configuration are prohibited.

## L0 Non-Goals

L0 introduced no HTTP route, request-body consumer, multipart handling, JPEG
decoding, OCR contract or process, job, session association, fake adapter,
ChatAgent behavior, TTS behavior, frontend change, dependency, listener,
firewall manifest, PKI, or runtime integration. L1 added only the control-plane
items described above. L2 adds only the memory-only multipart/JPEG ingress and
processor-frame seam described above. L3 adds only the local CPU OCR layer; it
adds no extractor, ChatAgent, TTS, or frontend behavior.

L3 qualification does not qualify an HBTC template, field extraction, a
remote-capable preset, TTS deployment, Avatar/RTC contention, horizontal
scaling, or end-to-end personalization. Those claims require their assigned
later milestones.
