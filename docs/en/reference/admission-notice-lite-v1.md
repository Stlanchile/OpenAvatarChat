# Admission Notice Lite v1

## Status and Normative Language

This document is the normative architecture, privacy boundary, and threat model
for Admission Notice Lite v1. It freezes the target behavior for milestones
L0–L7. L0 provided the disabled configuration surface. L1 now provides only
the process-local recognition control plane and its empty-body HTTP routes.
Image ingress, recognition, OCR, extraction, ChatAgent generation, and WebUI
behavior remain requirements for later milestones, not claims about current
runtime behavior.

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
Global Lite recognition gate, capacity 1
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
Sequential per-frame CPU OCR over UDS
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

The global recognition gate is one lightweight semaphore with capacity one. It
MUST be acquired before any request body byte is consumed and held until all
frame, OCR, extraction, and context buffers are released and the job reaches a
terminal state. It is not `CaptureCoordinator`, global quiescence, a
`WorkFence`, subsystem suspension, or a generation hierarchy.

## Data Lifecycle and Resource Bounds

All personal input and intermediate recognition data are memory-only:

| Stage | Representation | Maximum lifetime |
|---|---|---|
| Browser | `Blob` and ObjectURL | Revoked on removal, retake, close, completion, and teardown |
| HTTP | Bounded bytearrays | Until validation; never `UploadFile`, `request.form()`, or temporary-file spooling |
| JPEG validation | Encoded bytes plus transient decoded pixels | Decoded pixels released immediately after validation |
| OCR | One frame per UDS request | Frame released after its response |
| OCR spans | Bounded typed objects | Until matching and extraction finish |
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
max_ocr_result_json_bytes           = 49,152
ocr_timeout_seconds_per_frame       = 30
recognition_ttl_seconds             = 120
max_global_recognition_jobs         = 1
```

Cleanup MUST clear owned containers and drop references on every terminal
path. The implementation MUST NOT claim allocator zeroization or cryptographic
erasure.

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
`chat_session_override`, and equivalent fields are rejected because L1 accepts
no request body.

## L1 Recognition API and Control Plane

Because the baseline has no HTTP-to-session association, L1 uses this narrow
session-prefixed form:

```http
POST   /api/v1/sessions/{session_id}/admission-notice/recognitions
GET    /api/v1/sessions/{session_id}/admission-notice/recognitions/{recognition_id}
DELETE /api/v1/sessions/{session_id}/admission-notice/recognitions/{recognition_id}
```

No unprefixed alternative or additional endpoint is registered. L1 POST has
an intentionally empty body and requires explicit `Content-Length: 0`; it
rejects query parameters, missing or malformed content length, non-empty
bodies, and transfer-encoded bodies without consuming them. L2 will add the
final bounded multipart frame ingestion to this same POST. L1 does not accept
a temporary JSON payload, mock selector, debug header, image, frame, or OCR
input.

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

The stable L1 reasons are `INVALID_REQUEST`, `SERVICE_UNAVAILABLE`,
`SERVICE_BUSY`, `RECOGNITION_ALREADY_ACTIVE`, `RECOGNITION_NOT_FOUND`,
`RECOGNITION_CANCELLED`, `RECOGNITION_EXPIRED`, and `INTERNAL_ERROR`.
Unexpected processor exception text is neither logged nor returned.

When `enabled` is false, routes, service, registry, observer, processor, and
tasks are absent. When enabled in production L1, no processor is installed:
POST returns `503 SERVICE_UNAVAILABLE` and creates no job. Tests may inject a
payload-free `RecognitionProcessorLiteV1` directly into trusted construction.
No HTTP value, header, environment variable, or production configuration key
can select that fake. Fake completion means only that the control-plane call
ended; it performs no admission-notice recognition and has no ChatAgent, TTS,
history, WebSocket, or RTC side effect.

L2 MUST acquire its global body-admission gate before consuming request bytes
and MUST use memory-only multipart ingress. Starlette form parsing,
`UploadFile`, and temporary-file spooling remain prohibited.

## OCR Process Boundary

The backend sends one validated JPEG per OCR UDS request, sequentially, at most
three times per job. The sidecar MUST:

- expose only a local Unix Domain Socket and no TCP listener;
- run CPU-only with a fixed thread count;
- use no GPU, CUDA, remote OCR, fallback, or runtime model download;
- use strict, bounded request framing and JSON response parsing;
- remain independently restartable so a crash does not crash the backend;
- stop active work when cancellation closes the UDS request; and
- omit images, OCR text, and personal fields from logs.

The OCR boundary MUST enforce every request, response, span, polygon, character,
byte, and timeout bound listed in this document. Lite MUST NOT carry
`CaptureEpoch`, `WorkFence`, encrypted evidence stores, receipts, private
authorities, or hardened deployment manifests into this boundary. L0 starts no
OCR process and creates no OCR code.

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

Later regression suites MUST permanently cover prefix collisions, cross-session
isolation, stale identifiers, admission before body reads, global and
per-session capacity, sequential OCR, resource bounds, tool suppression,
per-session turn ordering, cleanup/privacy, and prohibited authenticity
wording.

## L0 and L1 Configuration

L0 introduced the section with `enabled: false`. L1 activates only the two
control-plane limits it needs:

```yaml
default:
  service:
    admission_notice_lite:
      enabled: false
      recognition_ttl_seconds: 120
      max_global_recognition_jobs: 1
```

Omitting `admission_notice_lite` produces a fresh disabled default. L1 accepts
strict boolean `enabled`; numeric, string, and null substitutes are rejected.
TTL is a strict integer from 1 through 3600. The configured global active-job
limit is a strict integer from 1 through 32. Unknown Lite keys are rejected
with the ordinary Pydantic `ValidationError`. Existing YAML presets remain
unchanged and default to disabled by omission.

These keys remain deferred and MUST NOT be accepted in L1:

| Key | Future default | Owner |
|---|---:|---|
| `ocr_timeout_seconds` | `30` | L3 |
| `ocr_socket_path` | `/run/openavatarchat-admission-lite/ocr.sock` | L3 |

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
firewall manifest, PKI, or runtime integration. L1 adds only the control-plane
items described above.

L0 also does not qualify OCR, a remote-capable preset, a TTS deployment,
horizontal scaling, or end-to-end behavior. Those claims require their assigned
later milestones. L0 stops after the normative document, disabled-only model,
its `ServiceConfigData` field, and focused static/configuration tests.
