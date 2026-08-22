# Secure Certificate Capture and Grounded Answering V1 — Base Specification

## Status

This document is the canonical Base V1 specification for Secure Certificate
Capture and Grounded Answering in OpenAvatarChat. Additive specifications may
reserve future behavior, but they do not weaken or replace these base
requirements unless they explicitly amend this document.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in
this document are normative.

## 1. Architecture and Security Invariants

Implement an opt-in certificate mode across OpenAvatarChat and `OpenAvatarChat-WebUI`:

1. Authenticate the principal and create a server-owned session.
2. Quiesce normal camera Perception, ChatAgent, microphone input, proactive output, and generic TTS.
3. Return `ARMED` only after epoch-bound barrier acknowledgements.
4. Upload certificate frames through a dedicated private HTTPS interface.
5. Seal the frame set and build calibrated assertions.
6. Keep the capture in `READY` while independent query jobs use those assertions.
7. Delete all capture/query/speech material on EndCapture, timeout, disconnect, failure, or session replacement.

Fixed invariants:

- Sensitive classification occurs in the engine core before sink delivery, history, logging, Perception, or ChatAgent.
- Raw frames, OCR, assertions, queries, answers, and certificate speech never enter generic ChatAgent, SessionHistory, memory writeback, manager tools, ordinary TTS, or generic avatar text/audio.
- ChatAgent tools are not a V1 trigger. Deferred/suspend tool semantics remain out of scope.
- V1 extracts text only; it never verifies certificate authenticity or issuer validity.
- Normal camera and microphone input are dropped—not buffered—while certificate mode is active.
- The feature is disabled by default and requires TLS, OIDC, authenticated session binding, a healthy GPU OCR sidecar, and matching calibration artifacts.

## 2. Normative Lifecycle and Epoch Contracts

### Capture lifecycle

`CaptureStateV1` contains exactly:

```text
IDLE
ENTERING
QUIESCING
ARMED
CAPTURING
BUILDING_ASSERTIONS
READY
ENDING
FAILED_CLOSED
```

Allowed transitions:

```text
IDLE → ENTERING → QUIESCING → ARMED
ARMED → CAPTURING                         first accepted frame
CAPTURING → BUILDING_ASSERTIONS          successful seal
BUILDING_ASSERTIONS → READY               assertion build completes
any non-IDLE state → ENDING → IDLE        authenticated EndCapture
any active state → FAILED_CLOSED           security/runtime failure
FAILED_CLOSED → ENDING → IDLE             proven cleanup
FAILED_CLOSED → session termination        cleanup cannot be proven
```

`ANSWERING` is not a capture state. The capture remains `READY` while queries and speech jobs execute.

### Seal and recapture semantics

`NEEDS_RECAPTURE` is a `SealOutcomeV1`, never a `CaptureStateV1`.

A valid seal request returns:

```text
SealResultV1 {
  seal_attempt_seq,
  outcome: BUILD_STARTED | NEEDS_RECAPTURE,
  capture_state,
  accepted_frame_count,
  independent_correlation_groups,
  remaining_frame_slots,
  reason_codes[],
  restart_required
}
```

Rules:

- `BUILD_STARTED` atomically changes `CAPTURING → BUILDING_ASSERTIONS`; further frame uploads are rejected.
- `NEEDS_RECAPTURE` leaves the capture in `CAPTURING`.
- Reason codes are limited to `TOO_FEW_UNIQUE_FRAMES`, `BLUR`, `GLARE`, `CROP`, `SKEW`, `DUPLICATE_DOMINANCE`, and `DOCUMENT_NOT_DETECTED`.
- The client may upload additional sequences until the eight-frame limit.
- When no slots remain, `restart_required=true`; the WebUI must EndCapture and begin a new capture.
- OCR conflicts discovered after a successful seal produce `READY` assertions with `CONFLICTED` or `INSUFFICIENT` decisions. They do not retroactively produce `NEEDS_RECAPTURE`.
- A syntactically valid seal attempt resets the inactivity timer, including a `NEEDS_RECAPTURE` result.

### Independent query lifecycle

Each query has its own `QueryEpochV1` and `QueryStateV1`:

```text
RECEIVED
VALIDATING
RESOLVING_ASSERTIONS
RENDERING
COMPLETED
REJECTED
FAILED
CANCELLED
EXPIRED
```

Normal path:

```text
RECEIVED → VALIDATING → RESOLVING_ASSERTIONS → RENDERING → COMPLETED
```

`QueryOutcomeV1` is separate from lifecycle state:

```text
ANSWERED
UNSUPPORTED_QUESTION
NO_SUPPORTED_ASSERTION
```

Rules:

- Queries are accepted only while the associated capture is `READY`.
- The capture remains `READY` for the query’s entire lifecycle.
- Only one distinct query may be active per capture. A duplicate `query_id` returns the existing status/result; a different concurrent query returns `QUERY_BUSY`.
- Unsupported questions complete with `UNSUPPORTED_QUESTION` and the supported-field list; they are not processing failures.
- A local rendering failure changes only the query to `FAILED`. Envelope, store, identity, or calibration-integrity failure changes the capture to `FAILED_CLOSED`.
- EndCapture cancels active queries. Inactivity expiry marks them `EXPIRED`.
- Query text, intermediate resolution, and results remain private and are deleted with the capture.

Local speech uses a separate lifecycle:

```text
SpeechJobStateV1:
QUEUED → SYNTHESIZING → READY
QUEUED | SYNTHESIZING → FAILED | CANCELLED | EXPIRED
```

Speech references a completed query. TTS failure does not invalidate the text answer or change capture state.

### Formal epochs

Define:

```text
SessionEpochV1 {
  session_instance_id: UUIDv7,
  generation: uint64
}

CaptureEpochV1 {
  session_epoch: SessionEpochV1,
  capture_id: UUIDv7,
  capture_seq: uint64
}

QueryEpochV1 {
  capture_epoch: CaptureEpochV1,
  query_id: UUIDv7,
  query_seq: uint64
}
```

Rules:

- `session_instance_id` is minted on authenticated session creation. Reconnect, replacement, or process restart creates a new value.
- `generation` starts at one and never decreases within a session instance.
- After replay validation, BeginCapture atomically increments `generation`, installs the private routing policy, and enters `ENTERING`. This immediately invalidates pre-capture Perception, ChatAgent, TTS, and stream work.
- A new capture receives a monotonically increasing `capture_seq`.
- EndCapture, timeout, disconnect, emergency shutdown, or transition to `FAILED_CLOSED` increments `generation` before cleanup begins.
- A query receives a monotonically increasing `query_seq`; idempotent retries retain the original sequence.
- Epoch values are server-issued and cannot be supplied or altered by handlers or clients.

### Late-callback fencing

Every queued item, external request, future, callback, store operation, TTS job, and output attempt carries a core-owned `WorkFenceV1`:

```text
WorkFenceV1 {
  session_epoch,
  capture_epoch?,
  query_epoch?,
  speech_job_id?,
  operation_id,
  operation_kind,
  deadline
}
```

The fence must be validated atomically:

1. At ingress/admission.
2. At queue dequeue.
3. Immediately before an external OCR, LLM, or TTS request.
4. Immediately after return or callback invocation.
5. Before any state or store mutation.
6. Before history, logging, metric-with-payload, stream publication, or client egress.

A fence is valid only when:

- `session_instance_id` and `generation` equal the current session epoch.
- The session remains active and owned by the same principal.
- Capture work matches the current `capture_id` and `capture_seq`.
- The current capture state permits the operation:
  - frame preprocessing: `ARMED` or `CAPTURING`;
  - OCR: `BUILDING_ASSERTIONS`;
  - assertion commit: `BUILDING_ASSERTIONS`;
  - query work: `READY` with matching active query;
  - speech: `READY` with matching completed query and live speech job.
- The operation has not been cancelled or exceeded its monotonic deadline.
- The core security envelope still authorizes the intended consumer.

On mismatch:

- Do not mutate state, cache, history, assertions, query results, or output.
- Do not publish a terminal success or barrier acknowledgement.
- Release frame/text/audio references immediately.
- Record only `late_callback_dropped_total{operation_kind, reason}`.
- Never log the rejected payload.

A Perception or ChatAgent quiescence acknowledgement is valid only after new admission is disabled, its queues are drained, old-generation callbacks are fenced at core egress, and any non-cancellable work is registered as side-effect-ineligible. An OCR-sidecar purge that does not acknowledge within the cleanup deadline causes the sidecar to restart and the capture to remain `FAILED_CLOSED`.

## 3. Protocol, Evidence, and Inference Identity

### Authenticated APIs

- `POST /api/v1/session-capabilities`
  - Validates OIDC signature, issuer, audience, `exp`, `nbf`, `iat`, and `sub`.
  - Returns a server-generated session ID and opaque 256-bit session capability.
  - Capability lifetime is 15 minutes; BeginCapture requires six minutes remaining.
- `POST /api/v1/sessions/{session_id}/certificate-captures`
  - Input: `{request_id, control_seq, profile_id}`
  - Returns `CaptureEpochV1` and a capture-scoped capability after the quiescence barrier.
- `PUT .../{capture_id}/frames/{frame_seq}`
  - JPEG only; maximum 2 MiB, 1920×1080 or 2,073,600 decoded pixels, eight frames and 16 MiB per capture.
  - Same sequence and hash is idempotent; same sequence with different content is a conflict.
- `POST .../{capture_id}/seal`
  - Returns `SealResultV1`.
- `GET .../{capture_id}`
  - Returns capture status; polling does not extend inactivity.
- `POST .../{capture_id}/queries`
  - Creates `QueryLifecycleV1` and returns `QueryEpochV1`.
- `GET .../{capture_id}/queries/{query_id}`
  - Returns query state and, when completed, `CertificateAnswerV1`.
- `POST .../{capture_id}/queries/{query_id}/speech`
  - Creates the local `SpeechJobV1`.
- `GET .../{capture_id}/speech/{speech_job_id}`
  - Returns authorized audio with `Cache-Control: no-store`.
- `GET .../{capture_id}/frames/{frame_id}`
  - Returns an authorized evidence image for highlighted regions.
- `POST .../{capture_id}/end`
  - Returns success only after key destruction, queue cleanup, callback fencing, and normal-mode resume acknowledgement.

### Evidence contract

Use immutable versioned records:

- `CaptureSetV1`: epochs, profile, frame set, inference identity, calibration dependency, and capture window.
- `EvidenceFrameV1`: frame sequence, receive time, SHA-256, perceptual hash, homography, quality features, and correlation group.
- `ObservationV1`: recognized span, polygon, raw OCR score, frame reference, and inference-identity hash.
- `FieldHypothesisV1`: normalized candidate with support and conflict observation IDs.
- `AssertionV1`: field/value, support/conflict sets, calibration artifact, calibrated probability, decision, and `verification_state:"not_checked"`.
- `CertificateAnswerV1`: deterministic text and claims linked to live assertions and source polygons.

Assertion decisions remain:

```text
SUPPORTED
CONFLICTED
INSUFFICIENT
UNCALIBRATED
NOT_FOUND
```

A `SUPPORTED` assertion requires matching observations from at least two independent correlation groups, a passing field validator, no high-quality conflicting value, and a calibrated probability meeting the frozen field threshold. Adjacent burst-frame probabilities are never multiplied as independent evidence.

### `InferenceIdentityV1`

Every OCR response and `CaptureSetV1` must reference a formally typed identity:

```text
InferenceIdentityV1 {
  schema_version,

  service: {
    protocol_version,
    source_revision,
    container_image_digest
  },

  software: {
    python_abi,
    paddleocr_version,
    paddlepaddle_version,
    paddlex_version,
    locked_wheel_hashes[]
  },

  execution: {
    engine,
    precision,
    deterministic_algorithms,
    hpi_enabled,
    tensorrt_enabled,
    batch_policy,
    device_kind,
    cuda_runtime_version,
    cudnn_version,
    gpu_compute_capability,
    gpu_model,
    driver_version
  },

  models: [{
    role,
    model_name,
    artifact_sha256,
    configuration_sha256
  }],

  pipeline: {
    canonical_configuration_sha256,
    character_dictionary_sha256
  },

  preprocessing: {
    implementation_version,
    source_sha256,
    configuration_sha256
  },

  postprocessing: {
    implementation_version,
    source_sha256,
    configuration_sha256
  }
}
```

Serialize it using deterministic canonical JSON and compute `inference_identity_sha256`.

Define an exact typed calibration projection:

```text
CalibrationDependencyV1 {
  schema_version,
  paddleocr_version,
  paddlepaddle_version,
  paddlex_version,
  locked_wheel_hashes,
  engine,
  precision,
  deterministic_algorithms,
  hpi_enabled,
  tensorrt_enabled,
  batch_policy,
  device_kind,
  cuda_runtime_version,
  cudnn_version,
  gpu_compute_capability,
  models,
  pipeline,
  preprocessing,
  postprocessing
}
```

Rules:

- Compute `calibration_dependency_sha256` from the canonical typed object.
- Calibration artifacts embed both the complete object and its hash; free-form compatibility strings and wildcard matching are forbidden.
- GPU serial number, ordinal, and driver patch version remain in the full inference identity for provenance but are excluded from calibration compatibility. Driver compatibility is enforced separately by startup health checks.
- Any calibration-dependency mismatch prevents the OCR sidecar from becoming certificate-ready.
- A missing field-specific calibration under an otherwise matching identity produces `UNCALIBRATED`.
- Model, dictionary, preprocessing, postprocessing, engine, precision, CUDA ABI, cuDNN, compute capability, or batch-policy changes require a new calibration artifact.

The initial GPU service remains pinned to PaddleOCR 3.7.0, PaddlePaddle GPU 3.2.0, CUDA 12.6, FP32 standard Paddle inference, and PP-OCRv6 medium. PaddleOCR’s official documentation identifies PP-OCRv6 medium as the 3.7 general-OCR default and exposes the recognized regions required for grounding. ([OCR pipeline](https://github.com/PaddlePaddle/PaddleOCR/blob/main/docs/version3.x/pipeline_usage/OCR.en.md), [GPU serving](https://github.com/PaddlePaddle/PaddleOCR/blob/main/docs/version3.x/inference_deployment/serving/serving.en.md))

## 4. Privacy, Grounded Answering, and Delivery

- Store frames, observations, assertions, answers, and generated audio using a per-capture 256-bit AES-256-GCM key.
- Delete the key before clearing ciphertext and references on EndCapture, inactivity, disconnect, failure, or session replacement.
- Use no persistent files, generic history, browser storage, analytics payloads, or crash-report attachments.
- Run OCR in a read-only GPU sidecar with baked and hashed models, tmpfs scratch space, no published port, no outbound route, one warmed worker, and no CPU fallback.
- Run deterministic bilingual certificate queries without an LLM. Supported fields are title, holder, issuer, issue date, expiry date, and qualification/award.
- Every answer copies its value from a live `SUPPORTED` assertion and includes assertion ID, source polygons, expiry, and `verification_state:"not_checked"`.
- Every answer states that the information was read from the image and authenticity was not verified.
- Local CosyVoice consumes only `CERTIFICATE_RESPONSE_TEXT`, logs no text, and produces private `CERTIFICATE_RESPONSE_AUDIO` for the owning WebUI. TTS output never uses generic avatar text/audio channels.
- The WebUI detaches the normal camera track before BeginCapture, waits for `ARMED`, captures up to eight frames, displays `SealOutcomeV1` guidance, shows highlighted evidence, and revokes all in-memory object URLs at EndCapture.

Implementation order:

1. TLS/OIDC session ownership and core-owned security envelopes.
2. Formal epochs, fencing predicate, barriers, and deterministic state-machine tests.
3. Private frame/control APIs and WebUI capture workflow with mock inference.
4. Typed inference identity, GPU OCR sidecar, evidence model, and calibration artifacts.
5. Independent query/speech lifecycles, grounded rendering, highlighted evidence, and private local TTS.
6. Security, statistical, performance, deletion, and rollout gates.

## 5. Statistical and Operational Acceptance Gates

### Dataset rules

- Split training, threshold-selection, calibration, and final holdout sets by certificate document identity.
- Frames or recaptures of the same document may not cross splits.
- The final holdout manifest, profile versions, thresholds, and statistical script are frozen before evaluation.
- The primary precision gate uses at most one prespecified capture set per document identity and field.
- Results cannot be pooled across production profiles. Every profile and enabled field must pass independently.
- Failure to obtain the required number of supported assertions is a failed gate, not an inconclusive pass.

### Precision gates

For each production `(profile, field)`:

```text
precision = correct SUPPORTED assertions / all SUPPORTED assertions
```

Let `M` be the total number of production `(profile, field)` precision gates. Compute a one-sided exact Clopper–Pearson lower confidence bound using:

```text
alpha_per_gate = 0.05 / M
```

This provides at least 95% family-wise confidence across the declared precision gates.

Required results:

- Critical exact fields—`issue_date` and `expiry_date`:
  - At least 1,000 supported assertions from 1,000 distinct document identities per profile and field.
  - Simultaneous one-sided lower confidence bound at least `0.99`.
- Text fields—title, holder, issuer, and qualification/award:
  - At least 500 supported assertions from 500 distinct document identities per profile and field.
  - Simultaneous one-sided lower confidence bound at least `0.98`.
- Custom profile fields declare either `critical_exact` or `text` and inherit the corresponding gate.
- Point estimates alone never satisfy the requirement.

### Coverage, OOD, and calibration

- Coverage is `SUPPORTED / eligible high-quality documents`.
- Evaluate at least 1,200 eligible documents per critical profile-field and 600 per text profile-field.
- The one-sided 95% Wilson lower bound for coverage must be at least `0.90`.
- Evaluate at least 1,000 OOD/unsupported documents per production profile, including at least 200 from each declared OOD category.
- The one-sided 95% Clopper–Pearson upper bound for false-supported rate must be at most `0.01`.
- Compute assertion-level expected calibration error using 15 equal-mass bins.
- Use 10,000 document-level bootstrap resamples; the one-sided 95% upper bound for ECE must be at most `0.05`.
- Thresholds cannot be adjusted after viewing holdout outcomes. Any adjustment requires a new calibration/test split and a new versioned artifact.

### Security and runtime gates

- Zero certificate payloads in generic ChatAgent, Perception, history, writeback, generic TTS/audio, manager exports, ordinary logs, or browser persistence.
- Race tests must complete old Perception, ChatAgent, OCR, query, and TTS operations after Begin/End and prove every stale callback is fenced.
- Tests must cover session replacement, generation rollover, capture/query sequence mismatch, idempotent retries, late cleanup acknowledgements, and malicious metadata/type/stream rewriting.
- Identity tests must reject every single-field `CalibrationDependencyV1` mismatch and accept changes only to explicitly non-calibration provenance fields.
- P95 seal-to-`READY` latency must be at most five seconds on the declared reference GPU.
- Feature-idle normal-chat P95 latency regression must not exceed 5%.
- Any failed authentication, epoch, isolation, identity, deletion, calibration, confidence-interval, GPU, or compatibility gate blocks production rollout.

V1 excludes authenticity verification, issuer/QR networking, remote OCR/TTS, continuous background certificate detection, private voice ASR, ChatAgent tool triggering, arbitrary documents outside configured profiles, and queries after EndCapture.
