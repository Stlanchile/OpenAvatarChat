# Certificate Extractor Module Reference

[简体中文](zh-cn/certificate-extractor.md) | English

This guide describes the certificate-extraction code currently implemented
under `src/certificate_capture/extraction/`. Despite the informal “certificate
extractor” name, V1 is not a generic certificate parser. It is a private,
deterministic parser for one 湖北交通职业技术学院 admission-notice template.

The source and behavior described here are pinned conceptually to review commit
`6db2b96176afc9f324d022e01f96b3cf3d811699` from 2026-08-27.

## 1. Purpose and current status

| Item | Current state |
|---|---|
| Implemented scope | M6B deterministic four-field extraction and M6C single-template compatibility matching |
| Input | One to three opaque receipts for encrypted M6A `OcrPageResultV1` records, opened only inside the private service |
| Output | One encrypted `AdmissionNoticeExtractionV1` plus an opaque `StoredAdmissionNoticeExtractionV1` receipt |
| Production status | Component implementation and isolated tests exist, but production `SealCapture` does not invoke M6A, M6B, M6C, or M7 |
| Public API | None: no OCR, extraction, template-match, or field-result HTTP/WebSocket endpoint |
| Trust statement | `MATCHED` means parser compatibility only; it does not establish authenticity, validity, issuance, issuer identity, or admission status |

The current production capture path checks only for a constructor-injected test
processor. After the unique-frame gate, a normal production Seal request
therefore returns `PROCESSOR_NOT_READY` regardless of whether an OCR deployment
manifest is available. This document describes implemented private components,
not an enabled production document-processing service.

## 2. Three distinct module roles

The following names are related but are not interchangeable:

| Name | Responsibility | Does not do |
|---|---|---|
| `AdmissionNoticeExtractorV1` | Pure deterministic parser over validated `OcrPageResultV1` objects; invokes template matching, field rules, and cross-page aggregation | Decrypt evidence, authorize work, persist results, or authenticate documents |
| `HbtcAdmissionNoticeTemplateMatcherV1` | M6C compatibility gate for the one fixed HBTC template | Extract semantic fields or verify authenticity |
| `PrivateAdmissionNoticeExtractionServiceV1` | Core-only M2/M3/M5A wrapper; decrypts OCR records under fences, invokes the parser, encrypts the result, and returns an opaque receipt | Expose plaintext or provide a public route |

The extractor package exports the pure parser and template matcher. The private
service is imported directly by the capture coordinator and is deliberately not
part of the package's general export list.

## 3. Package and contract map

| Source | Role |
|---|---|
| [`extraction/admission_notice.py`](../src/certificate_capture/extraction/admission_notice.py) | Field-specific deterministic rules and `AdmissionNoticeExtractorV1` |
| [`extraction/hbtc_admission_notice.py`](../src/certificate_capture/extraction/hbtc_admission_notice.py) | HBTC title/body compatibility matching and matched-page selection |
| [`extraction/reading_order.py`](../src/certificate_capture/extraction/reading_order.py) | Normalized-coordinate geometry handling, visual-line reconstruction, and bounded adjacent-run paths |
| [`extraction/normalization.py`](../src/certificate_capture/extraction/normalization.py) | Closed whitespace, punctuation, structural-trimming, control-character, and Han-character rules |
| [`extraction/identity.py`](../src/certificate_capture/extraction/identity.py) | Fixed extractor, template, match-rule, field-rule, and normalization identity |
| [`extraction/service.py`](../src/certificate_capture/extraction/service.py) | Private authority, work-fence, encrypted-store, idempotency, cancellation, and stable failures |
| [`contracts/admission_notice.py`](../src/certificate_capture/contracts/admission_notice.py) | Immutable extraction identity, field/result schemas, canonical parsing, hashes, storage key, and opaque receipt |
| [`contracts/admission_notice_template.py`](../src/certificate_capture/contracts/admission_notice_template.py) | Single-template descriptor, anchor IDs, and match-status contract |
| [`coordinator.py`](../src/certificate_capture/coordinator.py) | Sole owner of the private service and its internal extraction/release-staging seam |

## 4. Private data flow

```text
StoredOcrResultV1 receipts (1..3)
  -> PrivateAdmissionNoticeExtractionServiceV1.extract_v1
  -> exact live OCR_INFERENCE parent
  -> ADMISSION_NOTICE_EXTRACTION child work
  -> decrypt OcrPageResultV1 records
  -> deterministic reading-order reconstruction
  -> HbtcAdmissionNoticeTemplateMatcherV1.match_and_select_pages_v1
  -> matched pages only
  -> AdmissionNoticeExtractorV1.extract_pages_v1
  -> canonical AdmissionNoticeExtractionV1
  -> PrivateEvidenceStoreV1.put_admission_notice_extraction_v1
  -> StoredAdmissionNoticeExtractionV1 receipt
  -> optional AdmissionNoticeSafeReleaseServiceV1.stage_extraction_v1
```

The private service accepts one to three unique `StoredOcrResultV1` receipts.
It registers `ADMISSION_NOTICE_EXTRACTION` only as an exact child of live
`OCR_INFERENCE` work, decrypts each OCR record through separately fenced
`CAPTURE_EVIDENCE_READ` work, and checks capture and generation liveness at the
defined read, callback-return, extraction, memory-write, private-store-write,
and completion boundaries.

The pure parser accepts immutable `OcrPageResultV1` objects. All pages must
belong to the same exact `CaptureEpochV1`; OCR result IDs, frame IDs, and span
IDs must be unique. The parser orders pages by result UUID rather than caller or
camera order.

Only pages that individually satisfy `MATCHED` provide semantic candidates.
The final result still records every accepted source OCR result/frame ID so the
encrypted record remains bound to its complete input set. `INSUFFICIENT` pages
cannot contribute fields or borrow a matching title from another page.

## 5. Output contract

The encrypted plaintext-equivalent record has this fixed logical shape:

```text
AdmissionNoticeExtractionV1 {
  schema_version
  capture_epoch
  source_ocr_result_ids[1..3]
  source_frame_ids[1..3]
  extraction_identity
  name
  source_province
  college
  major
}

ExtractedAdmissionFieldV1 {
  schema_version
  status: FOUND | AMBIGUOUS | NOT_FOUND
  value?
  source_span_ids[]
  source_polygon?
}
```

There are exactly four semantic fields. The trusted institution is not a fifth
OCR field and cannot be supplied by the client.

| Field | Contract bound | Current deterministic rule |
|---|---:|---|
| `name` | 32 code points | A local salutation candidate before `同学`; normally 2–4 Han characters, or up to 8 when a middle dot is present |
| `source_province` | 16 code points | An exact member of the closed province-level allowlist within the `经…高等学校招生委员会…批准` grammar |
| `college` | 128 code points | The current parser additionally limits it to 64 and requires a recognized academic-unit suffix after `你被录取到我校` |
| `major` | 256 code points | A bounded Han/ASCII candidate immediately governing `专业学习`, with balanced parentheses and allowlisted punctuation |

Candidate values reject Unicode control, format, surrogate, and private-use
characters. Normalization collapses layout whitespace and canonicalizes only a
small allowlist of structural punctuation. It does not perform fuzzy matching,
spell correction, dictionary completion, NFKC rewriting, LLM/VLM inference, or
network lookup.

### 5.1 Field-level abstention

| Status | Meaning and retained content |
|---|---|
| `FOUND` | Exactly one value is supported for the field. The record retains the value and one to 32 sorted source span IDs; a normalized source rectangle is retained when one coherent rectangle is available. |
| `AMBIGUOUS` | A page has multiple candidate occurrences, matched pages disagree, or bounded provenance cannot be represented. The field retains no value, span IDs, or polygon. |
| `NOT_FOUND` | No matched page supplies a valid candidate. The field retains no value, span IDs, or polygon. |

An `AMBIGUOUS` decision on any matched page dominates that field's aggregate.
Multiple matched pages may produce `FOUND` only when their values agree.
`NOT_FOUND` for one field does not invalidate independently supported fields.
The extractor abstains rather than choosing by confidence, page order, or OCR
score.

For a semantic field candidate, its value and local authority-anchor spans are
rejected when an available raw engine score is below `0.50`; an absent raw
engine score is permitted by this deterministic rule. That floor is a field
parser guard, not a template-match threshold, calibrated probability, or
authenticity score.

### 5.2 Canonical form, identity, and reuse

`AdmissionNoticeExtractionV1` is immutable, strict, and limited to 16 KiB of
canonical JSON. Parsing rejects unknown/missing fields, duplicate JSON keys,
invalid UTF-8, non-canonical encoding, excessive nesting, invalid UUIDv7
identities, mismatched capture epochs, invalid status/value combinations, and
out-of-bound provenance.

The fixed extraction identity includes:

- `extractor_id`: `admission-notice-extractor.v1`;
- `template_id`: `hbtc_admission_notice_v1`;
- `template_match_rule_version`: `hbtc-admission-notice-template-match.v1`;
- `rule_set_version`: `admission-notice-rules.v2`;
- `normalization_version`: `admission-notice-normalization.v1`.

Rule set V2 makes the required `批准` anchor part of the province candidate's
raw-engine-score authority range. The V1 constant remains available only to
identify historical records; the fixed current extractor rejects a
caller-supplied identity that does not exactly match its implemented behavior.

The private-store idempotency key is the sorted OCR result-ID tuple plus the
SHA-256 of that full extraction identity. An exact prior encrypted result is
reused. Any semantic change to matching, field rules, or normalization must
therefore receive a new identity version; otherwise old ciphertext could be
incorrectly reused as if it were produced by the new rules.

## 6. HBTC template compatibility gate

V1 contains one immutable, server-owned template:

| Item | Exact value |
|---|---|
| Template ID | `hbtc_admission_notice_v1` |
| Trusted institution | `湖北交通职业技术学院` |
| Extractor ID | `admission-notice-extractor.v1` |
| Match-rule version | `hbtc-admission-notice-template-match.v1` |

`BeginCapture.profile_id` accepts only this template ID. V1 has no runtime
registry, generic multi-school plugin, client-selected institution, OCR-derived
institution authority, or network template lookup.

### 6.1 Required evidence

The exact institution heading must reconstruct in the upper title region.
Local same-line splits and two related adjacent title lines are supported, but a
materially different institution-form heading is a conflict.

In addition to the title, at least three of four body anchors must satisfy their
bounded region, local grammar, geometry, and plausible reading order:

| Anchor ID | Text |
|---|---|
| `student-salutation` | `同学` |
| `admission-committee` | `高等学校招生委员会` |
| `admission-body` | `你被录取到我校` |
| `major-study` | `专业学习` |

The qualifying body anchors must begin on at least three distinct reconstructed
visual lines. Footer text cannot independently satisfy the body signature.
Consecutive anchors require compatible horizontal geometry, with only the
closed admission-body-to-major transition allowing a bounded normalized gap.
Repeated pages add no weight.

### 6.2 Page-set outcomes

| Outcome | Page-set behavior |
|---|---|
| `MATCHED` | At least one page independently has the exact title and sufficient body signature, and no page has a conflicting institution heading. Only independently matched pages feed semantic extraction. |
| `NOT_MATCHED` | Any page contains a materially different institution heading. This outcome dominates all supported or insufficient pages and stops before field extraction. |
| `INSUFFICIENT` | No conflicting institution exists, but no page independently provides enough compatible title/body evidence. It also stops before field extraction. |

`MATCHED` is deliberately named as a compatibility outcome. It must never be
presented as proof that the photographed document is genuine, issued by the
institution, currently valid, or evidence of finalized admission or enrollment.

## 7. Reading order and field extraction

The parser does not trust OCR span array order. It derives a normalized
rectangle from each non-degenerate polygon, deterministically groups spans into
visual lines, sorts runs left-to-right, and explores only bounded
geometry-related forward paths of at most three lines.

Template matching constructs each page's `ReadingOrderV1` once. A matched
page's exact stack-local reading object is then reused for semantic extraction,
avoiding a second geometry reconstruction without caching OCR data across calls
or captures.

Field rules then operate in bounded vertical regions and local anchor grammar:

1. `name` is taken only from a structurally isolated salutation occurrence.
2. `source_province` must fit the committee-and-approval sentence pattern and
   the closed province-level allowlist.
3. `college` must follow the admission-body anchor and end at the first
   recognized academic-unit suffix; one related next-line run may complete it.
4. `major` must immediately govern the major-study anchor. A preceding related
   line is joined only when the current fragment is not already a valid major,
   preventing unrelated text from being merged.

Candidates carry their exact source spans and derived rectangle. Multiple
occurrences on one page are not ranked; they become `AMBIGUOUS`. Cross-page
aggregation is likewise deterministic and independent of input order.

## 8. Authority, storage, and cleanup

`PrivateAdmissionNoticeExtractionServiceV1` is construction-gated and created
only by `CaptureCoordinatorV1`. The coordinator's extraction seam is
underscore-prefixed, accepts only opaque OCR receipts plus exact parent work,
and returns only an opaque encrypted-result receipt.

Security and lifecycle properties include:

- exact `OCR_INFERENCE` parentage and `ADMISSION_NOTICE_EXTRACTION` child work;
- capture, session-generation, private-authority, and work-fence validation
  around every sensitive boundary;
- child `CAPTURE_EVIDENCE_READ` and `CAPTURE_EVIDENCE_AUXILIARY` work for store
  access;
- canonical extraction JSON stored as an encrypted
  `AUXILIARY_CANONICAL_JSON` record under the existing per-capture AES-256-GCM
  DEK;
- source OCR record existence, digest, capture profile, and provenance
  cross-checks before an extraction record is committed;
- atomic reuse/insertion and rollback on encryption or metadata failure;
- payload-free stable errors and redacted `repr` output;
- cancellation of active extraction work when the capture retires or service
  admission closes;
- key-first cleanup at EndCapture, after which the encrypted record is
  cryptographically inaccessible.

The service clears transient Python references in `finally`, but Python does
not guarantee allocator-level plaintext zeroization. The security property is
bounded private access plus capture-DEK destruction, not a claim that every
temporary byte was physically overwritten.

There is no supported direct read for handlers, plugins, routes, Manager, or
the browser. Authorized plaintext read helpers in the coordinator are
test-only. Logging and support bundles must exclude OCR text, extracted values,
span/polygon provenance, frame/result/capture IDs, capabilities, and serialized
M7 context.

## 9. Stable private failure outcomes

These are internal service reasons, not current browser/HTTP result codes:

| Reason | Meaning |
|---|---|
| `EXTRACTION_INPUT_INVALID` | Receipt/page/schema/provenance input is malformed, duplicated, missing, or otherwise invalid |
| `EXTRACTION_TEMPLATE_NOT_MATCHED` | The template matcher returned `NOT_MATCHED` |
| `EXTRACTION_TEMPLATE_INSUFFICIENT` | The template matcher returned `INSUFFICIENT` |
| `EXTRACTION_RESULT_TOO_LARGE` | The bounded encrypted auxiliary-store capacity cannot admit the result |
| `EXTRACTION_AUTHORITY_INVALID` | The private authority or coordinator ownership is unavailable |
| `EXTRACTION_STALE` | Capture/generation/work admission changed or a fence failed |
| `EXTRACTION_INTERNAL_ERROR` | Integrity, invariant, codec, encryption, or unexpected private processing failed closed |

Store integrity/invariant/type failures also notify the coordinator's fatal
protocol path. Exceptions intentionally contain a stable reason rather than
OCR text or extracted values.

## 10. Current integration boundary and release blocker

The coordinator always constructs `PrivateEvidenceStoreV1` and
`PrivateAdmissionNoticeExtractionServiceV1`; it also constructs
`AdmissionNoticeSafeReleaseServiceV1` when release authority is available. OCR
has a separate lifecycle: `CaptureCoordinatorV1._ocr_service_v1` initially
remains `None`. `ChatEngine` validates and stages `OcrDeploymentConfigV1`, but a
staged configuration does not create a client or install
`PrivateOcrServiceV1`.

The complete owner-only internal sequence is:

1. `ChatSession._bootstrap_certificate_ocr_v1()` calls
   `CaptureCoordinatorV1._bootstrap_private_ocr_runtime_v1()`, which creates the
   UDS client and installs `PrivateOcrServiceV1`;
2. after installation, `ChatSession._process_certificate_ocr_frames_v1()` calls
   `_process_private_ocr_frames_v1()` to process encrypted image evidence and
   return opaque OCR receipts;
3. `_process_private_admission_notice_extraction_v1()` invokes
   `PrivateAdmissionNoticeExtractionServiceV1.extract_v1()` for template
   matching and four-field extraction;
4. when a release service exists, `stage_extraction_v1()` stages the encrypted
   extraction receipt for an internal EndCapture reread.

Production `seal_capture_protocol_v1()` reaches `_execute_seal_attempt_v1()`,
which does not call that sequence. It checks `_test_processor_v1`, registers
`CAPTURE_MOCK_PROCESSOR`, and starts only `_run_mock_processor_v1`. A valid OCR
deployment manifest can therefore stage a configuration candidate, but only a
successful owner bootstrap installs the OCR service, and current Seal invokes
neither bootstrap nor extraction/release staging.

A production release therefore needs two separate gates:

1. implement and review the exact Seal → M6A OCR → M6B/M6C extraction → M7
   staging composition, preserving parent work, cancellation, cleanup, and
   failure semantics;
2. provision and qualify the real isolated CPU OCR lock, models, inference
   identity, UDS policy, performance/resource limits, and acceptance evidence.

Do not bridge the gap with a public extraction endpoint, browser OCR, plaintext
file/database storage, remote fallback, direct calls that bypass fences, or a
fake production-success processor.

## 11. Maintainer rules

- Keep the four-field boundary exact: `name`, `source_province`, `college`,
  `major`.
- Keep the trusted institution server-owned and separate from OCR output.
- Preserve field-level abstention; never choose among conflicts by page order,
  raw score, fuzzy similarity, or an LLM.
- Bump the appropriate extraction identity whenever matching, normalization, or
  semantic rules change, and add migration/reuse tests.
- Treat another institution, template, or generic certificate type as a new
  versioned design, not an unreviewed runtime plugin in V1.
- Preserve canonical schemas, byte/count bounds, provenance validation,
  redacted representations, encrypted-only persistence, and key-first cleanup.
- If the field set changes, review the M7 release allowlist independently; an
  extractor field does not automatically become public-chat safe.
- Keep template compatibility language distinct from authenticity,
  issuer-verification, admission-status, and enrollment claims.

## 12. Focused validation

Run the M6B and M6C suites separately because the repository's milestone test
directories contain repeated module basenames:

```bash
PYTHONPATH="$PWD:$PWD/src" .venv/bin/pytest -q tests/chat_engine/milestone_6b
PYTHONPATH="$PWD:$PWD/src" .venv/bin/pytest -q tests/chat_engine/milestone_6c
```

| Suite area | Primary evidence |
|---|---|
| Contract and parser rules | [`test_contracts_and_extractor.py`](../tests/chat_engine/milestone_6b/test_contracts_and_extractor.py) |
| Ambiguity and page-order invariance | [`test_ambiguity_and_multiframe.py`](../tests/chat_engine/milestone_6b/test_ambiguity_and_multiframe.py) |
| Private authority, encrypted store, races, cleanup | [`test_private_store_authority_lifecycle.py`](../tests/chat_engine/milestone_6b/test_private_store_authority_lifecycle.py) |
| Injection and sink isolation | [`test_injection_and_isolation.py`](../tests/chat_engine/milestone_6b/test_injection_and_isolation.py) |
| HBTC compatibility and adversarial layouts | [`test_template_compatibility.py`](../tests/chat_engine/milestone_6c/test_template_compatibility.py) |
| Matcher/extractor interaction | [`test_extraction_interaction.py`](../tests/chat_engine/milestone_6c/test_extraction_interaction.py) |
| Synthetic performance smoke | M6B and M6C `test_performance_smoke.py` files |

These suites use synthetic OCR objects and fixtures. They do not qualify a real
Paddle/PP-OCRv6 model, camera, document population, CPU class, or production
end-to-end path.

## 13. Related documentation

- [Technical report](technical-report.md)
- [Deployment guide](deployment-guide.md)
- [Operations and validation](operations-validation.md)
- [Canonical Secure Certificate Capture V1 amendment](../docs/en/reference/secure-certificate-capture-v1.md#current-admission-notice-roadmap-amendment)
