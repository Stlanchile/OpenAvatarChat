# OpenAvatarChat Technical Documentation

[简体中文](zh-cn/README.md) | English

This documentation is a source-backed review and deployment guide for the
checked-out OpenAvatarChat project. It is intended for engineers who must
understand, deploy, secure, operate, or extend the service rather than only run
the quick-start example.

## Review snapshot

| Item | Value |
|---|---|
| Review date | 2026-08-27 |
| Branch | `main` |
| Commit | `6db2b96176afc9f324d022e01f96b3cf3d811699` |
| Application-reported version | `0.6.0` |
| Root package version | `0.1.0` |
| Primary runtime | Python 3.11, FastAPI/Uvicorn, FastRTC/WebRTC, PyTorch CUDA 12.8; optional isolated CPU OCR sidecar |
| Deployment artifacts | Native `uv`, Docker, Docker Compose with coturn and an integration/qualification-gated OCR profile |
| Review basis | Original full-project review plus source-backed incremental review of Secure Certificate Capture V1 milestones 1–8 |

Source references and the secure-capture current-state sections are pinned
conceptually to the commit above. They may move after later edits.

External platform references in the deployment guide are advisory prerequisites
and retain their 2026-08-18 review date; they are not evidence that this checkout
passed an end-to-end deployment in the review environment.

## Document map

- [Technical report](technical-report.md) — architecture, execution model,
  components, data flow, state, interfaces, configuration, security boundaries,
  Secure Certificate Capture V1, and prioritized findings.
- [Certificate extractor module](certificate-extractor.md) — the exact M6B/M6C
  package boundary, deterministic four-field contract, HBTC compatibility
  rules, private storage/fencing, failures, and current production integration
  gap.
- [Deployment guide](deployment-guide.md) — deployment decision, prerequisites,
  preset selection, native installation, Docker, Compose/TURN, and public
  production topology, including the integration/qualification-gated
  certificate components.
- [Operations and validation](operations-validation.md) — health checks,
  observability, capacity guidance, backup/upgrade/rollback, troubleshooting,
  certificate privacy/cleanup gates, validation evidence, and residual
  uncertainty.

The deployment material is organized by deployment method, not by individual
dependency.

## Bottom line

The core design is a modular, configuration-driven real-time media pipeline:

```text
Browser / LAM client
        |
        +--> RTC or WebSocket client handler
        |         |
        |         v
        |    VAD -> ASR -> LLM -> TTS -> avatar renderer
        |         |                         |
        |         +---- stream graph -------+
        |         +---- signals/history ----+
        |
        +--> Authenticated HTTPS admission-notice capture
                  |
                  v
             WorkFenceV1 -> encrypted evidence
                  |
                  +--> production Seal -> PROCESSOR_NOT_READY
                  |
                  +--> owner-only seams (not production-wired):
                       CPU OCR over private UDS -> fixed-template extraction
                       -> one sanitized ChatAgent turn after EndCapture
```

The source has several strong operational properties: explicit handler
contracts, per-session contexts, stream ancestry and cancellation, bounded
stream recycling, health endpoints, preset-specific dependency discovery, and
pinned Git submodule commits. The opt-in certificate mode now also has
fail-closed TLS/OIDC startup, session/transport/Manager admission, generation
fencing, and capture-scoped encrypted evidence. Networkless CPU OCR,
deterministic fixed-template extraction, and one-use sanitized release are
implemented as private components with isolated tests, but the production Seal
path does not invoke them.

However, the shipped deployment should be treated as a development/reference
deployment until the production gates below are addressed:

1. Certificate capture is disabled by default. In that legacy/default mode the
   application and Manager retain unauthenticated behavior. Enabled certificate
   mode adds OIDC-backed admission, but it does not add rate limiting or make
   direct exposure of `8282`/`8283` acceptable.
2. The checked-in coturn configuration uses public static credentials, and the
   Compose file mounts the certificate as the TURN private key. TURN-over-TLS
   cannot work correctly in that form.
3. Starting coturn in Compose does not configure the application to advertise
   it to browsers; a `RtcClient.turn_config` block is still required.
4. Model artifacts are downloaded from mutable upstream revisions without
   checksums, while startup globally permits unsafe PyTorch pickle loading.
5. Dependency resolution is not reproducible from the tracked repository:
   `uv.lock` is ignored and is neither copied nor enforced by the image build.
6. The Qwen-Omni preset currently fails the real Dynaconf load path because it
   declares `connection_ttl` twice.
7. `.dockerignore` excludes every `*.yaml`/`*.yml` in the build context,
   including runtime YAML files used inside avatar/voice submodules. A stock
   image can build successfully and still be incomplete at handler startup.
8. `src/demo.py` still leaves `exit_code` at `0` for startup failures outside
   the explicitly handled certificate-configuration gates, then terminates from
   `finally` with `os._exit(exit_code)`. Process exit status alone is not valid
   success evidence.
9. The admission-notice components are implemented through the M8 WebUI, but
   they are not production-wired end to end: Seal only admits a
   constructor-injected test processor and never invokes the private OCR or
   extraction services. The checkout also lacks an approved OCR dependency
   lock, production models, inference identity, and CPU qualification record.
   Production Seal therefore unconditionally returns `PROCESSOR_NOT_READY`
   after the frame-count gate; template matching is not authenticity
   verification.

See [Technical report: prioritized findings](technical-report.md#prioritized-findings)
for evidence and mitigation detail.

## Recommended path

- For a first controlled deployment, use the native `uv` path with the standard
  LiteAvatar + cloud TTS preset on a dedicated Linux GPU host.
- For an isolated repeatable runtime, use the Docker image after validating the
  selected configuration, models, certificates, and GPU runtime. The current
  image is still dependency-resolution-dependent and is not bit-reproducible.
- Treat the supplied Compose/coturn stack as a scaffold. Apply every TURN and
  TLS correction in the deployment guide before using it outside a trusted lab.
- Treat the `certificate-ocr` Compose profile as qualification scaffolding, not
  a runnable production OCR service. Do not enable successful certificate
  processing until the production Seal-to-OCR/extraction/release composition is
  implemented and reviewed, and the exact CPU artifacts, deployment manifest,
  UDS ownership policy, and acceptance evidence are provisioned.
- For LAN or public users, terminate trusted TLS at an authenticated reverse
  proxy, keep the application on an internal network, and operate a deliberately
  configured TURN service.
- Keep the OpenClaw integration disabled unless the beta Agent preset is
  specifically required. This report covers it only as a secondary integration
  boundary.

## Evidence language

These documents use the following terms deliberately:

- **Confirmed** — directly established from source or a command executed in this
  checkout.
- **Conditionally supported** — source exists, but successful operation depends
  on hardware, models, credentials, network services, or an unexecuted build.
- **Not validated** — no end-to-end claim is made.
- **Finding** — a concrete code/deployment issue with a realistic trigger and
  material impact; it is not evidence that exploitation or an outage occurred.

This documentation refresh changes only `tech-doc/`; the product and WebUI
milestone commits described here already existed in the reviewed checkout.
