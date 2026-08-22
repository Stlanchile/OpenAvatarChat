# OpenAvatarChat Technical Documentation

[简体中文](zh-cn/README.md) | English

This documentation is a source-backed review and deployment guide for the
checked-out OpenAvatarChat project. It is intended for engineers who must
understand, deploy, secure, operate, or extend the service rather than only run
the quick-start example.

## Review snapshot

| Item | Value |
|---|---|
| Review date | 2026-08-18 |
| Branch | `main` |
| Commit | `8b7b3b45bca28ae9ab5fa72ee31bc03c5a99b08b` |
| Application-reported version | `0.6.0` |
| Root package version | `0.1.0` |
| Primary runtime | Python 3.11, FastAPI/Uvicorn, FastRTC/WebRTC, PyTorch CUDA 12.8 |
| Deployment artifacts | Native `uv`, Docker, Docker Compose with coturn |
| Review basis | Current source, manifests, all presets, existing `docs/`, and bounded static/runtime checks |

Line references in these documents are pinned conceptually to the commit above.
They may move after later edits.

External platform references in the deployment guide are advisory prerequisites
and were current when reviewed; they are not evidence that this checkout passed
an end-to-end deployment in the review environment.

## Document map

- [Technical report](technical-report.md) — architecture, execution model,
  components, data flow, state, interfaces, configuration, security boundaries,
  and prioritized findings.
- [Deployment guide](deployment-guide.md) — deployment decision, prerequisites,
  preset selection, native installation, Docker, Compose/TURN, and public
  production topology.
- [Operations and validation](operations-validation.md) — health checks,
  observability, capacity guidance, backup/upgrade/rollback, troubleshooting,
  validation evidence, and residual uncertainty.

The deployment material is organized by deployment method, not by individual
dependency.

## Bottom line

The core design is a modular, configuration-driven real-time media pipeline:

```text
Browser / LAM client
        |
        v
RTC or WebSocket client handler
        |
        v
VAD -> ASR -> LLM -> TTS -> avatar renderer
        |                         |
        +---- stream graph -------+
        +---- signals/history ----+
        |
        v
Audio, video, text, and interruption feedback
```

The source has several strong operational properties: explicit handler
contracts, per-session contexts, stream ancestry and cancellation, bounded
stream recycling, health endpoints, preset-specific dependency discovery, and
pinned Git submodule commits.

However, the shipped deployment should be treated as a development/reference
deployment until the production gates below are addressed:

1. The application and Manager endpoints have no server-side authentication or
   admission control. Do not expose port `8282`/`8283` directly to the Internet.
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
8. `src/demo.py` forces exit status `0` from its `finally` block, including for
   startup failures. Process exit status alone is not valid success evidence.

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

No product source was changed as part of this review. Only `tech-doc/` was
added.
