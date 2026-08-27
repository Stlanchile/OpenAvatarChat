# OpenAvatarChat Operations, Troubleshooting, and Validation

[简体中文](zh-cn/operations-validation.md) | English

## 1. Operational model

OpenAvatarChat is a stateful real-time process even though it has no database:

- model instances and registered handlers live for the process lifetime;
- sessions, stream graphs, dialogue history, queues, and Manager buffers live
  in process memory;
- one pump thread is created for every enabled handler in every session;
- one signal-distribution thread is created per session;
- WebRTC adds event-loop tasks and media queues;
- selected avatar handlers add their own worker threads/processes/GPU state;
- enabled certificate sessions add generation authority, capture coordination,
  capture-key encrypted evidence, and an optional isolated CPU OCR process;
- restart terminates all conversations and discards in-memory histories.

`src/demo.py` now preserves a nonzero status for explicit certificate
configuration/startup gate failures, but still ends through `os._exit()` and
can mask other startup failures. Supervisors, CI, and shell automation must
require positive readiness and log/handler evidence rather than interpreting
zero as success.

Operate one application process per allocated GPU/service instance. Scale by
explicitly partitioning users across isolated instances with admission control,
not by adding Uvicorn workers to one process command.

## 2. Health endpoints and their exact meaning

| Endpoint | Success means | Enabled-mode authorization | It does not prove |
|---|---|---|---|
| `/version` | HTTP app is responding and exposes hard-coded application version | Bearer token with `oac:manager` | Git/image/model/config identity |
| `/liveness` | FastAPI process/event loop can answer a simple request | Bearer token with `oac:manager` | Handler threads, GPU, TURN, models, OCR, API connectivity |
| `/readiness` | `ChatEngine.initialize()` completed and set `inited` | Bearer token with `oac:manager` | Browser RTC/capture path, credentials, model integrity, TURN, production OCR composition/qualification, capacity |

These anonymous probes apply only to legacy/default mode behind the private
listener:

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8282/liveness

curl --fail --silent --show-error \
  http://127.0.0.1:8282/readiness

curl --fail --silent --show-error \
  http://127.0.0.1:8282/version
```

Use HTTPS and normal certificate verification when Uvicorn terminates TLS.
Do not use `-k` in a production probe.

In enabled certificate mode, use a narrowly held `oac:manager` probe token and
the configured HTTPS hostname:

```bash
read -r OAC_MANAGER_ACCESS_TOKEN < /run/secrets/oac-manager-token
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${OAC_MANAGER_ACCESS_TOKEN}" \
  https://chat.example.com/liveness
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${OAC_MANAGER_ACCESS_TOKEN}" \
  https://chat.example.com/readiness
unset OAC_MANAGER_ACCESS_TOKEN
```

Do not put the token in the URL, command history, probe output, or metrics.

A deployment-specific readiness gate should additionally check:

- selected exact model files and approved hashes;
- CUDA device availability and a small non-destructive allocation/inference;
- certificate/key existence, match, hostname, and expiry when direct TLS is
  selected;
- required API key presence without logging the value;
- DNS/TCP/TLS reachability of selected cloud handlers;
- TURN allocation/relay path when TURN is required;
- disk space and writable output/cache paths;
- current sessions below the admission threshold;
- enabled-mode OIDC/JWKS reachability and exact route inventory;
- in a future integrated release, OCR deployment-manifest, identity,
  lock/model/qualification hashes, UDS owner/mode/peer checks, and a sidecar
  health probe;
- explicit `PROCESSOR_NOT_READY` expectation for every production Seal in this
  checkout, because the Seal path is not composed with OCR/extraction,
  independently of whether qualified OCR inputs are present.

The current application does not implement these deeper checks.

## 3. Startup log checklist

Positive evidence:

```text
Load config with env ...
Registered handler ...
Handler ... loaded in ... milliseconds
Serving frontend from ...
SSL enabled.                       # only for direct TLS
Service will be started on ...
```

Treat the following as failure or degraded readiness:

```text
Config file ... not found
Failed to parse handler config
Failed to import module
Cert file ... not found
Key file ... not found
No valid rtc provider configuration found
model ... not found
api_key=[EMPTY]
CUDA out of memory
Certificate capture startup preflight failed (...)
CERTIFICATE_OCR_UNAVAILABLE_V1
```

The application can continue after some handler-time processing exceptions,
and legacy-mode TLS explicitly continues after missing files. In enabled mode,
the certificate preflight failure is fatal; the log-only diagnostic
`CERTIFICATE_OCR_UNAVAILABLE_V1` means a deployment candidate was invalid or
conflicting. Ordinary chat remains operational. Production capture processing
is unavailable regardless because current Seal does not invoke OCR/extraction.
A running PID is not a sufficient startup result.

## 4. Logging and privacy operations

The logger writes:

- stdout at the configured log level;
- `logs/log.log`, rotating at 10 MB and retaining ten rotations.

The standard LLM handler writes full recognized user text and generated output
at INFO. Manager mode writes audio/image files under `temp/data_tool`. TURN
configuration, including static credentials, is logged at INFO when enabled.

Production controls:

1. make transcript/content logging opt-in;
2. redact API/TURN tokens before structured or text logging;
3. set a restrictive umask and service-owned log directory;
4. configure container/system log rotation as well as Loguru rotation;
5. define retention and deletion for transcripts, audio, images, and backups;
6. exclude `temp/data_tool`, logs, `.env`, and certificates from general support
   bundles unless explicitly authorized;
7. never publish raw logs in an issue without redaction;
8. verify deletion from replicas, object storage, and backups where applicable;
9. exclude every certificate JPEG, OCR span/transcript, extracted value,
   capability, token, prompt/context, receipt, record ID, and capture identity
   from logs, analytics, crash reports, and support bundles;
10. permit certificate-release telemetry only for policy version, opaque
    release ID, released-field count, lifecycle state, duration, and stable
    reason code.

The Manager's in-memory deque is bounded, but its written media files do not
have an automatic cleanup lifecycle in the reviewed code. Add an external
age/size-based cleanup job only after resolving the exact directory and
confirming that no active session is using the target files.

## 5. Capacity and resource management

### 5.1 What `concurrent_limit` controls

The engine-level `chat_engine.concurrent_limit` is copied into every handler
config and handed to the client stream implementation. It is an admission hint,
not a complete resource scheduler:

- it does not reserve GPU memory;
- it does not bound internal RTC audio/video queues;
- it does not bound every third-party worker queue;
- it does not apply per-user quotas or authentication;
- it does not coordinate across processes or hosts.

Never raise it from the preset value without measurements.

### 5.2 Measurement matrix

For each selected preset, record:

| Measurement | Idle | 1 session | Target sessions | Slow client | Disconnect/reconnect |
|---|---:|---:|---:|---:|---:|
| GPU memory used | | | | | |
| Host RSS | | | | | |
| CPU utilization | | | | | |
| GPU utilization | | | | | |
| Frame rate | | | | | |
| End-speech to first-audio latency p50/p95/p99 | | | | | |
| Audio/video drift after 5/15 minutes | | | | | |
| Handler queue depth | unavailable today | | | | |
| Error/cancel rate | | | | | |

Use the actual:

- avatar image/video resolution;
- RTC and avatar FPS;
- batch size;
- LLM/TTS provider and region;
- input audio duration;
- duplex/standard mode;
- connection TTL;
- network loss/latency profile.

Historical “2.2 seconds” or “~3 GB per LiteAvatar session” documentation is not
a substitute for this matrix.

### 5.3 Backpressure safety

The current RTC audio/video queues are unbounded and written from handler
threads into an `asyncio.Queue`. Until remediated:

- use conservative concurrency;
- monitor process RSS continuously;
- set container/system memory limits with a restart/alert plan;
- terminate dead/slow sessions at ingress;
- test network throttling and paused browser tabs;
- alert on sustained RSS growth and media delivery stalls.

After remediation, expected policy should be:

- video: bounded queue, drop stale frames, prefer newest frame;
- audio: bounded latency, controlled drop/close rather than unlimited growth;
- text/signals: bounded, ordered delivery with explicit overflow handling;
- session: close after repeated consumer failure.

## 6. Metrics and alerts

The project does not expose a Prometheus/OpenTelemetry metrics endpoint. At
minimum, collect externally:

- process availability/restarts/exit code;
- readiness and response latency;
- RSS, CPU, threads, file descriptors;
- GPU memory/utilization/temperature/errors;
- disk use for models, logs, build, exp, and temp;
- network connections and egress;
- reverse-proxy request/auth/rate-limit statistics;
- active and rejected sessions;
- TURN allocations, bandwidth, auth failures, relay-port utilization;
- cloud API request rate, latency, error class, and spend;
- certificate expiry;
- image/config/model digest drift;
- enabled-mode OIDC admission failures by stable reason, without token/subject;
- capture lifecycle counts, `PROCESSOR_NOT_READY`, cleanup failures, and
  late-callback drops by stable operation/reason;
- for a future integrated deployment, OCR sidecar health,
  RSS/CPU/thread/process counts, request latency, restart, manifest/identity
  drift, and evidence of any forbidden network/GPU activity;
- in a future integrated deployment, M7 release outcomes and released-field
  counts without field values.

Recommended alerts:

- readiness failure for two consecutive intervals;
- unexpected restart or SIGKILL/OOM;
- GPU unavailable or ECC/Xid error;
- RSS/GPU memory over measured safety threshold;
- disk over 80% or abnormal growth;
- certificate expiry under 30/14/7 days;
- TURN auth failures or allocation surge;
- cloud API 401/403/429/5xx surge;
- direct requests reaching the private application port;
- Manager endpoint access from an unauthorized network;
- capture cleanup/key-destruction failure or `FAILED_CLOSED`;
- OCR identity/qualification/socket-policy drift, unexpected sidecar egress, or
  any CUDA/GPU initialization;
- in a future integrated deployment, repeated release-policy rejection, replay,
  or stale-work drop surge.

## 7. Deployment inventory

Record this release tuple for every deployment:

```text
source Git commit
all submodule commits
container image repository + content digest
Python version
dependency lock/constraints digest
CUDA runtime + NVIDIA driver
selected config digest
secret version identifiers (never values)
model artifact names + immutable revision + SHA-256
avatar resource digest
frontend submodule commit/build digest
TURN version/config digest
certificate feature mode + OIDC config digest
OCR sidecar image + dependency lock digest
OCR model/identity/qualification/deployment-manifest digests
OCR UDS path/mode/expected UID/GID
deployment timestamp and operator/change record
```

The application `/version` response alone is insufficient because it is
hard-coded and currently does not match the root package version.

Useful commands:

```bash
git rev-parse HEAD
git submodule status --recursive
sha256sum /etc/openavatarchat/config.yaml
find models -type f -print0 | sort -z | xargs -0 sha256sum
docker image inspect --format '{{index .RepoDigests 0}}' <image>
nvidia-smi
.venv/bin/python --version
uv pip freeze
```

Model trees can be large; generate/store the manifest once during release
promotion, not on every health probe.

## 8. Backup and restore

### 8.1 Back up

Back up only intentional durable inputs:

- deployment config after secret redaction, or encrypted with access control;
- secret-manager references/versions;
- approved model digest manifest and acquisition record;
- avatar resources that are not reproducibly downloadable;
- image digest/SBOM/provenance;
- deployment unit/Compose/ingress/TURN configuration;
- operational dashboards/alerts.

Usually rebuild or re-download from verified sources rather than backing up:

- `.venv`;
- `__pycache__`;
- transient `build/`/`exp/`;
- Manager temporary media;
- active in-memory sessions.

Whether models themselves are backed up depends on licensing, download
availability, integrity guarantees, and recovery-time objectives.

### 8.2 Restore test

1. provision a clean compatible GPU host;
2. restore the exact source/image digest;
3. restore/render config and secrets;
4. restore or acquire models and verify every digest;
5. verify driver/runtime compatibility;
6. start on a non-production private port;
7. run health, one-session, duplex (if used), TLS, and external TURN tests;
8. promote traffic only after acceptance;
9. confirm logs contain no restored secret values.

Session continuity across restart is not supported.

## 9. Upgrade and rollback

### 9.1 Upgrade

1. freeze the current release tuple.
2. review source and every submodule change.
3. resolve dependencies from the approved lock/constraints in a clean build.
4. acquire/verify model changes separately.
5. validate all selected configs through the real runtime loader.
6. build an immutable image; generate SBOM/provenance.
7. run syntax, unit, integration, browser RTC, slow-client, TURN, security, and
   capacity tests.
8. deploy a canary instance with a separate session pool.
9. drain or terminate existing sessions deliberately; they cannot migrate.
10. promote gradually while watching GPU, memory, latency, API errors, and TURN.

### 9.2 Rollback

Rollback requires the previous:

- image digest;
- config and secret-version set;
- model/avatar set and digests;
- TURN/ingress compatibility;
- driver/runtime compatibility.

Do not roll back code alone while leaving incompatible model/config assets in
place. Stop routing new sessions, drain or terminate current sessions, start
the previous complete tuple, run acceptance, then restore traffic.

## 10. Security operations

### 10.1 Exposure policy

- Public: expose authenticated reverse proxy `443` and deliberate TURN ports
  only.
- Private: application listener `8282`/`8283`.
- Internal beta only: callback `8011` if used.
- Never expose Manager without server-side authorization.
- Prevent container/host metadata and private infrastructure destinations from
  being reachable through a misconfigured relay.

### 10.2 Credential rotation

Rotate independently:

- cloud API keys;
- ingress/session credentials;
- TURN credentials/shared secret;
- TLS private keys/certificates;
- OIDC signing-key/JWKS and audience/issuer configuration versions;
- registry credentials;
- any beta bridge token.

Test that old credentials stop working. Static TURN credentials are visible to
browser clients, so long-lived values are not secrets in the normal server-only
sense.

### 10.3 Model incident

If a model source or artifact is suspected:

1. remove the instance from service;
2. preserve source/image/model hashes and minimal redacted logs;
3. do not load the model again in a privileged environment;
4. rotate credentials accessible to the process;
5. replace from a verified immutable artifact;
6. rebuild the image/host if unsafe pickle loading may have executed code;
7. compare all mounted writable data for unexpected modification.

The global `weights_only=False` patch makes this a code-execution boundary, not
only a model-quality issue.

### 10.4 Certificate privacy or OCR incident

If certificate payload exposure, stale work, store-integrity failure, or OCR
identity drift is suspected:

1. stop new certificate admission without attempting a fallback processor;
2. EndCapture or terminate the owning secure session and require the DEK
   destruction/cleanup barrier; quarantine the process if cleanup cannot be
   proven;
3. preserve only payload-free reason codes, release IDs, versions, digests,
   lifecycle timing, and process/container evidence;
4. do not copy JPEG, OCR, extraction, prompt, capability, token, socket payload,
   or private-store records into incident tickets;
5. replace the OCR image/models/lock/manifest only with the last approved
   immutable bundle and repeat peer/no-network/no-GPU checks;
6. revoke affected OIDC/session authority and restart the single owning process;
7. treat any M7 response emitted before proven End cleanup, or any second
   personalization attempt, as a security incident.

## 11. Troubleshooting matrix

### 11.1 Installation and startup

| Symptom | Likely cause | Evidence/check | Action |
|---|---|---|---|
| `requires-python` failure | Host Python is not 3.11.7–3.11.x | `.venv/bin/python --version` | Recreate venv with supported 3.11 |
| Handler dependency compile fails | CUDA/compiler/RAM mismatch, especially `flash-attn` | Full install log, `nvcc --version`, RAM | Use supported toolchain; preserve first failing command |
| `Module ... not found in search path` | Wrong module path or search path | Config + target `.py` | Correct deployment config; validate before start |
| Runtime accepts install dry-run but startup fails on YAML | Different parser behavior | Real-loader validation | Fix duplicate/invalid key; do not rely on installer alone |
| Qwen preset `DuplicateKeyError` | Two `connection_ttl` entries | Config lines 17/19 | Remove one value and revalidate |
| Process starts with fewer handlers | Common config validation error was logged/skipped | Search startup for `Registered handler` | Compare against approved handler list; fail deployment |
| Startup logs an error but exits 0 | Unhandled startup paths leave the default `exit_code=0` before forced exit | Reproduce with a known-invalid config; inspect readiness/logs | Treat as failure; use restart-always workaround until every path preserves status |
| `api_key`/401/403 | Missing/wrong secret or provider model entitlement | Environment presence, provider response | Inject correct key; never print it |
| Startup hangs/downloads | SenseVoice/avatar/third party auto-download | Network/process/file activity | Pre-stage verified artifact; block runtime egress after rehearsal |

### 11.2 Models and avatars

| Symptom | Likely cause | Action |
|---|---|---|
| LiteAvatar first session fails | Weights exist but selected avatar resource does not | Run `download_avatar_model.py --model <avatar_name>` and verify extraction |
| Smart Turn “model not found” | Any ONNX caused downloader skip, exact `smart-turn-v3.1-cpu.onnx` absent | Verify exact configured filename and digest |
| MuseTalk source video missing | Standard and duplex presets use different source locations | Verify `avatar_video_path` inside host/container |
| MuseTalk cache error | S3FD directory/checkpoint missing or mount wrong | Inspect host path and container `/root/.cache/torch/hub/checkpoints` |
| FlashHead import/build failure | `flash-attn`, xformers, CUDA, or omitted models | Verify dependency build and both model directories |
| Model load is unexpectedly unsafe | Global `torch.load` patch | Do not load unverified artifacts; remediate before production |
| Downloader says complete but runtime fails | Partial directory accepted | Compare exact files/sizes/hashes; reacquire atomically |

### 11.3 Browser, TLS, RTC, and TURN

| Symptom | Likely cause | Action |
|---|---|---|
| Camera/mic API unavailable | Non-localhost HTTP or blocked permission | Use trusted HTTPS; inspect browser permission/policy |
| HTTPS URL refuses/answers HTTP | cert/key absent caused plaintext fallback | Check positive `SSL enabled` log and listener protocol |
| Certificate warning | Self-signed/untrusted, hostname/SAN mismatch, expiry | Install trusted hostname-valid certificate |
| “Waiting…” forever | ICE/NAT/TURN failure or app not advertising TURN | Inspect init config and browser ICE candidates |
| TURN UDP works but restrictive networks fail | TCP/TLS listener/firewall/cert missing | Test `3478/tcp` and `5349/tls`; fix actual key mount |
| coturn runs but no relay candidate | No `RtcClient.turn_config`, invalid credentials, wrong external IP | Add/validate config and inspect coturn logs |
| TURN TLS cannot load key | Compose mounted `.crt` as key | Mount actual private key read-only |
| TURN relay abuse/bandwidth spike | Public static credential/default config | Revoke/rotate, restrict firewall/peers, enable quotas |
| Audio/video drift | RTC FPS differs from avatar FPS | Set equal values; run long-duration sync test |
| MuseTalk fails load after FPS warning | FPS auto-corrected but RTC still uses original value | Use a 24,000-divisor FPS and set both configs explicitly |
| Media stalls/memory rises | Unbounded cross-thread RTC queues, slow client | Terminate session, reduce concurrency; remediate queue design |
| Session ends at 15 minutes | Default `connection_ttl: 900` | Change deliberately and retest resource cleanup |

### 11.4 Docker and Compose

| Symptom | Likely cause | Action |
|---|---|---|
| Docker CLI works, daemon denied | Socket permissions/service state | Use approved Docker access; do not run broad root shell |
| GPU unavailable in container | NVIDIA runtime not configured/authorized | Test minimal CUDA image and runtime config |
| Custom image tag not used | runtime helper hard-codes `latest` | Run explicit image or deliberately retag |
| `-p` appears ignored | helper uses host networking | Expected on Linux; bind/firewall host port directly |
| Compose config passes, startup fails | bind sources missing or directories auto-created | Verify every host path type before `up` |
| Image builds but handler import fails on YAML | `.dockerignore` removed all `*.yaml`/`*.yml` below `src` | Correct/negate broad rules, rebuild, and inspect exact runtime assets |
| Build helper executes unexpected shell text | Untrusted `--tag` reached `eval` | Preserve the invocation/build log; stop the build; remove `eval`; validate input; rotate affected build/registry credentials |
| App works, TURN does not | Compose ordering is not health/readiness, and app lacks `turn_config` | Add health checks and advertise TURN explicitly |
| Agent preset import fails in image | agent `pyproject.toml` omitted from dependency layer | Keep beta native-only or rebuild after dependency fix |
| Agent preset inaccessible in Compose | preset binds 8283 but Compose maps 8282:8282 | Change mapping and ingress deliberately; beta only |

### 11.5 Manager and privacy

| Symptom | Cause/action |
|---|---|
| Manager token seems accepted regardless of value | Expected only in legacy/default compatibility mode; isolate/disable Manager there. In enabled mode, verify `oac:manager` and ticket admission; acceptance is an incident |
| Unknown client can see all sessions | Legacy/default mode remains an unauthenticated hub; in enabled mode this is an incident |
| Config snapshot leaks secrets | Inline handler keys were serialized; rotate keys and remove inline values |
| Temporary media keeps growing | No automatic file cleanup; stop exposure, establish safe retention cleanup |
| Logs contain full transcripts | Current INFO logging; restrict access and change/redact logging |

### 11.6 Secure certificate capture and OCR

The current public capture path stops at `PROCESSOR_NOT_READY`; it cannot emit
template or release outcomes. The template/release rows below describe
owner-only component diagnostics and the required behavior of a future
production composition, not current HTTP responses.
The [certificate extractor module reference](certificate-extractor.md)
documents the internal M6B/M6C reason and abstention contracts.

| Symptom/reason | Likely cause | Action |
|---|---|---|
| Enabled startup fails with `TLS_*` or `MULTI_WORKER_UNSUPPORTED` | Missing/mismatched/encrypted TLS material or worker count is not exactly one | Correct reviewed TLS paths and `workers`/`WEB_CONCURRENCY`; do not bypass the gate |
| `AUTHENTICATION_FAILED` or `REQUIRED_SCOPE_MISSING` | Invalid `at+jwt`, issuer/audience/time/key mismatch, or wrong purpose scope | Fix the identity-provider/client flow; keep `certificate:capture` and `oac:manager` separate |
| `UNSUPPORTED_PROFILE` | Client did not request exact `hbtc_admission_notice_v1` | Fix the client; do not add a dynamic profile or trust a client-supplied school |
| `PROCESSOR_NOT_READY` | Current production Seal is not composed with M6A OCR/M6B extraction and only admits a constructor-injected test processor; this is unconditional after the frame gate | EndCapture and clean browser state; implement/review production composition and complete real isolated CPU qualification before enablement |
| Log warning `CERTIFICATE_OCR_UNAVAILABLE_V1` | Startup deployment candidate is malformed/conflicting or otherwise rejected; it is not an HTTP capture reason | Compare only approved hashes/identity/UDS policy; do not enable fallback/downloads/network; remember that a valid candidate still cannot make current Seal process |
| `NEEDS_RECAPTURE` | Fewer than three independent accepted JPEGs in the current implementation | Add a new sequence up to the limit; if full, End then begin a new capture |
| Template is `NOT_MATCHED` or `INSUFFICIENT` | Wrong-school heading or insufficient compatible title/body anchors | Do not extract, release, guess, or claim authenticity; recapture only when UX permits |
| `ADMISSION_RELEASE_NO_FIELDS` | No extracted field is exactly `FOUND` | End without a personalized turn; do not release ambiguous/missing candidates |
| Capture stays `FAILED_CLOSED` | Cleanup, authority, identity, timeout, or stale-work proof failed | Terminate/quarantine the secure session; investigate with payload-free evidence |
| Browser camera/photo state persists after cancel/Error/End | M8 cleanup or camera handoff failed | Treat as a privacy defect; revoke Object URLs, stop capture track, restore normal track, clear in-memory capabilities |

## 12. Validation performed for this report

All commands were bounded and avoided model downloads, paid APIs, service
startup, or persistent external effects.

### 12.1 Environment observed

| Tool | Observed |
|---|---|
| Host Python | 3.14.4; unsupported for the project |
| Project venv Python | 3.11.16; satisfies project constraint |
| uv | 0.12.5 |
| Docker CLI | 29.1.3 |
| Docker Compose | 2.40.3 |
| Node | 26.2.0 |
| npm | 12.0.1 |
| Bash | 5.3.9 |
| FFmpeg | 8.0.1 |
| GPU query | Not available: NVML access blocked by the environment |
| Docker daemon | Not available to this user: socket permission denied |

Tool versions describe this review host, not project minimums.

### 12.2 Successful checks

| Check | Result | Meaning |
|---|---|---|
| `uv lock --check --offline` with isolated cache | Exit 0; 149 packages | The local ignored lock was internally current offline; it is not tracked delivery evidence |
| `install.py --dry-run` for every preset | 13/13 exit 0 | Dependency discovery works without installing |
| Real Dynaconf/Pydantic loader | 12/13 valid | Qwen preset rejected for duplicate key |
| Missing-config process probe | Logged missing config, exited `0` | Confirms process status currently masks startup failure |
| Enabled module path scan | 105 references, 0 missing paths | Every enabled module string maps to a source file |
| Python source compile | 910 `src/**/*.py`, 0 syntax failures | Broad syntax only; includes external trees |
| First-party Python AST scan | 255 files, 0 syntax failures | First-party syntax only |
| `docker compose config --no-interpolate` | Exit 0 | Compose schema/normalization only |
| Supported top-level shell scripts `bash -n` | Exit 0 | Shell syntax only |
| MuseTalk FFmpeg helper run as a script | Exit 0 | FFmpeg executable discovery works |
| Model downloader `--help` | Exit 0 | CLI loads; it has no dry-run |

One third-party Python file emitted a warning for `is not -2`; it did not fail
compilation.

### 12.3 Reproduced failures

#### Qwen runtime configuration

The real loader raises `DuplicateKeyError` for
`config/chat_with_qwen_omni.yaml` because `connection_ttl` is declared twice.
The installer dry-run still passes. This is a deployment blocker for that
preset.

#### Process failure status

```bash
.venv/bin/python -B src/demo.py \
  --config /tmp/openavatarchat-review-missing-config.yaml
```

The process logged that the config did not exist and returned exit code `0`.
This confirms that this unhandled startup path leaves the default exit code
before `os._exit(exit_code)`. No file was created and no service was started.

#### Focused MuseTalk pytest

```bash
.venv/bin/pytest -q \
  src/handlers/avatar/musetalk/MuseTalk/test_ffmpeg.py
```

Exit 1: the test function requests an undefined `ffmpeg_path` fixture. Running
the same helper as its intended script succeeds, so this is a vendored pytest
collection defect, not evidence that FFmpeg is unavailable.

#### 2026-08-18 prebuilt frontend type checks

The frontend submodule's node and web type checks exit 2:

- unused symbols and missing `Window` properties in main/preload code;
- unresolved TypeScript module typing for
  `gaussian-splat-renderer-for-lam`.

Normal backend deployment serves the checked-in prebuilt `dist`, so this blocks
a clean frontend rebuild/type-check claim rather than proving that the current
dist cannot be served.

#### pnpm on the review host

The declared frontend package manager is pnpm 10.10.0. Under the review host's
Node 26/Corepack combination, `pnpm --version` fails with
`ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`. Use the frontend project's supported
Node/Corepack toolchain in a clean build environment.

#### Compose readiness

Compose syntax passes, but expected bind sources are absent and the TURN key
mount is wrong. `docker compose up` was not run because it could create
directories, start persistent services, pull images, and expose host-network
ports without producing a meaningful ready deployment.

### 12.4 Intentionally skipped

- full app startup;
- model and dependency downloads;
- paid/external API calls;
- Docker image build or Compose startup;
- real TLS/TURN/browser WebRTC;
- broad vendored pytest collection;
- docs build output;
- performance/load/GPU-memory measurement.

No end-to-end success, production readiness, or performance result should be
inferred from the static/syntax checks.

### 12.5 Secure-capture incremental evidence

The 2026-08-27 refresh additionally reviewed current HEAD `6db2b96`, the pinned
WebUI `b82f290`, the enabled/disabled route split, M2/M3 authority and fencing,
M4/M5 capture/private storage, M6A–M6C OCR/extraction/template code, M7 release,
M8 WebUI documentation/tests, and the OCR Compose boundary.
Dedicated first-party suites now exist for each of these layers.
The review also confirmed that production Seal calls none of the M6A/M6B/M7
owner-only seams and unconditionally requires a constructor-injected test
processor; this missing composition is a separate release blocker from OCR
qualification.

| Check rerun for this refresh | Result | Scope |
|---|---|---|
| M6B extractor suite | 75 passed in 3.32 s; one third-party deprecation warning | Four-field contracts/rules, ambiguity, page-order invariance, encrypted store, authority/lifecycle, isolation, races, performance smoke |
| M6C template suite | 74 passed in 1.19 s | Fixed HBTC identity, title/body compatibility, adversarial layouts, matched-page-only extraction, performance smoke |
| M7 backend suite | 40 passed in 1.01 s | Release contract, sanitizer, authority/lifecycle, races, ChatAgent context/tools, performance smoke |
| Certificate startup-gate service suite | 35 passed in 3.34 s; one third-party deprecation warning | Enabled/disabled configuration, TLS/worker/startup behavior |
| Documented secure service config through Pydantic | Passed | Confirms the YAML shape and exact `certificate:capture` field contract |
| `docker compose --profile certificate-ocr config --no-interpolate --quiet` | Passed | Compose rendering only; no image build or service start |
| Bilingual documentation gate | Passed: 5 pairs, 59 identical fenced blocks per language, 35 matching tables, 116 local links | Structural/content parity and local target existence |
| Frontend `pnpm run test:m8` | Not run | Pinned submodule has no `node_modules`; Node 26/Corepack fails to launch pnpm with `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`; no install was attempted |

No real Paddle/PP-OCRv6 model, qualified sidecar image, production manifest,
real certificate, browser camera, network service, or GPU was used. Synthetic
test success must not be promoted into a production OCR or end-to-end claim.

## 13. Recommended validation pipeline

### Gate A — source and configuration

- clean checkout and expected submodule commits;
- secret scan;
- real-loader validation of every supported preset;
- reject duplicate YAML keys;
- enabled module/path validation;
- enabled/disabled route inventory and purpose-scope separation;
- first-party lint/type/unit tests;
- dependency lock/constraints verification.

### Gate B — artifact build

- clean offline-capable image build from pinned base digest;
- SBOM and provenance;
- vulnerability/license policy;
- non-root runtime;
- exact model manifest with hashes and licenses;
- separately locked/hashed CPU OCR image, models, identity, qualification
  record, deployment manifest, and UDS ownership policy;
- frontend clean install/build/type check.

### Gate C — component integration

- mocked and real selected handler graph;
- model initialization;
- cloud handler auth/error/timeouts;
- standard and duplex stream/cancel tests;
- session isolation and cleanup;
- milestone security/fencing/capture/OCR/extraction/release suites run
  independently, including stale-callback and cleanup races;
- production Seal integration tests that invoke exact-fenced OCR, extraction,
  release, failure, and cleanup without a constructor-injected test processor;
- SIGTERM with active sessions;
- Manager authorization and retention.

### Gate D — media/network

- browser HTTPS permissions;
- M8 camera handoff, bounded JPEG preparation, cancel/error/End cleanup, and
  real-document capture;
- RTC signalling and audio/video/text;
- FPS and long-run A/V sync;
- network loss/reconnect;
- slow-client backpressure;
- external TURN UDP/TCP/TLS relay;
- credential expiry and relay abuse controls.

### Gate E — capacity and release

- target concurrency soak;
- GPU/RAM/CPU/disk/network safety margins;
- after production composition exists, real CPU OCR statistical qualification,
  RSS/thread/process/latency budgets, no-GPU/no-network proof, and realtime
  GPU-workload contention;
- p50/p95/p99 latency;
- external API rate/spend;
- canary, alerts, backup/restore, and rollback rehearsal.

Release only when every gate has an owner, evidence artifact, and explicit
acceptance decision.

## 14. Remediation order

1. Block direct public access; enforce authenticated ingress and disable/protect
   Manager in legacy mode or validate strict enabled-mode authorization.
2. Remove checked-in TURN credentials; fix TURN key/config/application wiring.
3. Remove or isolate unsafe PyTorch loading and verify immutable model artifacts.
4. Fix bounded event-loop-safe RTC output queues.
5. Establish tracked locked dependencies and immutable image/model manifests.
6. Make TLS and selected prerequisites fail closed.
7. Fix Qwen config, model downloader result validation, and FPS compatibility
   checks.
8. Stop active sessions transactionally on shutdown/failure.
9. Preserve real process failure status and orderly log/resource cleanup.
10. Remove `eval` from the privileged image build helper.
11. Wire history retention or remove nonfunctional tuning claims.
12. Add core tests, metrics, prerequisite-aware readiness, and non-root runtime.
13. Align versioning and documentation.
14. Address beta Agent packaging/callback only if that feature becomes a
    deployment priority.
15. Keep production certificate processing disabled until the missing
    Seal-to-OCR/extraction/release composition is implemented and independently
    reviewed, then the separate CPU OCR qualification and real-camera M8
    acceptance gates pass.
