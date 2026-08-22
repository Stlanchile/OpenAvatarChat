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
- restart terminates all conversations and discards in-memory histories.

`src/demo.py` currently forces exit status `0` from `finally`, including after
startup failure. Supervisors, CI, and shell automation must require positive
readiness and log/handler evidence rather than interpreting zero as success.

Operate one application process per allocated GPU/service instance. Scale by
explicitly partitioning users across isolated instances with admission control,
not by adding Uvicorn workers to one process command.

## 2. Health endpoints and their exact meaning

| Endpoint | Success means | It does not prove |
|---|---|---|
| `/version` | HTTP app is responding and exposes hard-coded application version | Git/image/model/config identity |
| `/liveness` | FastAPI process/event loop can answer a simple request | Handler threads, GPU, TURN, models, API connectivity |
| `/readiness` | `ChatEngine.initialize()` completed and set `inited` | Browser RTC path, credentials, model integrity, TURN, capacity |

Suggested probes behind the private listener:

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

A deployment-specific readiness gate should additionally check:

- selected exact model files and approved hashes;
- CUDA device availability and a small non-destructive allocation/inference;
- certificate/key existence, match, hostname, and expiry when direct TLS is
  selected;
- required API key presence without logging the value;
- DNS/TCP/TLS reachability of selected cloud handlers;
- TURN allocation/relay path when TURN is required;
- disk space and writable output/cache paths;
- current sessions below the admission threshold.

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
```

The application can continue after some handler-time processing exceptions,
and TLS explicitly continues after missing files. A running PID is not a
sufficient startup result.

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
8. verify deletion from replicas, object storage, and backups where applicable.

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
- image/config/model digest drift.

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
- Manager endpoint access from an unauthorized network.

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
| Startup logs an error but exits 0 | `os._exit(0)` masks the real result | Reproduce with a known-invalid config; inspect readiness/logs | Treat as failure; use restart-always workaround until code preserves status |
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
| Manager token seems accepted regardless of value | Backend does not validate it; isolate/disable Manager |
| Unknown client can see all sessions | Expected current unauthenticated hub behavior; treat as incident if exposed |
| Config snapshot leaks secrets | Inline handler keys were serialized; rotate keys and remove inline values |
| Temporary media keeps growing | No automatic file cleanup; stop exposure, establish safe retention cleanup |
| Logs contain full transcripts | Current INFO logging; restrict access and change/redact logging |

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
This directly confirms that the unconditional `os._exit(0)` masks startup
failure. No file was created and no service was started.

#### Focused MuseTalk pytest

```bash
.venv/bin/pytest -q \
  src/handlers/avatar/musetalk/MuseTalk/test_ffmpeg.py
```

Exit 1: the test function requests an undefined `ffmpeg_path` fixture. Running
the same helper as its intended script succeeds, so this is a vendored pytest
collection defect, not evidence that FFmpeg is unavailable.

#### Prebuilt frontend type checks

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

## 13. Recommended validation pipeline

### Gate A — source and configuration

- clean checkout and expected submodule commits;
- secret scan;
- real-loader validation of every supported preset;
- reject duplicate YAML keys;
- enabled module/path validation;
- first-party lint/type/unit tests;
- dependency lock/constraints verification.

### Gate B — artifact build

- clean offline-capable image build from pinned base digest;
- SBOM and provenance;
- vulnerability/license policy;
- non-root runtime;
- exact model manifest with hashes and licenses;
- frontend clean install/build/type check.

### Gate C — component integration

- mocked and real selected handler graph;
- model initialization;
- cloud handler auth/error/timeouts;
- standard and duplex stream/cancel tests;
- session isolation and cleanup;
- SIGTERM with active sessions;
- Manager authorization and retention.

### Gate D — media/network

- browser HTTPS permissions;
- RTC signalling and audio/video/text;
- FPS and long-run A/V sync;
- network loss/reconnect;
- slow-client backpressure;
- external TURN UDP/TCP/TLS relay;
- credential expiry and relay abuse controls.

### Gate E — capacity and release

- target concurrency soak;
- GPU/RAM/CPU/disk/network safety margins;
- p50/p95/p99 latency;
- external API rate/spend;
- canary, alerts, backup/restore, and rollback rehearsal.

Release only when every gate has an owner, evidence artifact, and explicit
acceptance decision.

## 14. Remediation order

1. Block direct public access; enforce authenticated ingress and disable/protect
   Manager.
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
