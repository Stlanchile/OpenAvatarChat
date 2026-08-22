# OpenAvatarChat Deployment Guide

[简体中文](zh-cn/deployment-guide.md) | English

## 1. Read this first

This guide covers the core OpenAvatarChat service. The beta OpenClaw path is
not a primary deployment target.

The checked-in deployment is a useful development scaffold, not a secure
public stack. In particular:

- do not expose application port `8282` or `8283` directly to the Internet;
- do not deploy `coturn-data/turnserver.conf` with its checked-in credential;
- do not expect `docker compose up` alone to provide working TURN;
- do not claim HTTPS unless a valid certificate/key pair was actually loaded;
- do not use Qwen-Omni until its duplicate YAML key is removed;
- do not put API keys in a Manager-enabled YAML file.

For public operation, use an authenticated TLS ingress in front of the
application and a separately hardened TURN service. The application currently
has no built-in authentication or rate limiting, so the ingress is a required
compensating control, not an optional optimization.

The process also currently forces exit code `0` even after startup failure.
Require positive readiness/log evidence; do not use a zero exit status as the
only deployment success condition.

## 2. Choose a deployment method

| Method | Best for | Advantages | Important limitations |
|---|---|---|---|
| Native `uv` | First install, development, single dedicated GPU host | Easiest diagnostics; preset-scoped dependency install | Host libraries and Python must be controlled; dependency resolution is not tracked/locked |
| Standalone Docker | Isolated single-host runtime after image-content correction | Bundled CUDA/Python/system dependencies | Broad `.dockerignore` removes handler YAML; large all-handler build; root runtime; floating dependency resolution |
| Docker Compose | Lab app + coturn orchestration | One command after preparation | Shipped TURN config/key mount is unsafe/broken; app does not advertise TURN automatically |
| Public production topology | Remote users | Trusted TLS, auth, rate limits, deliberate TURN | Requires external ingress/security work and remediation gates; not supplied as a ready stack |

Recommended sequence:

1. Prove the selected preset natively on localhost.
2. Record its models, GPU memory, latency, and required egress.
3. Build and verify an immutable image for that exact commit.
4. Add authenticated TLS ingress.
5. Add and externally test TURN only when the client network requires it.
6. Load-test the intended session count before increasing
   `chat_engine.concurrent_limit`.

## 3. Supported deployment target

The repository's concrete container target is Linux on x86-64, Ubuntu 22.04,
Python 3.11, and NVIDIA CUDA 12.8. Native operation on another platform may be
possible for selected handlers but is not covered by the current deployment
artifacts.

Hard source constraints:

- Python `>=3.11.7,<3.12`;
- PyTorch `2.8.0` CUDA 12.8 wheels;
- Git submodules and Git LFS;
- FFmpeg and audio/graphics system libraries;
- an NVIDIA GPU for the documented presets and container path.

For the CUDA 12.8 image, use a Linux NVIDIA driver at or above `570.26` as the
operational baseline. NVIDIA documents `525.60.13` as the lower CUDA 12.x
minor-version compatibility floor, but that is not the safest baseline for a
CUDA 12.8.1 production image. See the
[CUDA 12.8 release notes](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-toolkit-release-notes/index.html).

The repository does not specify a minimum GPU model, VRAM, RAM, disk capacity,
or network bandwidth. Those must be measured for the selected preset. Do not
turn historical RTX 4090 latency/VRAM statements into sizing guarantees.

## 4. Network and browser decision

| Client location | Application TLS | TURN | Recommended exposure |
|---|---|---|---|
| Same host via `localhost` | HTTP is acceptable for development because browsers treat localhost as potentially trustworthy | Usually not needed | Bind loopback where possible |
| Trusted LAN | Trusted HTTPS strongly recommended; browser must trust the certificate | Depends on LAN/NAT policy | Restricted firewall/VPN; no direct public listener |
| Internet | Trusted HTTPS required for camera/microphone | Required for robust restrictive-NAT coverage | Authenticated reverse proxy on 443; separate TURN host |
| Embedded iframe | HTTPS plus Permissions Policy and iframe `allow` attributes | Network dependent | Explicit `camera`/`microphone` policy |

Browser `getUserMedia()` is restricted to secure contexts; see
[MDN](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
and [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/).

## 5. Common preflight

### 5.1 Pin the source snapshot

For a reproducible review/deploy handoff, use a named release commit rather
than an unqualified branch:

```bash
git clone https://github.com/HumanAIGC-Engineering/OpenAvatarChat.git
cd OpenAvatarChat
git checkout <approved-commit>
git lfs install
git submodule update --init --recursive
git submodule status --recursive
```

Expected submodule status has a leading blank for each clean, initialized
submodule. A leading `-` means uninitialized; `+` means a different commit is
checked out. Do not use `git submodule update --remote` in a pinned deployment.

The reviewed fork commit is:

```text
8b7b3b45bca28ae9ab5fa72ee31bc03c5a99b08b
```

### 5.2 Host checks

```bash
nvidia-smi
git --version
git lfs version
ffmpeg -version
openssl version
df -h .
free -h
```

For containers, also check:

```bash
docker version
docker compose version
docker run --rm --gpus all nvidia/cuda:12.8.1-base-ubuntu22.04 nvidia-smi
```

The last command pulls an image if absent. In a controlled/offline environment,
use the approved locally mirrored image instead.

NVIDIA's current Docker runtime setup is:

```bash
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

See the
[NVIDIA Container Toolkit install guide](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html).

### 5.3 Egress inventory

Permit only the endpoints needed by the selected preset and model source.
Potential egress includes:

- PyPI/uv and the PyTorch CUDA 12.8 index during installation;
- GitHub plus Git LFS for submodules;
- ModelScope, Hugging Face, `hf-mirror.com`, or Aliyun OSS for models;
- configured OpenAI-compatible, DashScope/Bailian, Dify, or Edge TTS endpoints;
- DNS and trusted CA/OCSP services;
- TURN if hosted externally.

Model and dependency downloads are not immutable or checksum-verified by the
repository. For an offline/production build, mirror approved artifacts,
generate a digest manifest, and refuse activation on mismatch.

### 5.4 Select a preset

| Need | Starting preset | Extra preparation |
|---|---|---|
| Simplest core RTC path | `config/chat_with_openai_compatible_bailian_cosyvoice.yaml` | `DASHSCOPE_API_KEY`, LiteAvatar weights and avatar resource |
| Local TTS | `config/chat_with_openai_compatible.yaml` | Local CosyVoice dependencies/models; heavier install |
| No TTS API key | `config/chat_with_openai_compatible_edge_tts.yaml` | Edge TTS network reachability; LLM key still required |
| User interruption/duplex | `..._bailian_cosyvoice_duplex.yaml` | Smart Turn exact ONNX plus semantic LLM credentials |
| MuseTalk | `..._musetalk.yaml` | MuseTalk models, source video, matching RTC/avatar FPS, `PYTORCH_JIT=0` in container |
| FlashHead | `..._flashhead.yaml` | FlashHead + wav2vec models, `flash-attn` build, conservative concurrency |
| LAM client rendering | `config/chat_with_lam.yaml` | LAM models and selected LAM asset |
| Qwen-Omni | `config/chat_with_qwen_omni.yaml` | **Blocked until duplicate `connection_ttl` is fixed** |

Do not start with `--all` unless you truly need one development environment
containing every handler. It resolves many conflicting native/CUDA packages and
is much more expensive than a preset-scoped install.

### 5.5 Copy and review configuration

Do not edit a tracked preset in place for production. Render a deployment copy
outside the source tree, for example:

```text
/etc/openavatarchat/config.yaml
/etc/openavatarchat/openavatarchat.env
/etc/openavatarchat/tls/fullchain.pem
/etc/openavatarchat/tls/privkey.pem
```

Review at minimum:

- `service.host` and `service.port`;
- TLS termination choice;
- `chat_engine.model_root`;
- `chat_engine.concurrent_limit`;
- every enabled handler and module;
- every API endpoint/model name;
- avatar and model paths;
- `RtcClient.connection_ttl`;
- `RtcClient.output_video_fps`;
- TURN configuration, if used;
- Manager disabled unless its routes are protected.

Configuration corner cases:

- `OPEN_AVATAR_CHAT_CONFIG` overrides the CLI `--config` value.
- Relative paths resolve from the project root in most engine paths, but some
  third-party code still assumes its expected directory layout.
- MuseTalk requires `RtcClient.output_video_fps` to equal
  `AvatarMusetalk.fps`; the shipped MuseTalk presets use `24` for both.
- Other avatar modes do not have the same runtime equality guard. Several
  shipped LiteAvatar/FlashHead presets use avatar `25` and RTC default `30`;
  treat any difference between produced and paced FPS as an integration risk,
  and verify long-running A/V synchronization empirically.
- MuseTalk FPS must be `1..49` and should divide 24,000; supported/recommended
  values include 15, 16, 20, 24, 25, 30, 32, 40, and 48.
- MuseTalk `batch_size` must be at least 2.
- Duplex `history` settings in YAML currently have no runtime effect.
- The per-handler `concurrent_limit` is overwritten by the engine-level value.

### 5.6 Prepare secrets

Normal cloud presets need:

```text
DASHSCOPE_API_KEY
```

Optional paths may need:

```text
DIFY_API_KEY
SEMANTIC_LLM_EAS_TOKEN
INTERRUPT_JUDGE_LLM_EAS_TOKEN
```

Use a deployment secret manager or a root/service-user-readable environment
file:

```bash
sudo install -d -m 0750 -o openavatarchat -g openavatarchat /etc/openavatarchat
sudo install -m 0600 -o openavatarchat -g openavatarchat \
  /path/to/prepared.env /etc/openavatarchat/openavatarchat.env
```

Do not:

- commit `.env`;
- paste a real secret into shell history;
- bake secrets into the image;
- put API keys inline in a Manager-enabled YAML;
- expose `.env` through a read-write container mount when an environment/secret
  injection mechanism is available.

The current logger records complete conversation text and TURN config. Protect
logs and avoid static TURN credentials until logging is redacted.

### 5.7 Validate YAML through the real loader

After creating the environment, use the actual Dynaconf/Pydantic path:

```bash
PYTHONPATH=src .venv/bin/python -B - /etc/openavatarchat/config.yaml <<'PY'
import sys
from types import SimpleNamespace
from service.service_utils.service_config_loader import load_configs

path = sys.argv[1]
logger_config, service_config, engine_config = load_configs(
    SimpleNamespace(config=path, env="default")
)
print("service", service_config.host, service_config.port)
print("model_root", engine_config.model_root)
print("handlers", sorted((engine_config.handler_configs or {}).keys()))
PY
```

Then verify dependency discovery without installing:

```bash
.venv/bin/python -B install.py \
  --config /etc/openavatarchat/config.yaml \
  --dry-run
```

Both checks matter. The installer uses a different YAML parser and currently
accepts the invalid Qwen duplicate that the runtime loader rejects.

## 6. Native Linux deployment

### 6.1 Install system packages

On Ubuntu 22.04:

```bash
sudo apt-get update
sudo apt-get install -y \
  git git-lfs build-essential curl ca-certificates openssl \
  libgl1 libglib2.0-0 libsm6 libxext6 libgomp1 \
  libsndfile1 ffmpeg sox libsox-dev \
  libavcodec-dev libavformat-dev libswscale-dev
```

Install `uv` from your approved source. In a production build, pin and verify
the installer/package version rather than executing a floating remote install
script.

```bash
uv --version
uv python install 3.11
uv venv --python 3.11 --seed
.venv/bin/python --version
```

The resulting Python must be at least 3.11.7 and below 3.12.

### 6.2 Install only the selected handler set

Example:

```bash
uv run install.py \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml
```

For multiple approved presets:

```bash
uv run install.py \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml \
  --config config/chat_with_openai_compatible_bailian_cosyvoice_duplex.yaml
```

Installation compiles some packages from source. FlashHead's `flash-attn` path
uses at most four compilation jobs, but still needs sufficient RAM, build time,
and CUDA compiler compatibility.

Capture for release evidence:

```bash
.venv/bin/python --version
uv pip freeze
nvidia-smi
```

The generated local `uv.lock` is ignored by this repository; archive a reviewed
dependency manifest separately until a tracked lock workflow exists.

### 6.3 Download models

The unified model downloader has no dry-run mode and may install missing
download tooling. The command performs network writes:

```bash
uv run scripts/download_models.py \
  --config /etc/openavatarchat/config.yaml \
  --source huggingface
```

or, for a known handler:

```bash
uv run scripts/download_models.py --handler liteavatar
uv run scripts/download_models.py --handler smart_turn_eou
uv run scripts/download_models.py --handler musetalk
uv run scripts/download_models.py --handler flashhead
uv run scripts/download_models.py --handler lam
```

`--source modelscope` selects ModelScope or the configured mirror path where
implemented. Source selection is not equivalent to artifact verification.

LiteAvatar weights and a concrete avatar resource are separate. Pre-stage the
avatar selected by the config:

```bash
uv run scripts/download_avatar_model.py \
  --model 20250408/sample_data
```

This avoids a first-session download from inside the avatar handler. It also
creates the `bg_video_silence.mp4` used by the shipped duplex MuseTalk preset.

Important automatic-download cases:

- SenseVoice may download through ModelScope during handler load.
- Some local third-party components may fetch their own checkpoints.
- A directory's existence does not prove all expected files are present.

For production, run with egress disabled only after a clean-host rehearsal has
identified and mirrored every artifact.

### 6.4 Verify exact model inputs

Minimum source-level checks by path:

```bash
test -s models/smart_turn/smart-turn-v3.1-cpu.onnx
test -d models/SoulX-FlashHead-1_3B
test -d models/wav2vec2-base-960h
test -d models/musetalk
test -s resource/avatar/liteavatar/20250408/sample_data/bg_video_silence.mp4
test -s resource/avatar/flashhead/girl.png
```

Run only the checks applicable to the preset. These are presence checks, not
integrity checks. Add SHA-256 validation against an approved manifest.

For MuseTalk, confirm the configured source video exists and the S3FD
checkpoint is reachable at the path/cache expected by both native and
container runs.

### 6.5 Localhost smoke run

Use no-sync operation after installation so startup does not change the
environment:

```bash
set -a
. /etc/openavatarchat/openavatarchat.env
set +a

uv run --no-sync src/demo.py \
  --config /etc/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
```

For local HTTP fallback:

```text
http://localhost:8282/
```

For direct Uvicorn TLS:

```text
https://localhost:8282/
```

Use HTTPS only when logs confirm `SSL enabled` and the client trusts a
hostname-valid certificate.

Check:

```bash
curl --fail http://127.0.0.1:8282/version
curl --fail http://127.0.0.1:8282/liveness
curl --fail http://127.0.0.1:8282/readiness
```

Switch to `https://` for a TLS listener. `curl -k` is acceptable only for an
explicit self-signed development test, never as production verification.

### 6.6 Dedicated service process

Use a dedicated, unprivileged user and one process. A representative systemd
unit is:

```ini
[Unit]
Description=OpenAvatarChat
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openavatarchat
Group=openavatarchat
WorkingDirectory=/opt/openavatarchat
EnvironmentFile=/etc/openavatarchat/openavatarchat.env
ExecStart=/opt/openavatarchat/.venv/bin/python \
  /opt/openavatarchat/src/demo.py \
  --config /etc/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
Restart=always
RestartSec=5
TimeoutStopSec=60
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/openavatarchat/logs
ReadWritePaths=/opt/openavatarchat/temp
ReadWritePaths=/opt/openavatarchat/build
ReadWritePaths=/opt/openavatarchat/exp

[Install]
WantedBy=multi-user.target
```

Adjust GPU device permissions and writable model/cache paths deliberately.
Test SIGTERM with an active session before relying on graceful shutdown; the
current engine does not explicitly stop all sessions during engine shutdown.

`Restart=always` is intentional here: `src/demo.py` currently converts startup
failures to exit status zero, so `Restart=on-failure` would not restart them.
`systemctl stop` still suppresses policy restart. A zero exit status must not
satisfy deployment acceptance; probe `/readiness` and compare registered
handlers with the approved config.

Do not configure multiple workers.

## 7. Standalone Docker deployment

### 7.1 Build prerequisites

Before building:

- initialize every submodule;
- ensure Docker can access the NVIDIA runtime;
- ensure the selected registry/mirrors are approved and reachable;
- budget for an all-handler CUDA build including native compilation;
- understand that the image build does not use a tracked lockfile.
- correct the broad `.dockerignore` rules that exclude all `*.yaml` and
  `*.yml`, including runtime files below `src/`.

The stock context is incomplete for YAML-dependent handlers. FlashHead, for
example, imports
`src/handlers/avatar/flashhead/SoulX-FlashHead/flash_head/configs/infer_params.yaml`,
which the current ignore rule removes before `COPY ./src`. Do not use a
successful image build as FlashHead/LiteAvatar/MuseTalk/local-CosyVoice
readiness evidence. Scope the ignore to actual deployment/Kubernetes files or
explicitly re-include runtime YAML under `src`, then test the final image.

Build with an explicit immutable tag:

```bash
bash build_cuda128.sh \
  --tag open-avatar-chat:8b7b3b45
```

The helper's default is `open-avatar-chat:latest`. The runtime helper also
hard-codes `open-avatar-chat:latest`; use direct `docker run` or retag
deliberately when testing another tag.

Only pass trusted `--tag`/`--push` values to the current build helper. It builds
a shell string and executes it with `eval`; do not feed it branch, pull-request,
or user input until that implementation is replaced with an argument array.

Do not treat a successful image build as model readiness. Models and runtime
resources are mounted from the host.

### 7.2 Inspect the image

```bash
docker image inspect open-avatar-chat:8b7b3b45
docker history --no-trunc open-avatar-chat:8b7b3b45
docker run --rm --entrypoint test \
  open-avatar-chat:8b7b3b45 \
  -s /root/open-avatar-chat/src/handlers/avatar/flashhead/SoulX-FlashHead/flash_head/configs/infer_params.yaml
docker run --rm --gpus all \
  --entrypoint uv \
  open-avatar-chat:8b7b3b45 \
  run --no-sync python -c \
  "import sys, torch; print(sys.version); print(torch.__version__); print(torch.cuda.is_available())"
```

Run the YAML presence check only for a FlashHead-capable image, and add
equivalent exact asset checks for the selected handler.

For a controlled release, record the image content digest after pushing to an
immutable registry. The Dockerfile's `APP_VERSION` is metadata, not a content
identity.

### 7.3 Run a standard preset

The repository helper uses host networking:

```bash
bash run_docker_cuda128.sh \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml
```

On Linux, `-p 8282:8282` has no effect when `--network=host` is used. The
process binds the host port directly.

For production control, prefer an explicit command so the image, mounts, and
environment are visible:

```bash
docker run --rm --gpus all \
  --name open-avatar-chat \
  --network host \
  --env-file /etc/openavatarchat/openavatarchat.env \
  -e NVIDIA_VISIBLE_DEVICES=all \
  -e NVIDIA_DRIVER_CAPABILITIES=compute,video,utility \
  -v /srv/openavatarchat/models:/root/open-avatar-chat/models \
  -v /srv/openavatarchat/resource:/root/open-avatar-chat/resource \
  -v /srv/openavatarchat/build:/root/open-avatar-chat/build \
  -v /srv/openavatarchat/exp:/root/open-avatar-chat/exp \
  -v /srv/openavatarchat/logs:/root/open-avatar-chat/logs \
  -v /etc/openavatarchat/config.yaml:/run/openavatarchat/config.yaml:ro \
  -v /etc/openavatarchat/tls:/etc/openavatarchat/tls:ro \
  open-avatar-chat:8b7b3b45 \
  --config /run/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
```

With host networking, binding `127.0.0.1` is appropriate when a host reverse
proxy supplies public ingress. If clients connect directly on a trusted LAN,
the bind address and firewall must be changed deliberately.

The image runs as root. Until the image is remediated, reduce exposure and make
configuration/TLS mounts read-only. Models/resources can be read-only only
after all handlers have proven they do not download, extract, preprocess, or
cache into those mounts at runtime.

### 7.4 MuseTalk Docker case

The helper detects MuseTalk textually and adds:

```text
PYTORCH_JIT=0
```

It also mounts the S3FD model directory into Torch's checkpoint cache. Confirm:

- the config contains the exact `AvatarMusetalk` module path expected by the
  helper;
- `RtcClient.output_video_fps == AvatarMusetalk.fps`;
- the avatar source video exists inside a mounted path;
- the S3FD host directory is a directory containing the expected checkpoint;
- `/dev/shm` is large enough for the measured workload.

The Compose file sets 2 GB shared memory; the standalone helper does not set an
explicit `--shm-size`. Add a measured value when required.

### 7.5 Beta agent image caveat

The current Dockerfile does not copy the agent handler's dependency manifest
before `install.py --all`, so `mcp` is not installed by that layer. Do not claim
the beta agent preset is supported by the stock image.

## 8. Docker Compose and TURN

### 8.1 Current Compose state

This command validates only Compose syntax and interpolation:

```bash
docker compose config --no-interpolate
```

It does not validate host bind sources, certificate/key matching, coturn option
syntax, TURN credentials, relay reachability, or browser ICE behavior.

The reviewed checkout is not start-ready because these bind sources are
missing:

```text
.env
ssl_certs/localhost.crt
ssl_certs/localhost.key
models/musetalk/s3fd-619a316812/
```

The S3FD mount is unconditional even for non-MuseTalk presets.

### 8.2 Mandatory corrections before Compose use

1. Pin `coturn/coturn` to an approved version or digest.
2. Replace `user=admin:admin`.
3. Replace the example realm with the deployed TURN hostname.
4. Change `min-port:49152` and `max-port:65535` to coturn assignment syntax
   (`min-port=...`, `max-port=...`) and validate with the selected coturn image.
5. Mount the private key, not the certificate, at `/etc/turn_key.pem`.
6. Mount certificate/key/config read-only.
7. Add quotas, monitoring, and an intentionally bounded UDP relay range.
8. Review/remove `allowed-peer-ip=0.0.0.0`; do not assume it is a safe general
   production policy.
9. Add health checks.
10. Add a TURN configuration to the selected application's `RtcClient`.
11. Remove or make conditional the unrelated MuseTalk cache mount.
12. Put the app behind authenticated ingress; do not expose it directly.

The corrected key mount is conceptually:

```yaml
volumes:
  - ./coturn-data/turnserver.conf:/etc/coturn/turnserver.conf:ro
  - ./ssl_certs/turn-fullchain.pem:/etc/turn_cert.pem:ro
  - ./ssl_certs/turn-privkey.pem:/etc/turn_key.pem:ro
```

### 8.3 Connect the application to TURN

Running a TURN container is not enough. Add a deployment-rendered block under
the enabled RTC client:

```yaml
default:
  chat_engine:
    handler_configs:
      RtcClient:
        module: client/rtc_client/client_handler_rtc
        connection_ttl: 900
        turn_config:
          turn_provider: turn_server
          urls:
            - "turn:turn.example.com:3478?transport=udp"
            - "turn:turn.example.com:3478?transport=tcp"
            - "turns:turn.example.com:5349?transport=tcp"
          username: "<deployment-generated-user>"
          credential: "<deployment-generated-secret>"
```

Static TURN credentials are sent to the browser by design and become client
visible. Use short-lived credentials from a managed/dynamic provider when
possible. The current static provider does not mint ephemeral TURN REST
credentials.

The RTC provider currently logs this block, including the credential, at INFO.
Do not regard a static secret as protected until that logging is remediated.

### 8.4 TURN firewall

Use the smallest relay range that measured concurrency requires and make coturn
match it exactly.

| Protocol | Port/range | Purpose |
|---|---:|---|
| UDP | 3478 | TURN primary transport |
| TCP | 3478 | TURN fallback |
| TCP/TLS | 5349 | TURN over TLS fallback |
| UDP | configured bounded relay range | Allocated relay media |

RFC 8656 defines conventional 3478/5349 behavior and recommends the dynamic
range 49152–65535, but a smaller deliberate range can reduce exposure when
sized and monitored correctly. See
[RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656.html), which obsoletes
RFC 5766 and RFC 6156.

Also configure:

- correct `external-ip`/relay address for NAT;
- security-group and host firewall symmetry;
- no accidental private/container address in public ICE candidates;
- allocation/bandwidth quotas;
- credential rotation/revocation;
- source/allocation logging without secret logging;
- alerts for allocation, bandwidth, authentication failure, and port
  exhaustion.

Use the
[coturn configuration reference](https://github.com/coturn/coturn/blob/master/README.turnserver)
for the exact selected version. Avoid `server-relay` and development-only peer
relaxations.

### 8.5 External acceptance test

A loopback browser does not validate TURN. Test from a separate Internet
connection:

1. open the trusted HTTPS application URL;
2. grant camera/microphone permission;
3. start a conversation;
4. inspect `chrome://webrtc-internals` or the equivalent browser diagnostics;
5. verify a `relay` ICE candidate is selected when relay is forced/required;
6. test UDP, TCP, and TLS fallback policies separately;
7. stop coturn and verify an external TURN probe or TURN-specific alert fires;
   the built-in application `/readiness` endpoint is expected to remain `200`
   because it does not check TURN;
8. confirm credentials rotate and old credentials expire.

## 9. TLS

### 9.1 Preferred public design

Terminate a publicly trusted certificate at a reverse proxy or ingress on
TCP 443. Keep OpenAvatarChat on loopback/private networking over HTTP.
In the deployment copy of the application config, omit or set
`service.cert_file` and `service.cert_key` to `null` so internal plaintext is a
deliberate choice rather than a missing-file fallback.

The proxy must support:

- HTTP and WebSocket upgrade;
- long-lived signalling connections;
- disabled or carefully tuned response buffering for streaming;
- sufficiently long idle/read timeouts;
- authenticated access before signalling/session creation;
- rate and concurrent-session limits;
- trusted `Host` and WebSocket `Origin` validation;
- CSRF-safe cookie/token handling for HTTP and WebSocket session creation;
- correct forwarding headers;
- access-log redaction for tokens/query strings;
- all FastRTC and Manager paths, if Manager is deliberately exposed.

Because WebRTC media itself can be peer/relay traffic, the reverse proxy does
not replace TURN.

### 9.2 Direct Uvicorn TLS

If the application terminates TLS, set both:

```yaml
service:
  cert_file: "/etc/openavatarchat/tls/fullchain.pem"
  cert_key: "/etc/openavatarchat/tls/privkey.pem"
```

The current implementation silently starts plaintext when either path is
missing. Treat these log lines as deployment failures:

```text
Cert file ... not found
Key file ... not found
```

Require the positive line:

```text
SSL enabled.
```

### 9.3 Certificate preflight

```bash
openssl x509 -in fullchain.pem -noout -subject -issuer -dates
openssl x509 -in fullchain.pem -noout -ext subjectAltName
openssl pkey -in privkey.pem -check -noout
```

Compare the public keys:

```bash
openssl x509 -in fullchain.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  sha256sum

openssl pkey -in privkey.pem -pubout -outform DER |
  sha256sum
```

The two hashes must match.

`scripts/create_ssl_certs.sh` creates an interactive, one-year, self-signed
localhost certificate. It does not explicitly configure SANs. Reserve it for
development; use an internal/public CA certificate with the real hostname for
LAN/public deployment.

## 10. Public production topology

```text
Internet browser
      |
      | HTTPS / WSS :443
      v
Authenticated reverse proxy
      |
      | private HTTP :8282
      v
Single OpenAvatarChat process ----> approved cloud APIs/models
      |
      | ICE configuration
      v
Hardened TURN host
  :3478 UDP/TCP
  :5349 TLS
  bounded UDP relay range
```

Required production gates:

- application port reachable only from ingress/administration networks;
- server-side authentication before UI/signalling/Manager;
- per-user and global session quotas;
- non-root application container/user;
- immutable image digest and dependency/model manifests;
- selected handler runtime assets verified inside the final image;
- positive readiness evidence independent of the process exit code;
- model pickle risk removed or isolated;
- bounded event-loop-safe RTC queues;
- trusted TLS and explicit fail-closed verification;
- hardened TURN with non-public credentials;
- Manager disabled or separately authorized;
- transcript/log/media retention policy;
- active-session shutdown test;
- prerequisite-aware readiness;
- load test at intended sessions, media resolution, FPS, and network loss;
- rollback rehearsed with compatible config/model assets.

Until these gates are met, classify the deployment as a controlled demo, not a
production service.

## 11. Post-start acceptance checklist

### Process

- `/version` returns the expected application version.
- `/liveness` and `/readiness` return 200.
- logs contain every expected `Registered handler` and `Handler ... loaded`.
- logs contain no missing cert/key/model/API warnings.
- process runs as the intended UID with expected mounts only.
- deployment automation requires positive readiness; exit code `0` alone is
  rejected.

### GPU/media

- `nvidia-smi` shows the expected process and GPU.
- one session produces microphone input, ASR text, response text, audio, and
  avatar video.
- audio/video remains synchronized for at least the configured connection TTL
  sample window.
- manual and semantic interruption work for duplex presets.
- a slow/disconnected client does not cause unbounded memory growth. This is a
  required test because the current implementation has no queue bounds.

### Network/security

- direct access to `8282`/`8283` is blocked from untrusted networks.
- unauthenticated ingress is rejected.
- WebSocket upgrade works through the proxy.
- HTTPS certificate chain and hostname validate without bypass.
- Manager endpoints are absent or authorization-protected.
- TURN relay candidates work from an external restrictive network.
- checked-in/default TURN credentials are rejected.

### Persistence/operations

- logs go to the intended protected sink and do not contain secrets.
- write paths are bounded and monitored.
- restart loses only documented in-memory session state.
- model/config/image digests are recorded.
- rollback artifact is available and tested.

See [Operations and validation](operations-validation.md) for ongoing runbook
detail.
