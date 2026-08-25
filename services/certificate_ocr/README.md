# Certificate OCR sidecar

This package is the isolated Milestone 6A CPU OCR runtime. It has no TCP
listener and accepts one bounded request per private Unix-domain socket
connection. It never receives session capabilities, access tokens, principals,
or filesystem paths to captured images.

Production readiness is deliberately fail-closed. The service starts only when:

- `model_manifest.json` declares `qualification_status: "qualified"`;
- the complete `InferenceIdentityV1` is present and matches the runtime;
- `device` is exactly `cpu`, `engine` is exactly `paddle_static`, and HPI,
  automatic selection, fallback, and all GPU/CUDA permissions are disabled;
- every local PP-OCRv6 medium artifact and the qualification record matches its
  SHA-256;
- installed CPU package content and the direct-dependency wheel hashes match
  the frozen `uv.lock`;
- detector and recognizer directory digests match their
  `InferenceIdentityV1` executable-artifact hashes, and model
  source/configuration plus dictionary hashes name verified manifest
  artifacts;
- the fixed thread environment matches the identity;
- the pre-provisioned warmup fixture succeeds.

No production manifest or model is committed. Provision them into the
read-only model directory after qualification. Missing artifacts mean `OCR
unavailable`; the service never downloads models or switches backends.

Preprocessing is intentionally limited to the pinned OpenCV in-memory JPEG
decode, M4B-consistent EXIF orientation, exact canonical-dimension and
1920x1080 pixel-bound checks, and the BGR array expected by PaddleOCR. The
sidecar performs no dewarp, restoration, sharpening, super-resolution, disk
write, debug rendering, or application-owned resize; any engine-internal
resize is part of the hashed pipeline configuration.

The committed timeout and thread examples are scaffolding, not qualification
results. Run `certificate-ocr-qualify` in the isolated environment for each
candidate and valid thread count, then freeze a reviewed qualification record
and exact identity before enabling the sidecar. The production decision record
is strict `oac.ocr-qualification-record.v1` JSON and binds the selected
identity, backend, PP-OCRv6 medium model, fixed thread count, benchmark
environment, candidate-result hashes, and whether representative realtime
impact was measured. It does not turn raw engine scores into calibrated
probabilities.

This checkout cannot yet build the production image because no approved
sidecar `uv.lock`, model artifacts, qualification results, or selected identity
exist. Those inputs must come from an actual isolated CPU qualification; they
must not be synthesized from this example.

Deployment must use `network_mode: none`, a read-only root filesystem, a
read-only model mount, bounded tmpfs, no published port, and the shared private
UDS volume shown in the root Compose file. The owning process must configure
its `OcrSocketPolicyV1` for the deployed sidecar UID/GID (the committed image
uses `10001:10001`) and reject any socket path, mode, or `SO_PEERCRED`
mismatch. The sidecar independently checks the connecting process
`SO_PEERCRED` against `OCR_EXPECTED_CLIENT_UID` and
`OCR_EXPECTED_CLIENT_GID` before reading a request; the Compose defaults match
the current root-owned main container and must be changed together if that
container user changes.

The `certificate-ocr` Compose profile first runs a networkless, read-only-root
one-shot initializer with only `CHOWN` and `FOWNER` on the
private UDS volume. This is required because the main container may create the
named volume before the non-root sidecar starts. The initializer sets the
runtime directory to `10001:10001` and mode `0750`, exits, and only then may the
sidecar start; the OCR process itself remains `10001:10001` with all
capabilities dropped.

The main process composes OCR only when
`OPENAVATAR_CERTIFICATE_OCR_DEPLOYMENT_MANIFEST` names an absolute, bounded,
non-group/world-writable local JSON file (or an internal deployment layer
preloads the equivalent immutable object on the application state). The strict
`oac.certificate-ocr-deployment.v1` object contains only the expected complete
`InferenceIdentityV1`, qualification-record SHA-256, UDS path/UID/GID/mode,
and fixed connect/write/processing/read timeouts. It contains no capability,
token, image path, or OCR text. The processing timeout must match sidecar
readiness exactly; the owning M3 root fence is derived from the full reviewed
transport and best-effort cancellation budget. Missing, malformed, conflicting,
non-CPU, or unhealthy deployment configuration leaves OCR unavailable while
normal OpenAvatarChat remains operational.
