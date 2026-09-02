#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

readonly SCRIPT_NAME="${0##*/}"
readonly PROJECT_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1
    pwd -P
)"
readonly AVATAR_ARCHIVE="${PROJECT_ROOT}/src/handlers/avatar/liteavatar/algo/liteavatar/data/sample_data.zip"
readonly AVATAR_ROOT="/var/lib/openavatarchat/liteavatar"
readonly AVATAR_DATA_DIR="${AVATAR_ROOT}/preload"
readonly OCR_PROJECT="${PROJECT_ROOT}/services/admission_notice_ocr"
readonly OCR_SOCKET_DIR="/run/openavatarchat-admission-lite"
readonly OCR_SOCKET="${OCR_SOCKET_DIR}/ocr.sock"
readonly OCR_UNIT_NAME="openavatarchat-admission-lite-ocr.service"
readonly OCR_UNIT_PATH="/etc/systemd/system/${OCR_UNIT_NAME}"
readonly UNIT_MARKER="# Managed by ${SCRIPT_NAME}"

TARGET_USER=""
TARGET_GROUP=""
TARGET_HOME=""
TARGET_PATH=""
UV_BIN=""
temporary_env_file=""
temporary_unit_file=""
temporary_tls_dir=""
temporary_avatar_dir=""

usage() {
    cat <<EOF
Usage:
  sudo bash scripts/${SCRIPT_NAME}

Optional environment:
  OPENAVATAR_TARGET_USER   Normal user who will run OpenAvatarChat.
                           Defaults to SUDO_USER, then the repository owner.
  DASHSCOPE_API_KEY        Stored in the ignored project .env with mode 0600.
                           If absent and .env has no key, the script prompts
                           securely on /dev/tty.

This prepares LiteAvatar, CosyVoice, SenseVoice, local TLS, and the qualified
Admission Notice OCR sidecar. It does not select or modify an application
runtime preset.
EOF
}

log() {
    printf '[setup] %s\n' "$*"
}

die() {
    printf '[setup] ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "${temporary_env_file}" && -e "${temporary_env_file}" ]]; then
        rm -f -- "${temporary_env_file}"
    fi
    if [[ -n "${temporary_unit_file}" && -e "${temporary_unit_file}" ]]; then
        rm -f -- "${temporary_unit_file}"
    fi
    if [[ -n "${temporary_tls_dir}" && -d "${temporary_tls_dir}" ]]; then
        case "${temporary_tls_dir}" in
            /tmp/openavatarchat-tls.*)
                rm -rf -- "${temporary_tls_dir}"
                ;;
        esac
    fi
    if [[ -n "${temporary_avatar_dir}" && -d "${temporary_avatar_dir}" ]]; then
        case "${temporary_avatar_dir}" in
            "${AVATAR_ROOT}"/.setup.*)
                rm -rf -- "${temporary_avatar_dir}"
                ;;
        esac
    fi
}

trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

resolve_target_identity() {
    if [[ -n "${OPENAVATAR_TARGET_USER:-}" ]]; then
        TARGET_USER="${OPENAVATAR_TARGET_USER}"
    elif [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        TARGET_USER="${SUDO_USER}"
    else
        TARGET_USER="$(stat -c '%U' "${PROJECT_ROOT}")"
    fi

    [[ "${TARGET_USER}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] \
        || die "invalid target user: ${TARGET_USER}"
    [[ "${TARGET_USER}" != "root" ]] \
        || die "set OPENAVATAR_TARGET_USER to the normal service user"
    id "${TARGET_USER}" >/dev/null 2>&1 \
        || die "target user does not exist: ${TARGET_USER}"

    TARGET_GROUP="$(id -gn "${TARGET_USER}")"
    [[ "${TARGET_GROUP}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] \
        || die "invalid target group: ${TARGET_GROUP}"
    TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
    [[ -n "${TARGET_HOME}" && -d "${TARGET_HOME}" ]] \
        || die "target user has no usable home directory"
    TARGET_PATH="${TARGET_HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"

    UV_BIN="$(
        runuser -u "${TARGET_USER}" -- \
            env -i HOME="${TARGET_HOME}" PATH="${TARGET_PATH}" \
            sh -c 'command -v uv'
    )"
    [[ -n "${UV_BIN}" && -x "${UV_BIN}" ]] \
        || die "uv is not installed for ${TARGET_USER}"
    [[ "$(stat -c '%U' "${PROJECT_ROOT}")" == "${TARGET_USER}" ]] \
        || die "repository must be owned by ${TARGET_USER}: ${PROJECT_ROOT}"
}

run_as_target() {
    runuser -u "${TARGET_USER}" -- \
        env -i \
        HOME="${TARGET_HOME}" \
        USER="${TARGET_USER}" \
        LOGNAME="${TARGET_USER}" \
        PATH="${TARGET_PATH}" \
        "$@"
}

write_dashscope_env() {
    local env_file="${PROJECT_ROOT}/.env"
    local have_existing_key=false
    local key_count=0
    local key_value="${DASHSCOPE_API_KEY:-}"
    local replaced=false
    local line=""

    if [[ -e "${env_file}" || -L "${env_file}" ]]; then
        [[ -f "${env_file}" && ! -L "${env_file}" ]] \
            || die "refusing unsafe .env path: ${env_file}"
        grep -Eq '^export[[:space:]]+DASHSCOPE_API_KEY=' "${env_file}" \
            && die "normalize exported DASHSCOPE_API_KEY to a bare .env assignment"
        key_count="$(grep -Ec '^DASHSCOPE_API_KEY=' "${env_file}" || true)"
        [[ "${key_count}" -le 1 ]] \
            || die ".env contains duplicate DASHSCOPE_API_KEY assignments"
        if [[ "${key_count}" -eq 1 ]]; then
            grep -Eq '^DASHSCOPE_API_KEY=[^[:space:]]+$' "${env_file}" \
                || die ".env contains an empty or whitespace-bearing API key"
            have_existing_key=true
        fi
    fi

    if [[ -z "${key_value}" && "${have_existing_key}" == false ]]; then
        [[ -r /dev/tty ]] \
            || die "set DASHSCOPE_API_KEY for non-interactive setup"
        read -r -s -p "DASHSCOPE_API_KEY: " key_value </dev/tty
        printf '\n' >/dev/tty
        [[ -n "${key_value}" ]] || die "DASHSCOPE_API_KEY cannot be empty"
    fi
    if [[ -n "${key_value}" && "${key_value}" =~ [[:space:]] ]]; then
        die "DASHSCOPE_API_KEY must not contain whitespace or line breaks"
    fi

    if [[ -n "${key_value}" ]]; then
        temporary_env_file="$(mktemp "${PROJECT_ROOT}/.env.setup.XXXXXX")"
        chmod 0600 "${temporary_env_file}"
        if [[ -f "${env_file}" ]]; then
            while IFS= read -r line || [[ -n "${line}" ]]; do
                if [[ "${line}" == DASHSCOPE_API_KEY=* ]]; then
                    if [[ "${replaced}" == false ]]; then
                        printf 'DASHSCOPE_API_KEY=%s\n' "${key_value}" \
                            >>"${temporary_env_file}"
                        replaced=true
                    fi
                else
                    printf '%s\n' "${line}" >>"${temporary_env_file}"
                fi
            done <"${env_file}"
        fi
        if [[ "${replaced}" == false ]]; then
            printf 'DASHSCOPE_API_KEY=%s\n' "${key_value}" \
                >>"${temporary_env_file}"
        fi
        chown "${TARGET_USER}:${TARGET_GROUP}" "${temporary_env_file}"
        mv -f -- "${temporary_env_file}" "${env_file}"
        temporary_env_file=""
    fi

    [[ "$(stat -c '%U:%G' "${env_file}")" == "${TARGET_USER}:${TARGET_GROUP}" ]] \
        || die ".env must be owned by ${TARGET_USER}:${TARGET_GROUP}"
    run_as_target /usr/bin/chmod 0600 "${env_file}"
    unset key_value DASHSCOPE_API_KEY
}

prepare_submodules_and_dependencies() {
    local -a submodules=(
        "src/handlers/avatar/liteavatar/algo/liteavatar"
    )

    log "initializing LiteAvatar host submodules"
    run_as_target /usr/bin/git -C "${PROJECT_ROOT}" submodule update \
        --init --depth 1 -- "${submodules[@]}"

    log "installing LiteAvatar, SenseVoice, and CosyVoice dependencies"
    (
        cd "${PROJECT_ROOT}"
        run_as_target "${UV_BIN}" run --frozen install.py \
            --handler avatar/liteavatar \
            --handler asr/sensevoice \
            --handler tts/bailian_tts
    )

    log "downloading only LiteAvatar model weights"
    (
        cd "${PROJECT_ROOT}"
        run_as_target "${UV_BIN}" run --frozen scripts/download_models.py \
            --handler liteavatar
    )
    validate_liteavatar_weights \
        || die "LiteAvatar model weights are incomplete after provisioning"
}

validate_liteavatar_weights() {
    local weights="${PROJECT_ROOT}/src/handlers/avatar/liteavatar/algo/liteavatar/weights"
    local speech="${weights}/speech_paraformer-large_asr_nat-zh-cn-16k-common-vocab8404-pytorch"

    [[ -s "${weights}/model_1.onnx" ]] || return 1
    [[ -s "${speech}/model.pb" ]] || return 1
    [[ -s "${speech}/lm/lm.pb" ]] || return 1
}

prepare_sensevoice_model() {
    local model_dir="${PROJECT_ROOT}/models/iic/SenseVoiceSmall"

    if [[ -s "${model_dir}/model.pt" && -s "${model_dir}/config.yaml" ]]; then
        log "SenseVoiceSmall model already present"
        return
    fi

    log "downloading the SenseVoiceSmall ASR model"
    run_as_target /usr/bin/mkdir -p -- "${model_dir}"
    (
        cd "${PROJECT_ROOT}"
        run_as_target "${PROJECT_ROOT}/.venv/bin/modelscope" download \
            --model iic/SenseVoiceSmall \
            --local_dir "${model_dir}"
    )
    [[ -s "${model_dir}/model.pt" && -s "${model_dir}/config.yaml" ]] \
        || die "SenseVoiceSmall model provisioning failed"
}

validate_avatar_data() {
    local data_dir="$1"
    [[ -s "${data_dir}/bg_video.mp4" ]] || return 1
    [[ -s "${data_dir}/net.pth" ]] || return 1
    [[ -s "${data_dir}/net_decode.pt" ]] || return 1
    [[ -s "${data_dir}/net_encode.pt" ]] || return 1
    [[ -s "${data_dir}/neutral_pose.npy" ]] || return 1
    find "${data_dir}/ref_frames" -maxdepth 1 -type f -name '*.jpg' \
        -print -quit 2>/dev/null | grep -q .
}

prepare_avatar_data() {
    local staging_dir=""
    local state_root="/var/lib/openavatarchat"

    [[ -f "${AVATAR_ARCHIVE}" && ! -L "${AVATAR_ARCHIVE}" && -s "${AVATAR_ARCHIVE}" ]] \
        || die "bundled LiteAvatar archive is missing: ${AVATAR_ARCHIVE}"
    if [[ -e "${state_root}" || -L "${state_root}" ]]; then
        [[ -d "${state_root}" && ! -L "${state_root}" ]] \
            || die "refusing unsafe state directory: ${state_root}"
    fi
    install -d -o root -g root -m 0755 "${state_root}"
    if [[ -e "${AVATAR_ROOT}" || -L "${AVATAR_ROOT}" ]]; then
        [[ -d "${AVATAR_ROOT}" && ! -L "${AVATAR_ROOT}" ]] \
            || die "refusing unsafe avatar root: ${AVATAR_ROOT}"
    fi
    install -d -o root -g "${TARGET_GROUP}" -m 0750 \
        "${AVATAR_ROOT}"

    if [[ -e "${AVATAR_DATA_DIR}" || -L "${AVATAR_DATA_DIR}" ]]; then
        [[ -d "${AVATAR_DATA_DIR}" && ! -L "${AVATAR_DATA_DIR}" ]] \
            || die "refusing unsafe avatar data path: ${AVATAR_DATA_DIR}"
        [[ "$(stat -c '%U:%G' "${AVATAR_DATA_DIR}")" == "root:${TARGET_GROUP}" ]] \
            || die "avatar data must be owned by root:${TARGET_GROUP}"
        if find "${AVATAR_DATA_DIR}" -xdev -perm /022 -print -quit \
            | grep -q .; then
            die "avatar data must not be group- or other-writable"
        fi
        validate_avatar_data "${AVATAR_DATA_DIR}" \
            || die "existing LiteAvatar data is incomplete: ${AVATAR_DATA_DIR}"
        log "stable LiteAvatar data already prepared"
        return
    fi

    staging_dir="$(mktemp -d "${AVATAR_ROOT}/.setup.XXXXXX")"
    temporary_avatar_dir="${staging_dir}"
    /usr/bin/python3 -m zipfile \
        -e "${AVATAR_ARCHIVE}" "${staging_dir}"
    validate_avatar_data "${staging_dir}/preload" \
        || die "bundled LiteAvatar archive extracted incompletely at ${staging_dir}"
    mv -- "${staging_dir}/preload" "${AVATAR_DATA_DIR}"
    rmdir -- "${staging_dir}"
    temporary_avatar_dir=""
    chown -R "root:${TARGET_GROUP}" "${AVATAR_DATA_DIR}"
    find "${AVATAR_DATA_DIR}" -xdev -type d -exec chmod 0750 {} +
    find "${AVATAR_DATA_DIR}" -xdev -type f -exec chmod 0640 {} +
    log "prepared stable LiteAvatar data at ${AVATAR_DATA_DIR}"
}

tls_certificate_is_valid() {
    local cert_file="$1"
    local key_file="$2"
    local cert_public_key=""
    local key_public_key=""
    local san=""

    [[ -f "${cert_file}" && ! -L "${cert_file}" ]] || return 1
    [[ -f "${key_file}" && ! -L "${key_file}" ]] || return 1
    openssl x509 -in "${cert_file}" -noout -checkend 86400 >/dev/null 2>&1 \
        || return 1
    openssl pkey -in "${key_file}" -noout -check >/dev/null 2>&1 \
        || return 1
    cert_public_key="$(
        openssl x509 -in "${cert_file}" -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -outform DER 2>/dev/null \
            | sha256sum \
            | cut -d' ' -f1
    )"
    key_public_key="$(
        openssl pkey -in "${key_file}" -pubout -outform DER 2>/dev/null \
            | sha256sum \
            | cut -d' ' -f1
    )"
    [[ -n "${cert_public_key}" && "${cert_public_key}" == "${key_public_key}" ]] \
        || return 1
    san="$(openssl x509 -in "${cert_file}" -noout -ext subjectAltName 2>/dev/null)" \
        || return 1
    [[ "${san}" == *"DNS:localhost"* ]] || return 1
    [[ "${san}" == *"IP Address:127.0.0.1"* ]] || return 1
}

prepare_tls_certificate() {
    local cert_dir="${PROJECT_ROOT}/ssl_certs"
    local cert_file="${cert_dir}/localhost.crt"
    local key_file="${cert_dir}/localhost.key"
    local staged_cert=""
    local staged_key=""
    local cert_exists=false
    local key_exists=false

    if [[ -e "${cert_dir}" || -L "${cert_dir}" ]]; then
        [[ -d "${cert_dir}" && ! -L "${cert_dir}" ]] \
            || die "refusing unsafe TLS directory: ${cert_dir}"
    fi
    install -d -o "${TARGET_USER}" -g "${TARGET_GROUP}" -m 0750 "${cert_dir}"
    for path in "${cert_file}" "${key_file}"; do
        if [[ -e "${path}" || -L "${path}" ]]; then
            [[ -f "${path}" && ! -L "${path}" ]] \
                || die "refusing unsafe TLS path: ${path}"
        fi
    done
    [[ -f "${cert_file}" ]] && cert_exists=true
    [[ -f "${key_file}" ]] && key_exists=true
    [[ "${cert_exists}" == "${key_exists}" ]] \
        || die "refusing to replace an incomplete existing TLS identity"

    if [[ "${cert_exists}" == true ]]; then
        tls_certificate_is_valid "${cert_file}" "${key_file}" \
            || die "refusing to replace invalid or expiring existing TLS material"
        [[ "$(stat -c '%U:%G' "${cert_file}")" == "${TARGET_USER}:${TARGET_GROUP}" ]] \
            || die "existing TLS certificate has an unexpected owner"
        [[ "$(stat -c '%U:%G' "${key_file}")" == "${TARGET_USER}:${TARGET_GROUP}" ]] \
            || die "existing TLS key has an unexpected owner"
        run_as_target /usr/bin/chmod 0644 "${cert_file}"
        run_as_target /usr/bin/chmod 0600 "${key_file}"
    else
        log "creating a local-only TLS certificate for localhost"
        temporary_tls_dir="$(
            /usr/bin/mktemp -d "/tmp/openavatarchat-tls.XXXXXX"
        )"
        staged_cert="${temporary_tls_dir}/localhost.crt"
        staged_key="${temporary_tls_dir}/localhost.key"
        /usr/bin/openssl req \
            -x509 \
            -newkey rsa:2048 \
            -sha256 \
            -nodes \
            -days 365 \
            -subj "/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            -keyout "${staged_key}" \
            -out "${staged_cert}"
        tls_certificate_is_valid "${staged_cert}" "${staged_key}" \
            || die "generated localhost TLS identity did not validate"
        install -o "${TARGET_USER}" -g "${TARGET_GROUP}" -m 0644 \
            "${staged_cert}" "${cert_file}"
        install -o "${TARGET_USER}" -g "${TARGET_GROUP}" -m 0600 \
            "${staged_key}" "${key_file}"
        rm -rf -- "${temporary_tls_dir}"
        temporary_tls_dir=""
    fi
}

prepare_ocr_environment() {
    log "creating the locked CPU-only OCR environment"
    run_as_target "${UV_BIN}" sync \
        --frozen \
        --project "${OCR_PROJECT}" \
        --no-dev \
        --python 3.11

    log "provisioning and verifying the qualified OCR models"
    run_as_target "${UV_BIN}" run \
        --frozen \
        --project "${OCR_PROJECT}" \
        --no-dev \
        python -m admission_notice_ocr.provision_models \
        --thread-count 2
    run_as_target "${UV_BIN}" run \
        --frozen \
        --project "${OCR_PROJECT}" \
        --no-dev \
        python -m admission_notice_ocr.provision_models \
        --verify-only
}

install_ocr_service() {
    [[ "${PROJECT_ROOT}" =~ ^/[A-Za-z0-9._/-]+$ ]] \
        || die "project path contains characters unsafe for a systemd unit"

    if [[ -e "${OCR_UNIT_PATH}" || -L "${OCR_UNIT_PATH}" ]]; then
        [[ -f "${OCR_UNIT_PATH}" && ! -L "${OCR_UNIT_PATH}" ]] \
            || die "refusing unsafe systemd unit path: ${OCR_UNIT_PATH}"
        grep -Fq "${UNIT_MARKER}" "${OCR_UNIT_PATH}" \
            || die "refusing to overwrite unmanaged unit: ${OCR_UNIT_PATH}"
    fi

    temporary_unit_file="$(
        mktemp "/tmp/openavatarchat-admission-lite-ocr.XXXXXX.service"
    )"
    cat >"${temporary_unit_file}" <<EOF
${UNIT_MARKER}
[Unit]
Description=OpenAvatarChat Admission Notice Lite CPU OCR
After=local-fs.target

[Service]
Type=simple
User=${TARGET_USER}
Group=${TARGET_GROUP}
WorkingDirectory=${PROJECT_ROOT}
ExecStart=${OCR_PROJECT}/.venv/bin/python -m admission_notice_ocr.app --socket-path ${OCR_SOCKET}
Restart=on-failure
RestartSec=2
RuntimeDirectory=openavatarchat-admission-lite
RuntimeDirectoryMode=0750
UMask=0007
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=${OCR_SOCKET_DIR}
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

    systemd-analyze verify "${temporary_unit_file}"
    install -o root -g root -m 0644 "${temporary_unit_file}" "${OCR_UNIT_PATH}"
    rm -f -- "${temporary_unit_file}"
    temporary_unit_file=""

    systemctl daemon-reload
    systemctl enable "${OCR_UNIT_NAME}" >/dev/null
    systemctl restart "${OCR_UNIT_NAME}"
}

verify_ocr_service() {
    local attempt=0

    log "waiting for the qualified OCR sidecar"
    for attempt in $(seq 1 90); do
        if ! systemctl is-active --quiet "${OCR_UNIT_NAME}"; then
            journalctl -u "${OCR_UNIT_NAME}" -n 50 --no-pager >&2 || true
            die "OCR sidecar exited during startup"
        fi
        if [[ -S "${OCR_SOCKET}" ]]; then
            break
        fi
        sleep 1
    done
    [[ -S "${OCR_SOCKET}" ]] || {
        journalctl -u "${OCR_UNIT_NAME}" -n 50 --no-pager >&2 || true
        die "OCR sidecar did not create ${OCR_SOCKET}"
    }

    run_as_target \
        env PYTHONPATH="${PROJECT_ROOT}/src" \
        "${PROJECT_ROOT}/.venv/bin/python" \
        -c '
from service.admission_notice_lite_ocr import (
    build_qualified_admission_notice_ocr_processor_lite_v1,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

config = AdmissionNoticeLiteFeatureConfigV1(
    enabled=True,
    ocr_socket_path="/run/openavatarchat-admission-lite/ocr.sock",
)
if build_qualified_admission_notice_ocr_processor_lite_v1(config) is None:
    raise SystemExit("qualified OCR identity check failed")
'
}

run_host_resource_preflight() {
    local weights="${PROJECT_ROOT}/src/handlers/avatar/liteavatar/algo/liteavatar/weights"
    local speech="${weights}/speech_paraformer-large_asr_nat-zh-cn-16k-common-vocab8404-pytorch"
    local -a readable_paths=(
        "${weights}/model_1.onnx"
        "${speech}/model.pb"
        "${speech}/lm/lm.pb"
        "${AVATAR_DATA_DIR}/bg_video.mp4"
        "${AVATAR_DATA_DIR}/net.pth"
        "${AVATAR_DATA_DIR}/net_decode.pt"
        "${AVATAR_DATA_DIR}/net_encode.pt"
        "${AVATAR_DATA_DIR}/neutral_pose.npy"
        "${PROJECT_ROOT}/ssl_certs/localhost.crt"
        "${PROJECT_ROOT}/ssl_certs/localhost.key"
        "${PROJECT_ROOT}/models/iic/SenseVoiceSmall/model.pt"
    )
    local path=""
    local reference_frame=""

    log "running the host-resource preflight"
    validate_liteavatar_weights \
        || die "LiteAvatar weights failed the final preflight"
    validate_avatar_data "${AVATAR_DATA_DIR}" \
        || die "LiteAvatar data failed the final preflight"
    tls_certificate_is_valid \
        "${PROJECT_ROOT}/ssl_certs/localhost.crt" \
        "${PROJECT_ROOT}/ssl_certs/localhost.key" \
        || die "localhost TLS identity failed the final preflight"
    [[ -s "${PROJECT_ROOT}/models/iic/SenseVoiceSmall/model.pt" ]] \
        || die "SenseVoiceSmall model failed the final preflight"
    run_as_target /usr/bin/test -x "${AVATAR_DATA_DIR}" \
        || die "LiteAvatar data is not traversable by ${TARGET_USER}"
    run_as_target /usr/bin/test -x "${AVATAR_DATA_DIR}/ref_frames" \
        || die "LiteAvatar reference frames are not traversable by ${TARGET_USER}"
    while IFS= read -r -d '' path; do
        reference_frame="${path}"
        break
    done < <(
        find "${AVATAR_DATA_DIR}/ref_frames" -maxdepth 1 -type f -name '*.jpg' \
            -print0
    )
    [[ -n "${reference_frame}" ]] \
        || die "LiteAvatar reference frames failed the final preflight"
    run_as_target /usr/bin/test -r "${reference_frame}" \
        || die "LiteAvatar reference frame is not readable by ${TARGET_USER}"
    for path in "${readable_paths[@]}"; do
        run_as_target /usr/bin/test -r "${path}" \
            || die "host resource is not readable by ${TARGET_USER}: ${path}"
    done
}

main() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        usage
        return
    fi
    [[ "$#" -eq 0 ]] || die "unknown argument: $1"
    [[ "${EUID}" -eq 0 ]] \
        || die "run this one-time provisioner as root with sudo"

    umask 0077
    require_command cut
    require_command find
    require_command getent
    require_command git
    require_command grep
    require_command install
    require_command journalctl
    require_command mktemp
    require_command openssl
    [[ -x /usr/bin/python3 ]] || die "required command not found: /usr/bin/python3"
    [[ -x /usr/bin/test ]] || die "required command not found: /usr/bin/test"
    require_command runuser
    require_command seq
    require_command stat
    require_command systemctl
    require_command systemd-analyze
    require_command sha256sum

    resolve_target_identity
    write_dashscope_env
    prepare_submodules_and_dependencies
    prepare_sensevoice_model
    prepare_avatar_data
    prepare_tls_certificate
    prepare_ocr_environment
    install_ocr_service
    verify_ocr_service
    run_host_resource_preflight

    log "host preparation complete for ${TARGET_USER}"
    printf '\nSelect and validate the application runtime configuration separately.\n'
}

main "$@"
