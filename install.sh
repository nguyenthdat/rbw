#!/bin/sh
# Standalone installer for rbw (https://github.com/nguyenthdat/rbw)
#
# Usage:
#   curl -LsSf https://github.com/nguyenthdat/rbw/releases/latest/download/install.sh | sh
#   curl -LsSf https://github.com/nguyenthdat/rbw/releases/latest/download/install.sh | sh -s -- --version 1.16.1
#
# Environment variables:
#   RBW_VERSION                   Release version/tag to install (default: latest)
#   RBW_INSTALL_DIR               Installation directory (default: ~/.local/bin)
#   RBW_NO_MODIFY_PATH            Set to 1 to skip updating shell profile PATH
#   RBW_INSTALL_QUIET             Set to 1 to suppress informational output
#   RBW_INSTALL_LIBC              Force Linux libc flavor: gnu or musl
#   RBW_INSTALL_TARGET            Override target triple explicitly
#   RBW_INSTALL_REPO              GitHub repository (default: nguyenthdat/rbw)
#   RBW_INSTALL_GITHUB_BASE_URL   GitHub base URL (default: https://github.com)

set -u

# Stamped automatically by .github/workflows/release.yaml when attached to a release.
RBW_RELEASE_VERSION=""

APP_NAME="rbw"
DEFAULT_REPO="nguyenthdat/rbw"
DEFAULT_GITHUB_BASE="https://github.com"
MIN_GLIBC_MAJOR=2
MIN_GLIBC_MINOR=39

QUIET="${RBW_INSTALL_QUIET:-0}"
NO_MODIFY_PATH="${RBW_NO_MODIFY_PATH:-0}"
OPT_VERSION=""
OPT_INSTALL_DIR=""
TMP_DIR=""

usage() {
    cat <<'EOF'
rbw installer

USAGE:
    install.sh [OPTIONS]

OPTIONS:
    -v, --version <VERSION>      Install a specific version (e.g. 1.16.1 or v1.16.1)
    -d, --install-dir <DIR>      Install binaries into DIR (default: ~/.local/bin)
        --no-modify-path         Do not modify shell profile files
    -q, --quiet                  Suppress informational output
    -h, --help                   Show this help message

ENVIRONMENT:
    RBW_VERSION                  Same as --version
    RBW_INSTALL_DIR              Same as --install-dir
    RBW_NO_MODIFY_PATH=1         Same as --no-modify-path
    RBW_INSTALL_QUIET=1          Same as --quiet
    RBW_INSTALL_LIBC=gnu|musl    Force Linux gnu or musl build
    RBW_INSTALL_TARGET=<triple>  Override detected Rust target triple
    RBW_INSTALL_REPO=<o/r>       Override GitHub repository (default: nguyenthdat/rbw)
    RBW_INSTALL_GITHUB_BASE_URL  Override GitHub base URL (default: https://github.com)
EOF
}

say() {
    if [ "${QUIET}" = "0" ] || [ "${QUIET}" = "false" ] || [ -z "${QUIET}" ]; then
        printf '%s\n' "$*" >&2
    fi
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

err() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

need_cmd() {
    if ! check_cmd "$1"; then
        err "required command '$1' not found in PATH"
    fi
}

cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}

is_loopback_http() {
    case "$1" in
        http://127.0.0.1* | http://localhost* | http://\[::1\]*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

download() {
    _url="$1"
    _out="$2"

    case "${_url}" in
        https://*)
            _secure=1
            ;;
        *)
            if is_loopback_http "${_url}"; then
                _secure=0
            else
                err "refusing insecure download URL: ${_url}"
            fi
            ;;
    esac

    if check_cmd curl; then
        if [ "${_secure}" -eq 1 ]; then
            curl --proto '=https' --tlsv1.2 -LsSf -o "${_out}" "${_url}"
        else
            curl -LsSf -o "${_out}" "${_url}"
        fi
    elif check_cmd wget; then
        if [ "${_secure}" -eq 1 ]; then
            wget --https-only --secure-protocol=TLSv1_2 -q -O "${_out}" "${_url}"
        else
            wget -q -O "${_out}" "${_url}"
        fi
    else
        err "either 'curl' or 'wget' is required to download ${APP_NAME}"
    fi
}

compute_sha256() {
    _file="$1"
    if check_cmd sha256sum; then
        sha256sum "${_file}" | awk '{print tolower($1)}'
    elif check_cmd shasum; then
        shasum -a 256 "${_file}" | awk '{print tolower($1)}'
    elif check_cmd openssl; then
        openssl dgst -sha256 "${_file}" | awk '{print tolower($NF)}'
    else
        err "no SHA-256 tool found (need sha256sum, shasum, or openssl)"
    fi
}

verify_sha256() {
    _archive="$1"
    _sha_file="$2"
    _asset_name="$3"

    _expected="$(awk -v asset="${_asset_name}" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        NF == 1 && NR == 1 { print tolower($1); exit }
        NF >= 2 {
            f = $2
            sub(/^\*/, "", f)
            sub(/^\.\//, "", f)
            sub(/^.*\//, "", f)
            if (f == asset) {
                print tolower($1)
                exit
            }
        }
    ' "${_sha_file}")"

    if [ -z "${_expected}" ] || [ "${#_expected}" -ne 64 ]; then
        err "failed to parse valid SHA-256 digest for ${_asset_name}"
    fi

    _actual="$(compute_sha256 "${_archive}")"
    if [ "${_actual}" != "${_expected}" ]; then
        err "SHA-256 mismatch for ${_asset_name}: expected ${_expected}, got ${_actual}"
    fi
}

detect_linux_libc() {
    if [ -n "${RBW_INSTALL_LIBC:-}" ]; then
        case "${RBW_INSTALL_LIBC}" in
            gnu | musl)
                printf '%s' "${RBW_INSTALL_LIBC}"
                return 0
                ;;
            *)
                err "invalid RBW_INSTALL_LIBC='${RBW_INSTALL_LIBC}' (expected 'gnu' or 'musl')"
                ;;
        esac
    fi

    if [ -f /etc/alpine-release ]; then
        printf 'musl'
        return 0
    fi

    _glibc_ver=""
    if check_cmd getconf; then
        _glibc_ver="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '/glibc/ {print $2}')"
    fi

    if [ -z "${_glibc_ver}" ] && check_cmd ldd; then
        _ldd_out="$(ldd --version 2>&1 || true)"
        case "${_ldd_out}" in
            *musl* | *MUSL*)
                printf 'musl'
                return 0
                ;;
        esac
        _glibc_ver="$(printf '%s\n' "${_ldd_out}" | head -n 1 | grep -oE '[0-9]+\.[0-9]+$' || true)"
    fi

    if [ -n "${_glibc_ver}" ]; then
        _major="${_glibc_ver%%.*}"
        _rest="${_glibc_ver#*.}"
        _minor="${_rest%%.*}"
        case "${_major}" in
            '' | *[!0-9]*) _major=0 ;;
        esac
        case "${_minor}" in
            '' | *[!0-9]*) _minor=0 ;;
        esac
        if [ "${_major}" -gt "${MIN_GLIBC_MAJOR}" ] \
            || { [ "${_major}" -eq "${MIN_GLIBC_MAJOR}" ] && [ "${_minor}" -ge "${MIN_GLIBC_MINOR}" ]; }; then
            printf 'gnu'
            return 0
        fi
    fi

    printf 'musl'
}

detect_target() {
    if [ -n "${RBW_INSTALL_TARGET:-}" ]; then
        printf '%s' "${RBW_INSTALL_TARGET}"
        return 0
    fi

    _os="$(uname -s 2>/dev/null || printf 'unknown')"
    _arch="$(uname -m 2>/dev/null || printf 'unknown')"

    case "${_os}" in
        Darwin)
            case "${_arch}" in
                arm64 | aarch64)
                    printf 'aarch64-apple-darwin'
                    ;;
                x86_64)
                    if check_cmd sysctl && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')" = "1" ]; then
                        printf 'aarch64-apple-darwin'
                    else
                        printf 'x86_64-apple-darwin'
                    fi
                    ;;
                *)
                    err "unsupported macOS architecture: ${_arch}"
                    ;;
            esac
            ;;
        Linux)
            case "${_arch}" in
                x86_64 | amd64)
                    _arch="x86_64"
                    ;;
                aarch64 | arm64)
                    _arch="aarch64"
                    ;;
                *)
                    err "unsupported Linux architecture: ${_arch} (install from source with 'cargo install --locked rbw')"
                    ;;
            esac
            _libc="$(detect_linux_libc)"
            printf '%s-unknown-linux-%s' "${_arch}" "${_libc}"
            ;;
        *)
            err "unsupported operating system: ${_os} (install from source with 'cargo install --locked rbw')"
            ;;
    esac
}

resolve_install_dir() {
    if [ -n "${OPT_INSTALL_DIR}" ]; then
        printf '%s' "${OPT_INSTALL_DIR}"
    elif [ -n "${RBW_INSTALL_DIR:-}" ]; then
        printf '%s' "${RBW_INSTALL_DIR}"
    elif [ -n "${XDG_BIN_HOME:-}" ]; then
        printf '%s' "${XDG_BIN_HOME}"
    elif [ -n "${XDG_DATA_HOME:-}" ]; then
        printf '%s' "$(dirname "${XDG_DATA_HOME}")/bin"
    elif [ -n "${HOME:-}" ]; then
        printf '%s' "${HOME}/.local/bin"
    else
        err "could not determine install directory; set RBW_INSTALL_DIR or --install-dir"
    fi
}

path_contains() {
    case ":${PATH:-}:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

display_home_path() {
    _p="$1"
    if [ -n "${HOME:-}" ]; then
        case "${_p}" in
            "${HOME}")
                # shellcheck disable=SC2016
                printf '$HOME'
                return 0
                ;;
            "${HOME}"/*)
                # shellcheck disable=SC2016
                printf '$HOME/%s' "${_p#"${HOME}"/}"
                return 0
                ;;
        esac
    fi
    printf '%s' "${_p}"
}

append_line_if_missing() {
    _file="$1"
    _line="$2"
    if [ -f "${_file}" ] && grep -Fqx "${_line}" "${_file}" 2>/dev/null; then
        return 0
    fi
    _parent="$(dirname "${_file}")"
    mkdir -p "${_parent}"
    if [ -f "${_file}" ] && [ -s "${_file}" ]; then
        # Ensure preceding newline before appending.
        printf '\n%s\n' "${_line}" >> "${_file}"
    else
        printf '%s\n' "${_line}" >> "${_file}"
    fi
}

configure_path() {
    _dir="$1"
    _env_sh="${_dir}/env"
    _disp_dir="$(display_home_path "${_dir}")"
    _disp_env="$(display_home_path "${_env_sh}")"

    cat > "${_env_sh}" <<EOF
#!/bin/sh
# add rbw binaries to PATH if not already present
case ":\${PATH}:" in
    *:"${_disp_dir}":*)
        ;;
    *)
        export PATH="${_disp_dir}:\$PATH"
        ;;
esac
EOF

    _source_line=". \"${_disp_env}\""
    _modified=""

    if [ -n "${HOME:-}" ]; then
        _shell_name="$(basename "${SHELL:-}" 2>/dev/null || printf '')"

        if [ "${_shell_name}" = "zsh" ] || [ -f "${HOME}/.zshrc" ]; then
            append_line_if_missing "${HOME}/.zshrc" "${_source_line}"
            _modified="${_modified} ${HOME}/.zshrc"
        fi

        if [ "${_shell_name}" = "bash" ] || [ -f "${HOME}/.bashrc" ]; then
            append_line_if_missing "${HOME}/.bashrc" "${_source_line}"
            _modified="${_modified} ${HOME}/.bashrc"
        fi

        if [ -f "${HOME}/.profile" ] || [ -z "${_modified}" ]; then
            append_line_if_missing "${HOME}/.profile" "${_source_line}"
            _modified="${_modified} ${HOME}/.profile"
        fi

        _fish_conf_dir="${XDG_CONFIG_HOME:-${HOME}/.config}/fish/conf.d"
        if [ "${_shell_name}" = "fish" ] || [ -d "${XDG_CONFIG_HOME:-${HOME}/.config}/fish" ]; then
            mkdir -p "${_fish_conf_dir}"
            cat > "${_fish_conf_dir}/rbw.fish" <<EOF
fish_add_path -g "${_dir}"
EOF
            _modified="${_modified} ${_fish_conf_dir}/rbw.fish"
        fi
    fi

    say ""
    say "To add ${_disp_dir} to your PATH in this shell, run:"
    say "    . \"${_disp_env}\""
    if [ -n "${_modified}" ]; then
        say "Updated shell profile(s):${_modified}"
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -v | --version)
                [ "$#" -ge 2 ] || err "missing argument for $1"
                OPT_VERSION="$2"
                shift 2
                ;;
            --version=*)
                OPT_VERSION="${1#*=}"
                shift
                ;;
            -d | --install-dir)
                [ "$#" -ge 2 ] || err "missing argument for $1"
                OPT_INSTALL_DIR="$2"
                shift 2
                ;;
            --install-dir=*)
                OPT_INSTALL_DIR="${1#*=}"
                shift
                ;;
            --no-modify-path)
                NO_MODIFY_PATH="1"
                shift
                ;;
            -q | --quiet)
                QUIET="1"
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                err "unknown argument: $1 (run with --help for usage)"
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    need_cmd tar
    need_cmd mktemp
    need_cmd uname
    need_cmd awk

    _repo="${RBW_INSTALL_REPO:-${DEFAULT_REPO}}"
    _github_base="${RBW_INSTALL_GITHUB_BASE_URL:-${DEFAULT_GITHUB_BASE}}"
    _github_base="${_github_base%/}"

    _target="$(detect_target)"
    _install_dir="$(resolve_install_dir)"

    _req_version="${OPT_VERSION:-${RBW_VERSION:-${RBW_RELEASE_VERSION}}}"
    if [ -z "${_req_version}" ] || [ "${_req_version}" = "latest" ]; then
        _base_url="${_github_base}/${_repo}/releases/latest/download"
        _version_label="latest"
    else
        case "${_req_version}" in
            v*) _tag="${_req_version}" ;;
            *) _tag="v${_req_version}" ;;
        esac
        _base_url="${_github_base}/${_repo}/releases/download/${_tag}"
        _version_label="${_tag}"
    fi

    _archive_name="${APP_NAME}-${_target}.tar.gz"
    _archive_url="${_base_url}/${_archive_name}"
    _checksum_url="${_base_url}/${_archive_name}.sha256"

    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rbw-install.XXXXXX")"
    trap cleanup EXIT INT TERM

    say "downloading ${APP_NAME} (${_version_label}) for ${_target}"
    download "${_checksum_url}" "${TMP_DIR}/${_archive_name}.sha256" \
        || err "failed to download checksum from ${_checksum_url}"
    download "${_archive_url}" "${TMP_DIR}/${_archive_name}" \
        || err "failed to download archive from ${_archive_url}"

    verify_sha256 \
        "${TMP_DIR}/${_archive_name}" \
        "${TMP_DIR}/${_archive_name}.sha256" \
        "${_archive_name}"

    mkdir -p "${TMP_DIR}/extract" || err "failed to create extraction directory"
    tar -xzf "${TMP_DIR}/${_archive_name}" -C "${TMP_DIR}/extract" \
        || err "failed to extract ${_archive_name}"

    _src_dir="${TMP_DIR}/extract/${APP_NAME}-${_target}"
    if [ ! -f "${_src_dir}/rbw" ]; then
        _src_dir="${TMP_DIR}/extract"
    fi
    [ -f "${_src_dir}/rbw" ] || err "archive did not contain 'rbw' binary"
    [ -f "${_src_dir}/rbw-agent" ] || err "archive did not contain 'rbw-agent' binary"

    mkdir -p "${_install_dir}" || err "failed to create ${_install_dir}"

    # Stop any existing rbw-agent cleanly before swapping binaries.
    if [ -x "${_install_dir}/rbw" ]; then
        "${_install_dir}/rbw" stop-agent >/dev/null 2>&1 || true
    elif check_cmd rbw; then
        rbw stop-agent >/dev/null 2>&1 || true
    fi

    # Install into temporary files in the destination directory and rename
    # atomically (avoids busy-text errors and macOS code-signature cache issues).
    _tmp_agent="${_install_dir}/.rbw-agent.install.$$"
    _tmp_rbw="${_install_dir}/.rbw.install.$$"
    cp "${_src_dir}/rbw-agent" "${_tmp_agent}" \
        || { rm -f "${_tmp_agent}" "${_tmp_rbw}"; err "failed to stage rbw-agent in ${_install_dir}"; }
    cp "${_src_dir}/rbw" "${_tmp_rbw}" \
        || { rm -f "${_tmp_agent}" "${_tmp_rbw}"; err "failed to stage rbw in ${_install_dir}"; }
    chmod 755 "${_tmp_agent}" "${_tmp_rbw}" \
        || { rm -f "${_tmp_agent}" "${_tmp_rbw}"; err "failed to set executable permissions in ${_install_dir}"; }
    mv -f "${_tmp_agent}" "${_install_dir}/rbw-agent" \
        || { rm -f "${_tmp_agent}" "${_tmp_rbw}"; err "failed to install rbw-agent to ${_install_dir}"; }
    mv -f "${_tmp_rbw}" "${_install_dir}/rbw" \
        || { rm -f "${_tmp_rbw}"; err "failed to install rbw to ${_install_dir}"; }

    _installed_ver="$("${_install_dir}/rbw" --version 2>/dev/null || printf '%s' "${APP_NAME}")"
    say "installed ${_installed_ver} to ${_install_dir}"
    say "  - ${_install_dir}/rbw"
    say "  - ${_install_dir}/rbw-agent"

    if ! path_contains "${_install_dir}"; then
        if [ "${NO_MODIFY_PATH}" = "1" ] || [ "${NO_MODIFY_PATH}" = "true" ]; then
            say ""
            say "Add ${_install_dir} to your PATH to run 'rbw' directly."
        else
            configure_path "${_install_dir}"
        fi
    fi

    if ! check_cmd pinentry && ! check_cmd pinentry-mac && ! check_cmd pinentry-curses; then
        warn "'pinentry' was not found in PATH; install pinentry (e.g. 'brew install pinentry-mac' or 'sudo apt install pinentry-curses') for master password prompts"
    fi

    say ""
    say "everything's installed! Run 'rbw self update' anytime to upgrade."
}

main "$@"
