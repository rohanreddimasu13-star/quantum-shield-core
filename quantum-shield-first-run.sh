#!/usr/bin/env bash
set -Eeuo pipefail


# QS_GRAPHICAL_PATH_PICKER_BEGIN
# Convert matching interactive path prompts into graphical Zenity selectors.
read() {
  local prompt='' arg picked='' mode='' lower_prompt='' lower_var='' joined='' complex=0
  local -a qs_read_args=("$@") qs_read_vars=() qs_picker_args=()
  local i

  for ((i=0; i<${#qs_read_args[@]}; i++)); do
    arg=${qs_read_args[i]}
    case "$arg" in
      -p)
        if (( i + 1 < ${#qs_read_args[@]} )); then
          i=$((i+1)); prompt=${qs_read_args[i]}
        fi ;;
      -rp|-pr)
        if (( i + 1 < ${#qs_read_args[@]} )); then
          i=$((i+1)); prompt=${qs_read_args[i]}
        fi ;;
      -p*) prompt=${arg#-p} ;;
      -r|-e) ;;
      -s|-E|-n|-N|-d|-t|-u|-i|-a|-A|-C|-S|-c|-k|-q|-z)
        complex=1 ;;
      -*) complex=1 ;;
      *) qs_read_vars+=("$arg") ;;
    esac
  done

  # Keep unusual reads and non-path prompts behaving normally.
  # Bracketed defaults are normal text prompts, not path-picker requests.
  if (( complex )) || [[ -z "$prompt" || "$prompt" =~ \[[^]]*\] ]] ||
     (( ${#qs_read_vars[@]} != 1 )) ||
     ! command -v zenity >/dev/null 2>&1; then
    builtin read "$@"
    return $?
  fi

  lower_prompt=${prompt,,}
  lower_var=${qs_read_vars[0],,}
  joined="$lower_prompt $lower_var"

  # Never replace interactive credentials, URLs, IDs, or menu choices.
  if [[ "$joined" =~ (https?://|website[[:space:]]+url|site[[:space:]]+url|api[[:space:]_-]*(key|token)|password|passphrase|token|secret|key[[:space:]_-]*id|yes/no|confirm|choose[[:space:]]*\\[|select[[:space:]].*(option|mode)|branch|email|username|hostname|port) ]]; then
    builtin read "$@"
    return $?
  fi

  # Explicit file selection takes priority over generic path prompts.
  if [[ "$joined" =~ (save|output|destination|export)[[:space:]_-]*(file|path|location|as|to) ]]; then
    mode=save
  elif [[ "$joined" =~ (file|filename|file_name|file-path|file_path|zip|archive|executable|binary|certificate|cert|pem|private[[:space:]_-]*key|tls[[:space:]_-]*key|config|keystore|script|input[[:space:]_-]*file|source[[:space:]_-]*file) ]]; then
    mode=file
  elif [[ "$joined" =~ (directory|directories|folder|project|repository|repo|workspace|codebase|source[[:space:]_-]*(tree|directory|folder)|app[[:space:]_-]*root|root[[:space:]_-]*directory) ]]; then
    mode=directory
  elif [[ "$joined" =~ (path|location) || "$lower_var" =~ (path|target|source|file|filename|zip|archive|executable|binary|certificate|cert|config) ]]; then
    # An ambiguous path defaults to the file chooser.
    mode=file
  elif [[ "$lower_var" =~ (directory|directories|dir|folder|workspace|project|repository|repo|root) ]]; then
    mode=directory
  else
    builtin read "$@"
    return $?
  fi

  qs_picker_args=(--file-selection --title="$prompt" --filename="$HOME/")
  case "$mode" in
    directory)
      qs_picker_args+=(--directory) ;;
    save)
      qs_picker_args+=(--save --confirm-overwrite) ;;
    file)
      if [[ "$joined" =~ zip|archive ]]; then
        qs_picker_args+=(--file-filter='Archives | *.zip *.ZIP *.tar *.tar.gz *.tgz *.7z *.rar')
      fi ;;
  esac

  if ! picked="$(zenity "${qs_picker_args[@]}" 2>/dev/null)"; then
    printf -v "${qs_read_vars[0]}" '%s' ''
    printf 'Selection cancelled. Choose a path again in the wizard.\n' >&2
    return 0
  fi

  printf -v "${qs_read_vars[0]}" '%s' "$picked"
}
# QS_GRAPHICAL_PATH_PICKER_END


ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
QSCTL="$ROOT/target/debug/qsctl"
DESKTOP="$ROOT/target/debug/qs-desktop"

usage() {
    cat <<'HELP'
Quantum Shield — first-run protection wizard

Usage:
  ./quantum-shield-first-run.sh

Choose one workflow:
  1. Quick Protect — URL, ZIP, local folder, repository or software
  2. Encrypt/decrypt a file or protect a project archive
  3. Website — HTTPS/TLS reverse proxy and traffic protections
  4. Repository — source scanning, Git history and dependency auditing
  5. Software — application auditing and Bubblewrap sandbox
  6. Check/remove project integration
  7. Exit

Direct integration commands:
  target/debug/qsctl integrate detect .
  target/debug/qsctl integrate install .
  target/debug/qsctl integrate status .
  target/debug/qsctl integrate remove .
HELP
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ ! -t 0 ]]; then
    echo "ERROR: The first-run wizard requires an interactive terminal."
    usage
    exit 2
fi

if [[ "$(id -u)" == 0 ]]; then
    echo "ERROR: Run Quantum Shield as your normal user, not root."
    exit 2
fi

if [[ ! -x "$QSCTL" ]]; then
    echo "Quantum Shield CLI has not been built yet."
    echo "Building the existing CLI..."
    cargo build --manifest-path "$ROOT/Cargo.toml" --bin qsctl
fi

confirm() {
    local answer
    read -r -p "Type YES to continue: " answer
    [[ "$answer" == "YES" ]]
}

# Discover supported path-taking CLI commands from their actual help.
# No shell eval is used; paths and arguments remain separate argv entries.
run_path_command() {
    local mode="$1"
    local target="$2"
    shift 2

    local candidate help usage option placeholder found
    local -a args

    for candidate in "$@"; do
        if ! help="$("$QSCTL" "$candidate" --help 2>&1)"; then
            continue
        fi

        usage="$(printf '%s\n' "$help" |
            grep -m1 -Ei '^[[:space:]]*Usage:' || true)"

        args=()

        if grep -Eq -- '--mode([=[:space:]]|$)' <<<"$help"; then
            args+=(--mode "$mode")
        elif [[ "$usage" == *"<MODE>"* ]]; then
            args+=("$mode")
        fi

        option=""
        for placeholder in \
            repo-path repository-path repo-root repository repo \
            root directory path; do
            if grep -Eq -- "--${placeholder}([=[:space:]]|$)" <<<"$help"; then
                option="$placeholder"
                break
            fi
        done

        if [[ -n "$option" ]]; then
            args+=("--$option" "$target")
        else
            found=0
            for placeholder in \
                "<PATH>" "<REPO>" "<REPOSITORY>" "<ROOT>" \
                "<DIRECTORY>" "<DIR>" "<REPO_PATH>"; do
                if [[ "$usage" == *"$placeholder"* ]]; then
                    args+=("$target")
                    found=1
                    break
                fi
            done
            [[ "$found" == 1 ]] || continue
        fi

        echo
        echo "Running existing command: qsctl $candidate"
        "$QSCTL" "$candidate" "${args[@]}"
        return $?
    done

    echo "No compatible CLI command was discovered from the following candidates:"
    printf '  %s\n' "$@"
    echo "Run '$QSCTL --help' or use the existing desktop workflow."
    return 127
}


# Real graphical selectors: the selected path is returned to the caller.
qs_pick_file() {
    local title="$1" start="${2:-$HOME}"
    [[ -d "$start" ]] || start="$(dirname -- "$start")"
    [[ -d "$start" ]] || start="$HOME"

    if command -v yad >/dev/null 2>&1; then
        yad --file-selection --title="$title" --filename="$start/" 2>/dev/null
    elif command -v zenity >/dev/null 2>&1; then
        zenity --file-selection --title="$title" --filename="$start/" 2>/dev/null
    elif command -v kdialog >/dev/null 2>&1; then
        kdialog --getopenfilename "$start" 2>/dev/null
    else
        echo "No GUI file chooser installed. Install yad or zenity." >&2
        return 127
    fi
}

qs_pick_directory() {
    local title="$1" start="${2:-$HOME}"
    [[ -d "$start" ]] || start="$HOME"

    if command -v yad >/dev/null 2>&1; then
        yad --file-selection --directory --title="$title" --filename="$start/" 2>/dev/null
    elif command -v zenity >/dev/null 2>&1; then
        zenity --file-selection --directory --title="$title" --filename="$start/" 2>/dev/null
    elif command -v kdialog >/dev/null 2>&1; then
        kdialog --getexistingdirectory "$start" 2>/dev/null
    else
        echo "No GUI folder chooser installed. Install yad or zenity." >&2
        return 127
    fi
}

qs_pick_output() {
    local title="$1" default="$2"
    if command -v yad >/dev/null 2>&1; then
        yad --file-selection --save --title="$title" --filename="$default" 2>/dev/null
    elif command -v zenity >/dev/null 2>&1; then
        zenity --file-selection --save --title="$title" --filename="$default" 2>/dev/null
    elif command -v kdialog >/dev/null 2>&1; then
        kdialog --getsavefilename "$default" 2>/dev/null
    else
        echo "No GUI save dialog installed. Install yad or zenity." >&2
        return 127
    fi
}

qs_choose_key() {
    local listing id default
    listing="$("$QSCTL" key-list)" || return $?
    if [[ "$listing" == *"No local encryption keys found."* || -z "$listing" ]]; then
        default="qs-local-$(date +%Y%m%d-%H%M%S)"
        read -r -p "No key exists. Create a new key ID [$default]: " id || return 1
        id="${id:-$default}"
        [[ "$id" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || {
            echo "Invalid key ID."; return 1;
        }
        "$QSCTL" key-generate "$id" || return $?
    else
        echo "Existing encryption keys:"
        printf '%s\n' "$listing"
        read -r -p "Enter an existing key ID: " id || return 1
        grep -Fxq -- "$id" <<<"$listing" || {
            echo "That key ID was not found."; return 1;
        }
    fi
    QS_SELECTED_KEY_ID="$id"
}

encryption_mode() {
    local choice input output kind operation
    echo
    echo "========== FILE & PROJECT ENCRYPTION =========="
    echo "1) Encrypt a file"
    echo "2) Decrypt an encrypted file"
    echo "3) Encrypt a repository/software project archive"
    echo "4) List encryption keys"
    echo "0) Back"
    read -r -p "Choose [0-4]: " choice || return 0

    case "$choice" in
        1|2)
            input="$(qs_pick_file "Choose file" "$HOME")" || {
                echo "Cancelled."; return 0;
            }
            input="$(realpath -e -- "$input")" || return 1
            [[ -f "$input" && ! -L "$input" ]] || {
                echo "Select a regular file, not a symbolic link."; return 1;
            }

            if [[ "$choice" == 1 ]]; then
                operation="encrypt-file"
                output="$(qs_pick_output "Save encrypted file" "$input.qse")" || {
                    echo "Cancelled."; return 0;
                }
            else
                operation="decrypt-file"
                output="$(qs_pick_output "Save decrypted file" "$input.decrypted")" || {
                    echo "Cancelled."; return 0;
                }
                echo "Decrypted output is plaintext. Store it securely."
            fi

            [[ ! -e "$output" && ! -L "$output" ]] || {
                echo "Refusing to overwrite existing output: $output"; return 1;
            }
            qs_choose_key || return $?
            echo "Input:  $input"
            echo "Output: $output"
            confirm || { echo "Cancelled."; return 0; }

            "$QSCTL" "$operation" --key-id "$QS_SELECTED_KEY_ID" \
                --input "$input" --output "$output"
            ;;
        3)
            input="$(qs_pick_directory "Choose repository or project folder" "$HOME")" || {
                echo "Cancelled."; return 0;
            }
            input="$(realpath -e -- "$input")" || return 1
            [[ -d "$input" ]] || { echo "Folder not found."; return 1; }

            echo "1) Repository snapshot"
            echo "2) Application/software snapshot"
            read -r -p "Choose [1-2]: " kind || return 0
            case "$kind" in
                1) kind=repository ;;
                2) kind=application ;;
                *) echo "Cancelled."; return 0 ;;
            esac

            output="$(qs_pick_output "Save encrypted project archive" \
                "$(dirname -- "$input")/$(basename -- "$input").qse")" || {
                echo "Cancelled."; return 0;
            }
            [[ ! -e "$output" && ! -L "$output" ]] || {
                echo "Refusing to overwrite existing output: $output"; return 1;
            }
            qs_choose_key || return $?
            echo "Project: $input"
            echo "Output:  $output"
            echo "Original project files will be preserved."
            confirm || { echo "Cancelled."; return 0; }
            "$QSCTL" protect --kind "$kind" --path "$input" \
                --key-id "$QS_SELECTED_KEY_ID" --output "$output"
            ;;
        4) "$QSCTL" key-list ;;
        0) return 0 ;;
        *) echo "Invalid choice."; return 2 ;;
    esac
}


qs_choose_file_gui() {
    zenity --file-selection --title="${1:-Choose a file}" \
        --filename="${2:-$HOME}/" 2>/dev/null
}

qs_choose_folder_gui() {
    zenity --file-selection --directory --title="${1:-Choose a folder}" \
        --filename="${2:-$HOME}/" 2>/dev/null
}

qs_choose_output_gui() {
    zenity --file-selection --save --title="${1:-Save output}" \
        --filename="${2:-$HOME/output.qse}" 2>/dev/null
}

integration_mode() {
    local choice target archive destination answer
    local -a dirs=() files=()

    echo
    echo "========== QUANTUM SHIELD QUICK PROTECT =========="
    echo "1) Website URL — passive security assessment"
    echo "2) Local project folder — detect and integrate shields"
    echo "3) Website/app ZIP — extract and integrate locally"
    echo "4) Repository — security scan"
    echo "5) Linux software — audit and sandbox workflow"
    echo "6) Files/project folder — read-only application audit"
    echo "0) Back"
    read -r -p "Choose [0-6]: " choice || return 0

    case "$choice" in
        1)
            read -r -p "Website URL: " target || return 1
            [[ -n "$target" ]] || { echo "URL required."; return 1; }
            echo "PASSIVE ASSESSMENT ONLY: this does not change remote hosting or routing."
            "$QSCTL" website-audit "$target"
            ;;
        2|3)
            if [[ "$choice" == 2 ]]; then
                target="$(qs_choose_folder_gui "Choose project folder" "$PWD")" || { echo "Cancelled."; return 0; }
                [[ -d "$target" ]] || { echo "Folder not found."; return 1; }
            else
                command -v python3 >/dev/null || {
                    echo "Python 3 required for ZIP import."; return 1;
                }
                archive="$(qs_choose_file_gui "Choose project ZIP" "$HOME")" || { echo "Cancelled."; return 0; }
                [[ -f "$archive" ]] || { echo "ZIP not found."; return 1; }
                archive="$(realpath -e -- "$archive")"
                destination="$PWD/$(basename -- "${archive%.*}")-quantum-shield"
                [[ ! -e "$destination" && ! -L "$destination" ]] || {
                    echo "Destination already exists: $destination"
                    echo "Nothing overwritten; choose another working directory."
                    return 1
                }

                python3 - "$archive" "$destination" <<'PYZIP'
import shutil, stat, sys, zipfile
from pathlib import Path, PurePosixPath

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
if dst.exists() or dst.is_symlink():
    raise SystemExit("Destination already exists.")
try:
    with zipfile.ZipFile(src) as z:
        entries = z.infolist()
        if len(entries) > 20000:
            raise ValueError("Too many ZIP entries (limit 20,000).")
        total, seen = 0, set()
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            path = PurePosixPath(name)
            if not name or name.startswith("/") or path.is_absolute() or \
               any(part in ("..", "") for part in path.parts) or \
               (path.parts and ":" in path.parts[0]):
                raise ValueError(f"Unsafe path: {entry.filename!r}")
            if str(path) in seen:
                raise ValueError(f"Duplicate path: {entry.filename!r}")
            seen.add(str(path))
            if entry.flag_bits & 1:
                raise ValueError("Encrypted ZIP entries are unsupported.")
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"Link/special file refused: {entry.filename!r}")
            total += entry.file_size
            if total > 512 * 1024 * 1024:
                raise ValueError("ZIP uncompressed size exceeds 512 MiB.")
        dst.mkdir(mode=0o700)
        try:
            z.extractall(dst)
        except Exception:
            shutil.rmtree(dst, ignore_errors=True)
            raise
except Exception as exc:
    if dst.is_dir() and not dst.is_symlink():
        shutil.rmtree(dst, ignore_errors=True)
    raise SystemExit(f"ZIP import failed: {exc}")

print(f"Extracted into new directory: {dst}")
PYZIP
                target="$destination"
                mapfile -t dirs < <(find "$target" -mindepth 1 -maxdepth 1 -type d -print)
                mapfile -t files < <(find "$target" -mindepth 1 -maxdepth 1 -type f -print)
                if [[ ${#dirs[@]} -eq 1 && ${#files[@]} -eq 0 ]]; then
                    target="${dirs[0]}"
                fi
            fi

            target="$(realpath -e -- "$target")"
            echo
            echo "Target: $target"
            "$QSCTL" integrate detect "$target" || return $?
            echo
            echo "Quantum Shield will manage only its own integration files."
            echo "Your application source and existing hooks should remain untouched."
            confirm || { echo "Cancelled."; return 0; }
            "$QSCTL" integrate install "$target"
            ;;
        4) repository_mode ;;
        5) software_mode ;;
        6)
            read -r -p "Directory to audit: " target || return 1
            [[ -d "$target" ]] || { echo "Directory not found."; return 1; }
            target="$(realpath -e -- "$target")"
            "$QSCTL" app-audit "$target"
            ;;
        0) return 0 ;;
        *) echo "Invalid choice."; return 2 ;;
    esac
}
integration_maintenance_mode() {
    local target action
    echo
    read -r -p "Project directory [$PWD]: " target
    target="${target:-$PWD}"
    [[ -d "$target" ]] || { echo "ERROR: Project directory does not exist."; return 1; }
    target="$(realpath -e -- "$target")"
    echo "  1) Status"
    echo "  2) Remove unmodified Quantum Shield integration files"
    read -r -p "Choose [1-2]: " action
    case "$action" in
        1) "$QSCTL" integrate status "$target" ;;
        2) confirm || { echo "Cancelled."; return 1; }; "$QSCTL" integrate remove "$target" ;;
        *) echo "Invalid choice."; return 2 ;;
    esac
}

website_mode() {
    local action target archive destination answer helper
    local config cert key listen blocked_agents

    echo
    echo "========== QUANTUM SHIELD WEBSITE SHIELD =========="
    echo "1) Import website ZIP and integrate Quantum Shield"
    echo "2) Select existing website folder and integrate"
    echo "3) Start HTTPS reverse proxy with existing configuration"
    echo "0) Back"
    read -r -p "Choose [0-3]: " action || return 0

    case "$action" in
        1|2)
            if [[ "$action" == 1 ]]; then
                command -v python3 >/dev/null 2>&1 || {
                    echo "ERROR: Python 3 is required for safe ZIP import."
                    return 1
                }
                archive="$(zenity --file-selection \
                    --title="Choose website project ZIP" \
                    --filename="$HOME/" \
                    --file-filter='ZIP archives | *.zip *.ZIP' 2>/dev/null)" || {
                    echo "ZIP selection cancelled."
                    return 0
                }
                [[ -f "$archive" ]] || {
                    echo "ERROR: ZIP file not found."
                    return 1
                }
                archive="$(realpath -e -- "$archive")" || return 1
                destination="$PWD/$(basename -- "${archive%.*}")-quantum-shield"

                [[ ! -e "$destination" && ! -L "$destination" ]] || {
                    echo "ERROR: Destination already exists: $destination"
                    echo "Nothing was overwritten."
                    return 1
                }

                echo "Checking and extracting ZIP into a new directory..."
                python3 - "$archive" "$destination" <<'PYZIP'
import shutil, stat, sys, zipfile
from pathlib import Path, PurePosixPath

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
if dst.exists() or dst.is_symlink():
    raise SystemExit("Destination already exists.")

try:
    with zipfile.ZipFile(src) as z:
        entries = z.infolist()
        if len(entries) > 20000:
            raise ValueError("ZIP contains more than 20,000 entries.")

        total = 0
        seen = set()
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            path = PurePosixPath(name)

            if (not name or name.startswith("/") or path.is_absolute()
                or any(part in ("..", "") for part in path.parts)
                or (path.parts and ":" in path.parts[0])):
                raise ValueError(f"Unsafe archive path: {entry.filename!r}")

            normalized = str(path)
            if normalized in seen:
                raise ValueError(f"Duplicate archive path: {entry.filename!r}")
            seen.add(normalized)

            if entry.flag_bits & 1:
                raise ValueError("Encrypted ZIP entries are unsupported.")

            mode = stat.S_IFMT(entry.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"Link or special file refused: {entry.filename!r}")

            total += entry.file_size
            if total > 512 * 1024 * 1024:
                raise ValueError("Uncompressed ZIP exceeds 512 MiB.")

        dst.mkdir(mode=0o700)
        try:
            z.extractall(dst)
        except Exception:
            shutil.rmtree(dst, ignore_errors=True)
            raise

except Exception as exc:
    if dst.is_dir() and not dst.is_symlink():
        shutil.rmtree(dst, ignore_errors=True)
    raise SystemExit(f"ZIP import failed: {exc}")

print(f"Extracted safely into: {dst}")
PYZIP
                local zip_status=$?
                if (( zip_status != 0 )); then
                    return "$zip_status"
                fi

                target="$destination"
                local -a dirs=() files=()
                mapfile -t dirs < <(find "$target" -mindepth 1 -maxdepth 1 -type d -print)
                mapfile -t files < <(find "$target" -mindepth 1 -maxdepth 1 -type f -print)
                if [[ ${#dirs[@]} -eq 1 && ${#files[@]} -eq 0 ]]; then
                    target="${dirs[0]}"
                fi
            else
                target="$(qs_choose_folder_gui "Choose website project folder" "$PWD")" || {
                    echo "Folder selection cancelled."
                    return 0
                }
                [[ -d "$target" ]] || {
                    echo "ERROR: Selected folder does not exist."
                    return 1
                }
            fi

            target="$(realpath -e -- "$target")" || return 1

            echo
            echo "===== PROJECT DETECTION ====="
            "$QSCTL" integrate detect "$target" || {
                echo "Detection failed. No integration was installed."
                return 1
            }

            echo
            echo "The installer creates managed files under:"
            echo "$target/.quantum-shield/"
            echo "It does not rewrite your application source or deployment files."
            confirm || {
                echo "Integration cancelled. Your original project is preserved."
                return 0
            }

            echo
            echo "===== INSTALLING REVERSIBLE INTEGRATION ====="
            "$QSCTL" integrate install "$target" || {
                echo "Integration did not complete successfully."
                echo "Inspect the project before retrying."
                return 1
            }

            echo
            echo "===== INTEGRATION STATUS ====="
            "$QSCTL" integrate status "$target" || true

            helper="$target/.quantum-shield/website-shield.sh"
            if [[ -f "$helper" ]]; then
                echo
                echo "A local loopback gateway helper was generated:"
                echo "$helper"
                echo "Start your website application first."
                read -r -p "Start the local gateway now? [y/N]: " answer || answer=""
                case "${answer,,}" in
                    y|yes)
                        echo "Starting local gateway. Press Ctrl+C to stop it."
                        exec bash "$helper"
                        ;;
                    *)
                        echo "Gateway not started. Integration files are installed."
                        ;;
                esac
            else
                echo
                echo "No local gateway helper was generated for this platform."
                echo "Review the detection output for its supported deployment path."
                echo "Static or managed hosting requires a compatible edge/reverse-proxy route."
            fi
            ;;

        3)
            echo
            echo "=== HTTPS REVERSE PROXY ==="
            echo "This starts the existing HTTPS traffic-protection proxy."
            echo "It requires a valid site configuration and matching certificate/key."

            read -r -p "Site configuration path: " config
            [[ -n "$config" && -f "$config" ]] || {
                echo "ERROR: Provide an existing configuration file."
                return 1
            }

            read -r -p "TLS certificate PEM path: " cert
            read -r -p "TLS private key PEM path: " key
            [[ -f "$cert" && -f "$key" ]] || {
                echo "ERROR: Certificate and key files must both exist."
                return 1
            }

            read -r -p "Listen address [127.0.0.1:8443]: " listen
            listen="${listen:-127.0.0.1:8443}"

            case "$listen" in
                127.*|localhost:*|'[::1]':*) ;;
                *)
                    echo "WARNING: This listener may expose the service beyond this machine."
                    echo "Check firewall, DNS, certificate and upstream configuration."
                    confirm || {
                        echo "Cancelled."
                        return 1
                    }
                    ;;
            esac

            read -r -p "Blocked User-Agent substrings (comma-separated; blank disables): " blocked_agents
            if [[ -n "$blocked_agents" ]]; then
                export QS_BLOCKED_USER_AGENTS="$blocked_agents"
            else
                unset QS_BLOCKED_USER_AGENTS || true
            fi

            echo
            echo "Starting the existing HTTPS reverse proxy."
            echo "Direct serve-https does not automatically issue certificates."
            confirm || return 1

            exec "$QSCTL" serve-https "$config" \
                --listen "$listen" --cert "$cert" --key "$key"
            ;;

        0) return 0 ;;
        *) echo "Invalid choice."; return 2 ;;
    esac
}

repository_mode() {
    local repo failed=0

    echo
    echo "=== REPOSITORY SHIELD ==="
    echo "Layer 1: bounded source and configuration scanning."
    echo "Layer 2: Git-history secret scanning, when Git history exists."
    echo "Layer 3: dependency advisory audit, when Cargo.lock and cargo-audit exist."

    repo="$(qs_pick_directory "Choose repository folder" "$HOME")" || { echo "Cancelled."; return 0; }
    [[ -d "$repo" ]] || {
        echo "ERROR: Directory does not exist."
        return 1
    }

    repo="$(realpath -e -- "$repo")"

    echo "Target: $repo"
    confirm || { echo "Cancelled."; return 1; }

    echo
    echo "=== Source and configuration scan ==="
    if "$QSCTL" repo-scan "$repo"; then
        echo "Source scan command completed; review its findings."
    else
        echo "ERROR: Source scan failed."
        failed=1
    fi

    echo
    echo "=== Git-history scan ==="
    if [[ -e "$repo/.git" ]]; then
        if "$QSCTL" git-history-scan "$repo"; then
            echo "Git-history scan command completed; review its findings."
        else
            echo "WARNING: Git-history scan failed or reported a problem."
            failed=1
        fi
    else
        echo "UNAVAILABLE: No Git metadata found; history was not scanned."
    fi

    echo
    echo "=== Dependency advisory scan ==="
    if [[ -f "$repo/Cargo.lock" ]]; then
        if "$QSCTL" cargo-audit "$repo"; then
            echo "Dependency audit command completed; inspect its status."
        else
            echo "UNAVAILABLE OR FAILED: Dependency audit did not complete cleanly."
            failed=1
        fi
    else
        echo "SKIPPED: No Cargo.lock in this target; Cargo dependency audit does not apply."
    fi

    if [[ "$failed" -ne 0 ]]; then
        echo "PARTIAL: One or more checks failed. Do not treat the repository as clean."
        return 1
    fi
}

software_mode() {
    local executable audit_dir app_dir writable share arg
    local -a command_args target_args

    echo
    echo "=== SOFTWARE SHIELD ==="
    echo "Layer 1: application source/deployment audit."
    echo "Layer 2: Bubblewrap isolation and enforced resource limits."
    echo "This profile is for compatible Linux CLI software, not arbitrary GUI apps."

    executable="$(qs_pick_file "Choose Linux executable" "$HOME")" || { echo "Cancelled."; return 0; }
    [[ -f "$executable" && -x "$executable" ]] || {
        echo "ERROR: Executable is missing or not executable."
        return 1
    }
    executable="$(realpath -e -- "$executable")"

    audit_dir="$(qs_pick_directory "Choose application source folder" "$HOME")" || { echo "Cancelled."; return 0; }
    [[ -d "$audit_dir" ]] || {
        echo "ERROR: An existing audit directory is required for the first layer."
        return 1
    }
    audit_dir="$(realpath -e -- "$audit_dir")"

    read -r -p "Choose an app directory to mount read-only? [y/N]: " use_app_dir || return 0
    if [[ "$use_app_dir" =~ ^[Yy]$ ]]; then
        app_dir="$(qs_pick_directory "Choose app folder" "$HOME")" || { echo "Cancelled."; return 0; }
    else
        app_dir=""
    fi
    if [[ -n "$app_dir" ]]; then
        [[ -d "$app_dir" ]] || {
            echo "ERROR: Application directory does not exist."
            return 1
        }
        app_dir="$(realpath -e -- "$app_dir")"
        case "$executable" in
            "$app_dir"/*) ;;
            *)
                echo "ERROR: When using --app-dir, the executable must be inside that directory."
                return 1
                ;;
        esac
    fi

    read -r -p "Optional writable output directory (blank = none): " writable
    if [[ -n "$writable" ]]; then
        [[ -d "$writable" ]] || {
            echo "ERROR: Writable output directory must already exist."
            return 1
        }
        writable="$(realpath -e -- "$writable")"
    fi

    read -r -p "Share host networking? Type YES to opt in; otherwise isolate: " share

    target_args=()
    echo "Enter one application argument per line; submit a blank line to finish."
    while true; do
        read -r -p "Argument: " arg || break
        [[ -n "$arg" ]] || break
        target_args+=("$arg")
    done

    echo
    echo "Planned protections:"
    echo "  1. Audit: $audit_dir"
    echo "  2. Sandbox executable: $executable"
    echo "  Network isolation: $([[ "$share" == "YES" ]] && echo "disabled by explicit opt-in" || echo "enabled")"
    echo
    confirm || { echo "Cancelled."; return 1; }

    echo
    echo "=== Application audit ==="
    if ! "$QSCTL" app-audit "$audit_dir"; then
        echo "ERROR: Application audit did not complete. Sandbox launch cancelled."
        return 1
    fi

    command_args=("$QSCTL" sandbox-run "$executable")

    if [[ -n "$app_dir" ]]; then
        command_args+=(--app-dir "$app_dir")
    fi
    if [[ -n "$writable" ]]; then
        command_args+=(--writable-dir "$writable")
    fi
    if [[ "$share" == "YES" ]]; then
        command_args+=(--share-network)
    fi
    if ((${#target_args[@]})); then
        command_args+=(-- "${target_args[@]}")
    fi

    echo
    echo "=== Launching existing Software Shield sandbox ==="
    exec "${command_args[@]}"
}

echo
echo "===================================="
echo "          QUANTUM SHIELD"
echo "     Guided layered protection"
echo "===================================="
echo "Choose a workflow:"
echo "  1) Quick Protect — select a project/folder/ZIP graphically"
echo "  2) Encrypt/decrypt file or protect a project archive"
echo "  3) Website — HTTPS reverse proxy"
echo "  4) Repository — security assessments"
echo "  5) Linux software/application — audit and sandbox"
echo "  6) Check/remove project integrations"
echo "  7) Exit"

read -r -p "Select [1-7]: " choice || exit 0
case "$choice" in
    1) integration_mode ;;
    2) encryption_mode ;;
    3) website_mode ;;
    4) repository_mode ;;
    5) software_mode ;;
    6) integration_maintenance_mode ;;
    7) exit 0 ;;
    *) echo "Invalid choice."; exit 2 ;;
esac
