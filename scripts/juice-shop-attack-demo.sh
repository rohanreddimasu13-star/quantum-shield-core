#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || { echo "ERROR: Cannot enter Quantum Shield project directory."; exit 2; }
QS="$ROOT/target/debug/qsctl"
IMAGE="bkimminich/juice-shop"
HOST="localhost"
UPSTREAM_PORT="${QS_DEMO_UPSTREAM_PORT:-13002}"
SHIELD_PORT="${QS_DEMO_SHIELD_PORT:-18445}"
STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield/juice-shop-demo"
CURRENT="$STATE_ROOT/current-session"

mkdir -p "$STATE_ROOT"

# Stop only the disposable demo session created by this script.
if [[ "${1:-}" == "--stop" ]]; then
    if [[ ! -r "$CURRENT" ]]; then
        echo "No recorded Quantum Shield demo session."
        exit 0
    fi

    SESSION="$(cat "$CURRENT")"
    case "$SESSION" in
        "$HOME"/Projects/quantum-shield-backups/juice-shop-demo-*) ;;
        *) echo "ERROR: Unrecognized session path; refusing cleanup."; exit 2 ;;
    esac

    if [[ ! -d "$SESSION" ]]; then
        rm -f "$CURRENT"
        echo "Removed stale session marker."
        exit 0
    fi

    PID="$(cat "$SESSION/shield.pid" 2>/dev/null || true)"
    PORT="$(cat "$SESSION/shield.port" 2>/dev/null || true)"
    CONTAINER="$(cat "$SESSION/container.name" 2>/dev/null || true)"

    if [[ "$PID" =~ ^[0-9]+$ && -r "/proc/$PID/cmdline" ]]; then
        ARGS="$(tr '\0' ' ' < "/proc/$PID/cmdline")"
        if [[ "$ARGS" == *"$ROOT/target/debug/qsctl"* &&
              "$ARGS" == *"serve-https"* &&
              "$ARGS" == *"127.0.0.1:$PORT"* &&
              "$ARGS" == *"$SESSION/key.pem"* ]]; then
            kill -TERM "$PID" 2>/dev/null || true
            echo "Stopped the recorded demo proxy process."
        else
            echo "WARNING: PID does not match the recorded demo proxy; left untouched."
        fi
    fi

    if [[ -n "$CONTAINER" ]] && docker inspect "$CONTAINER" >/dev/null 2>&1; then
        LABEL="$(docker inspect -f '{{ index .Config.Labels "quantum-shield.local-demo" }}' "$CONTAINER" 2>/dev/null || true)"
        if [[ "$LABEL" == "true" ]]; then
            docker rm -f "$CONTAINER"
            echo "Removed disposable demo container."
        else
            echo "WARNING: Container label did not match; left container untouched."
        fi
    fi

    rm -f "$CURRENT"
    echo "Stop complete. Evidence retained at: $SESSION"
    exit 0
fi

if [[ -e "$CURRENT" ]]; then
    echo "A demo session is already recorded: $(cat "$CURRENT")"
    echo "Inspect it or stop it through the launcher before starting another."
    exit 2
fi

for tool in docker cargo curl openssl ss python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: Missing required tool: $tool"
        exit 2
    }
done

# Never take over an unrelated service using either demo port.
for port in "$UPSTREAM_PORT" "$SHIELD_PORT"; do
    if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
        echo "ERROR: Port $port is occupied. Existing service left untouched."
        exit 2
    fi
done

# Build the real Quantum Shield CLI.
cargo build --locked --bin qsctl
[[ -x "$QS" ]] || { echo "ERROR: qsctl binary was not built."; exit 2; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Juice Shop image not cached; pulling the official demo image."
    docker pull "$IMAGE"
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
SESSION="$HOME/Projects/quantum-shield-backups/juice-shop-demo-$STAMP"
mkdir -p "$SESSION/evidence"
chmod 700 "$SESSION"
OWNED_CONTAINER=""
OWNED_PID=""
SETUP_COMPLETE=0

cleanup_failed_setup() {
    RC=$?
    if [[ "$SETUP_COMPLETE" -ne 1 && "$RC" -ne 0 ]]; then
        if [[ -n "$OWNED_PID" ]]; then
            kill -TERM "$OWNED_PID" 2>/dev/null || true
        fi
        if [[ -n "$OWNED_CONTAINER" ]]; then
            docker rm -f "$OWNED_CONTAINER" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup_failed_setup EXIT

umask 077
CONTAINER="qs-juice-shop-demo-$STAMP"
printf '%s\n' "$CONTAINER" > "$SESSION/container.name"
printf '%s\n' "$SHIELD_PORT" > "$SESSION/shield.port"

echo "=== Starting disposable Juice Shop on loopback ==="
docker run -d \
    --name "$CONTAINER" \
    --label quantum-shield.local-demo=true \
    -p "127.0.0.1:$UPSTREAM_PORT:3000" \
    "$IMAGE" > "$SESSION/container.id"
OWNED_CONTAINER="$CONTAINER"

DIRECT_OK=0
for _ in $(seq 1 60); do
    if curl --noproxy '*' --silent --show-error --max-time 2 \
        -o "$SESSION/direct-home.html" \
        -w '%{http_code}' "http://127.0.0.1:$UPSTREAM_PORT/" \
        > "$SESSION/direct.status" 2> "$SESSION/direct.err"; then
        if [[ "$(cat "$SESSION/direct.status")" == "200" ]] &&
           grep -Eiq 'juice.?shop|OWASP' "$SESSION/direct-home.html"; then
            DIRECT_OK=1
            break
        fi
    fi
    sleep 1
done
if [[ "$DIRECT_OK" -ne 1 ]]; then
    echo "ERROR: Direct origin did not prove it was Juice Shop with HTTP 200."
    cat "$SESSION/direct.err" 2>/dev/null || true
    exit 2
fi
echo "PASS: Direct-origin identity and HTTP 200 verified."

cat > "$SESSION/config.toml" <<TOML
schema_version = 1

[[sites]]
id = "judge-juice-shop"
domain = "$HOST"
upstream = "http://127.0.0.1:$UPSTREAM_PORT"
TOML

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -sha256 -days 2 -nodes \
    -keyout "$SESSION/key.pem" -out "$SESSION/cert.pem" \
    -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST" >/dev/null 2>&1
chmod 600 "$SESSION/key.pem"

AGENTS="GPTBot,ChatGPT-User,OAI-SearchBot,ClaudeBot,Claude-User,PerplexityBot,CCBot,Bytespider,Amazonbot,meta-externalagent,cohere-ai,Diffbot,YouBot,AI2Bot-Dolma,GoogleOther,LangChain,ARTEX,nuclei,sqlmap,HeadlessChrome,Playwright,Puppeteer,Selenium"

echo "=== Starting Quantum Shield HTTPS proxy ==="
QS_BLOCKED_USER_AGENTS="$AGENTS" nohup "$QS" serve-https \
    --listen "127.0.0.1:$SHIELD_PORT" \
    --cert "$SESSION/cert.pem" \
    --key "$SESSION/key.pem" \
    "$SESSION/config.toml" > "$SESSION/shield.log" 2>&1 </dev/null &
OWNED_PID=$!
printf '%s\n' "$OWNED_PID" > "$SESSION/shield.pid"

BASE="https://$HOST:$SHIELD_PORT"
READY=0
for _ in $(seq 1 30); do
    if ! kill -0 "$OWNED_PID" 2>/dev/null; then
        break
    fi
    if curl --noproxy '*' --insecure --silent --show-error --max-time 3 \
        --resolve "$HOST:$SHIELD_PORT:127.0.0.1" \
        -o "$SESSION/shield-home.html" -w '%{http_code}' "$BASE/" \
        > "$SESSION/shield-baseline.status" 2> "$SESSION/shield-baseline.err"; then
        if [[ "$(cat "$SESSION/shield-baseline.status")" == "200" ]]; then
            READY=1
            break
        fi
    fi
    sleep 1
done
if [[ "$READY" -ne 1 ]]; then
    echo "ERROR: Shield baseline failed. Log:"
    tail -n 80 "$SESSION/shield.log" 2>/dev/null || true
    exit 2
fi

# Register only after the disposable origin and shield are both ready.
printf '%s\n' "$SESSION" > "$CURRENT"
SETUP_COMPLETE=1
trap - EXIT

printf 'test\texpected\tactual\tcurl_exit\tresult\turl\n' > "$SESSION/results.tsv"
PASS_COUNT=0
FAIL_COUNT=0
LAST_HEADERS=""

probe() {
    local name="$1" expected="$2" url="$3"
    shift 3
    local tmp slug actual curl_rc outcome bytes digest

    slug="$(printf '%s' "$name" | sed 's/[^A-Za-z0-9]/_/g' | tr '[:upper:]' '[:lower:]')"
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/qs-demo-probe.XXXXXX")"

    if actual="$(curl --noproxy '*' --insecure --silent --show-error \
        --connect-timeout 3 --max-time 20 \
        --resolve "$HOST:$SHIELD_PORT:127.0.0.1" \
        --dump-header "$tmp/headers" --output "$tmp/body" \
        --write-out '%{http_code}' "$@" "$url" 2>"$tmp/error")"; then
        curl_rc=0
    else
        curl_rc=$?
        actual="${actual:-000}"
    fi

    [[ -n "$actual" ]] || actual="000"
    bytes="$(wc -c < "$tmp/body" | tr -d ' ')"
    digest="$(sha256sum "$tmp/body" | awk '{print $1}')"

    # Save only selected non-sensitive headers; never save Set-Cookie.
    awk 'BEGIN { IGNORECASE=1 }
        /^HTTP\// { print; next }
        tolower($0) ~ /^(content-type|content-length|x-quantum-shield-policy|server):/ { print }
    ' "$tmp/headers" > "$SESSION/evidence/$slug.headers"

    printf 'url=%s\nexpected_http=%s\nactual_http=%s\ncurl_exit=%s\nbody_bytes=%s\nbody_sha256=%s\n' \
        "$url" "$expected" "$actual" "$curl_rc" "$bytes" "$digest" \
        > "$SESSION/evidence/$slug.txt"
    LAST_HEADERS="$SESSION/evidence/$slug.headers"

    if [[ "$actual" == "$expected" && "$curl_rc" -eq 0 ]]; then
        outcome="PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "PASS: $name — HTTP $actual"
    else
        outcome="REVIEW"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "REVIEW: $name — expected HTTP $expected, got HTTP $actual (curl exit $curl_rc)"
        if [[ -s "$tmp/error" ]]; then
            sed -n '1,3p' "$tmp/error"
        fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$expected" "$actual" "$curl_rc" "$outcome" "$url" \
        >> "$SESSION/results.tsv"
    rm -rf -- "$tmp"
}

echo
echo "========== LOCAL ATTACK DEMONSTRATION =========="
echo "Through Quantum Shield: $BASE"
echo "Direct origin: http://127.0.0.1:$UPSTREAM_PORT/"
echo "Evidence: $SESSION"

probe "Benign homepage" 200 "$BASE/"
probe "Benign product search" 200 "$BASE/rest/products/search?q=apple"
probe "SQL injection query" 403 "$BASE/rest/products/search?q=%27%20OR%201%3D1--"
probe "XSS query" 403 "$BASE/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
probe "Raw path traversal" 403 "$BASE/../../../../etc/passwd" --path-as-is
probe "Encoded path traversal" 403 "$BASE/%2e%2e%2fetc/passwd" --path-as-is
probe "Double-encoded traversal" 403 "$BASE/%252e%252e%252fetc/passwd" --path-as-is
probe "Invalid Host rejected" 421 "$BASE/" -H "Host: attacker.invalid"
probe "PURGE rejected" 403 "$BASE/" -X PURGE
probe "TRACE rejected" 405 "$BASE/" -X TRACE
probe "CONNECT rejected" 501 "$BASE/" -X CONNECT
probe "Unsigned JWT rejected" 401 "$BASE/" \
    -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.'
probe "GPTBot denied" 403 "$BASE/" \
    -H 'User-Agent: Mozilla/5.0 (compatible; GPTBot/1.2)'
if grep -Eqi '^X-Quantum-Shield-Policy:[[:space:]]*ai-agent-blocked' "$LAST_HEADERS"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS\t%s\t%s\t0\tPASS\t%s\n' \
        "GPTBot policy header" "ai-agent-blocked" "$BASE/" >> "$SESSION/results.tsv"
    echo "PASS: GPTBot response has the policy header."
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL\t%s\t%s\t0\tREVIEW\t%s\n' \
        "GPTBot policy header" "ai-agent-blocked" "$BASE/" >> "$SESSION/results.tsv"
    echo "REVIEW: expected X-Quantum-Shield-Policy: ai-agent-blocked."
fi
probe "Normal Chrome allowed" 200 "$BASE/" \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36'
probe "Googlebot allowed" 200 "$BASE/" \
    -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

echo "Creating a bounded 17 MiB upload to test the configured body cap..."
head -c 17825792 /dev/zero > "$SESSION/.bounded-17MiB.bin"
probe "17 MiB request body limit" 413 "$BASE/" \
    -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$SESSION/.bounded-17MiB.bin" --max-time 45
rm -f -- "$SESSION/.bounded-17MiB.bin"

python3 - "$SESSION/results.tsv" "$SESSION/report.md" "$PASS_COUNT" "$FAIL_COUNT" <<'PY'
import csv, sys
from pathlib import Path

tsv, report = Path(sys.argv[1]), Path(sys.argv[2])
passes, failures = int(sys.argv[3]), int(sys.argv[4])
rows = list(csv.DictReader(tsv.open(), delimiter="\t"))
with report.open("w") as f:
    f.write("# Quantum Shield — Local Juice Shop Attack Demo\n\n")
    f.write("Scope: disposable OWASP Juice Shop on loopback, tested through Quantum Shield HTTPS.\n\n")
    f.write("No public targets were scanned. Response status mismatches are triage candidates, not automatically confirmed vulnerabilities.\n\n")
    f.write(f"- Checks matching expected response: **{passes}**\n")
    f.write(f"- Checks requiring review: **{failures}**\n")
    f.write(f"- Checks recorded: **{len(rows)}**\n\n")
    f.write("| Test | Expected | Actual | curl exit | Result |\n|---|---:|---:|---:|---|\n")
    for r in rows:
        test = r["test"].replace("|", "\\|")
        f.write(f'| {test} | {r["expected"]} | {r["actual"]} | {r["curl_exit"]} | {r["result"]} |\n')
    f.write("\n## Evidence\n\n")
    f.write("Per-request evidence contains the URL, HTTP status, body size, SHA-256 digest, and an allowlist of response headers. Set-Cookie headers are not preserved.\n")
    f.write("See `results.tsv`, `evidence/`, and `shield.log` for the run artifacts.\n\n")
    f.write("This is a bounded local demonstration, not a complete penetration test or production-readiness certification.\n")
print("Report written:", report)
PY

echo
echo "========== DEMO SUMMARY =========="
echo "Checks matching expected responses: $PASS_COUNT"
echo "Checks requiring review:            $FAIL_COUNT"
echo "Judge URL: $BASE/"
echo "Report:    $SESSION/report.md"
echo "TSV:       $SESSION/results.tsv"
echo "Shield log: $SESSION/shield.log"
echo "Services remain running for the demonstration."
echo "Stop safely with: bash \"$ROOT/quantum-shield-first-run.sh\" --stop-attack-demo"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "Some responses differ from expectations. Review the evidence; no bypass is declared solely from a status mismatch."
    exit 1
fi

echo "All configured demonstration checks matched their expected responses."
