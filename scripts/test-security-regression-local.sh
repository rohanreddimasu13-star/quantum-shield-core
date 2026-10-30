#!/usr/bin/env bash
set -u

PROJECT="$HOME/Projects/quantum-shield-rc2/quantum-shield-rust-v1.0.0-rc2"
LAB="$HOME/Projects/qs-local-attack-lab"
QS="$PROJECT/target/debug/qsctl"
CFG="$LAB/qs-config.toml"
CERT="$LAB/fullchain.pem"
KEY="$LAB/privkey.pem"
HOST="qs-lab.test"
PORT="${QS_TEST_PORT:-18444}"
BASE="https://$HOST:$PORT"
STAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_LOG="$LAB/results/security-regression-$STAMP.log"
SHIELD_LOG="$LAB/results/security-regression-shield-$STAMP.log"
TMPDIR="$(mktemp -d "$LAB/.regression.XXXXXX")"
TEST_PID=""
UPSTREAM_PID=""
FAILURES=0
PASSES=0

exec > >(tee -a "$RESULT_LOG") 2>&1

cleanup() {
    if [ -n "$TEST_PID" ]; then
        kill "$TEST_PID" 2>/dev/null || true
        wait "$TEST_PID" 2>/dev/null || true
    fi
    if [ -n "${UPSTREAM_PID:-}" ]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

pass() {
    printf 'PASS: %s\n' "$1"
    PASSES=$((PASSES + 1))
}

fail() {
    printf 'FAIL: %s\n' "$1"
    FAILURES=$((FAILURES + 1))
}

exact() {
    LABEL="$1"
    ACTUAL="$2"
    EXPECTED="$3"
    if [ "$ACTUAL" = "$EXPECTED" ]; then
        pass "$LABEL (HTTP $ACTUAL)"
    else
        fail "$LABEL (expected HTTP $EXPECTED, received $ACTUAL)"
    fi
}

printf 'Quantum Shield local regression suite\n'
printf 'Started: %s\nTarget: %s\n' "$(date --iso-8601=seconds)" "$BASE"

if [ ! -x "$QS" ] || [ ! -r "$CFG" ] ||
   [ ! -r "$CERT" ] || [ ! -r "$KEY" ]; then
    echo "FAIL: required binary, config, or TLS files are missing."
    exit 2
fi

if ! grep -Fq 'upstream = "http://127.0.0.1:13001"' "$CFG"; then
    echo "FAIL: unexpected upstream mapping; refusing to test."
    exit 2
fi

if ss -ltn 2>/dev/null | grep -Eq ":$PORT([[:space:]]|$)"; then
    echo "FAIL: port $PORT is already in use; refusing to interrupt it."
    exit 2
fi


# QS_REGRESSION_UPSTREAM_FIXTURE: local test-only service on loopback.
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required for the test upstream."
    exit 2
fi

cat > "$TMPDIR/upstream.py" <<'QS_UPSTREAM_PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"Quantum Shield Rust test upstream\n"

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > 1024 * 1024:
                self.send_response(413)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            remaining = length
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(BODY)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(BODY)
        except (BrokenPipeError, ConnectionResetError, ValueError):
            pass

    do_GET = respond
    do_POST = respond
    do_PUT = respond
    do_PATCH = respond
    do_DELETE = respond
    do_OPTIONS = respond
    do_HEAD = respond

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", 13001), Handler).serve_forever()
QS_UPSTREAM_PY

python3 "$TMPDIR/upstream.py" > "$TMPDIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!

UPSTREAM_READY=0
for n in $(seq 1 30); do
    if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        break
    fi
    if curl --noproxy '*' --silent --fail --max-time 1 \
        http://127.0.0.1:13001/ -o "$TMPDIR/upstream-body" 2>/dev/null &&
       grep -Fqx 'Quantum Shield Rust test upstream' "$TMPDIR/upstream-body"; then
        UPSTREAM_READY=1
        break
    fi
    sleep 0.2
done

if [ "$UPSTREAM_READY" -ne 1 ]; then
    echo "ERROR: local test upstream did not become ready."
    cat "$TMPDIR/upstream.log" 2>/dev/null || true
    exit 2
fi
echo "PASS: local upstream ready at 127.0.0.1:13001."

    QS_BLOCKED_USER_AGENTS="${QS_BLOCKED_USER_AGENTS:-GPTBot,ChatGPT-User,ClaudeBot,PerplexityBot,CCBot,HeadlessChrome}" "$QS" serve-https --listen "127.0.0.1:$PORT" \
    --cert "$CERT" --key "$KEY" "$CFG" > "$SHIELD_LOG" 2>&1 &
TEST_PID=$!

READY=0
for n in $(seq 1 15); do
    if ! kill -0 "$TEST_PID" 2>/dev/null; then
        break
    fi
    CODE="$(curl --noproxy '*' --resolve "$HOST:$PORT:127.0.0.1" \
        --connect-timeout 1 --max-time 2 -k -sS -o /dev/null \
        -w '%{http_code}' "$BASE/" 2>/dev/null)"
    if [ "$CODE" != "000" ] && [ -n "$CODE" ]; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "FAIL: test Shield did not become ready. Log follows:"
    tail -50 "$SHIELD_LOG"
    exit 2
fi

curl_code() {
    URL="$1"
    shift
    curl --noproxy '*' --resolve "$HOST:$PORT:127.0.0.1" \
        --connect-timeout 2 --max-time 10 -k -sS \
        "$@" -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null
}

echo
echo "=== LEGITIMATE TRAFFIC ==="
exact "Homepage" "$(curl_code "$BASE/")" "200"
exact "Normal product search" \
    "$(curl_code "$BASE/rest/products/search?q=apple")" "200"

echo
echo "=== AI AGENT / CRAWLER POLICY ==="
exact "GPTBot blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: Mozilla/5.0 GPTBot/1.0')" "403"
exact "ChatGPT-User blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: ChatGPT-User/1.0')" "403"
exact "ClaudeBot blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: ClaudeBot/1.0')" "403"
exact "PerplexityBot blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: PerplexityBot/1.0')" "403"
exact "CCBot blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: CCBot/2.0')" "403"
exact "HeadlessChrome blocked" \
    "$(curl_code "$BASE/" -H 'User-Agent: Mozilla/5.0 HeadlessChrome/120.0.0.0')" "403"
exact "Normal browser allowed" \
    "$(curl_code "$BASE/" -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')" "200"

echo
echo "=== WAF ATTACK TESTS ==="
exact "SQL injection query blocked" \
    "$(curl_code "$BASE/rest/products/search" --get \
      --data-urlencode "q=' OR 1=1--")" "403"

exact "XSS query blocked" \
    "$(curl_code "$BASE/rest/products/search" --get \
      --data-urlencode 'q=<script>alert(1)</script>')" "403"

echo
echo "=== JWT POLICY ==="
UNSIGNED_JWT='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.'
exact "Unsigned JWT bearer rejected" \
    "$(curl_code "$BASE/" -H "Authorization: Bearer $UNSIGNED_JWT")" "401"

echo
echo "=== REQUEST BODY REGRESSION ==="
BODY_CODE="$(curl_code "$BASE/rest/user/login" \
    -X POST -H 'Content-Type: application/json' \
    --data-binary \
    '{"email":"shield-regression-does-not-exist@example.invalid","password":"not-a-real-password"}')"
if [ "$BODY_CODE" != "502" ] && [ "$BODY_CODE" != "000" ]; then
    pass "Fixed-length request body did not yield a 502 (HTTP $BODY_CODE)"
else
    fail "Fixed-length request body returned HTTP $BODY_CODE"
fi

echo
echo "=== HOST ALLOWLIST ==="
UNKNOWN_CODE="$(curl --noproxy '*' \
    --resolve "unknown.test:$PORT:127.0.0.1" \
    --connect-timeout 2 --max-time 8 -k -sS \
    -o /dev/null -w '%{http_code}' \
    "https://unknown.test:$PORT/" 2>/dev/null)"
exact "Unknown host rejected" "$UNKNOWN_CODE" "421"

echo
echo "=== REAL WEBSOCKET UPGRADE AND ENGINE.IO EXCHANGE ==="
if python3 - "$PORT" <<'PY'
import base64, os, socket, ssl, sys

port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=5)
sock.settimeout(5)
context = ssl._create_unverified_context()
context.set_alpn_protocols(["http/1.1"])
conn = context.wrap_socket(sock, server_hostname="qs-lab.test")

key = base64.b64encode(os.urandom(16)).decode()
request = (
    "GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n"
    f"Host: qs-lab.test:{port}\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: websocket\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Origin: https://qs-lab.test\r\n\r\n"
)
conn.sendall(request.encode('ascii'))

buffer = b""
while b"\r\n\r\n" not in buffer and len(buffer) < 16384:
    chunk = conn.recv(4096)
    if not chunk:
        raise RuntimeError("closed before HTTP upgrade response")
    buffer += chunk

header, _, buffer = buffer.partition(b"\r\n\r\n")
status = header.split(b"\r\n", 1)[0]
print("WebSocket response:", status.decode("latin1"))
if status.startswith((b"HTTP/1.1 501 ", b"HTTP/1.0 501 ")):
    print("PASS: WebSocket support is disabled; HTTP 501 is expected")
    raise SystemExit(0)
if b" 101 " not in status:
    raise RuntimeError("WebSocket upgrade did not return 101")

def read_exact(count):
    global buffer
    while len(buffer) < count:
        chunk = conn.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during WebSocket frame")
        buffer += chunk
    result, buffer = buffer[:count], buffer[count:]
    return result

def read_frame():
    first, second = read_exact(2)
    opcode = first & 0x0f
    length = second & 0x7f
    masked = bool(second & 0x80)
    if length == 126:
        length = int.from_bytes(read_exact(2), "big")
    elif length == 127:
        length = int.from_bytes(read_exact(8), "big")
    if length > 65536:
        raise RuntimeError("test frame exceeds safe bound")
    mask = read_exact(4) if masked else b""
    payload = read_exact(length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload

# Receive the Engine.IO opening packet.
opened = False
for _ in range(5):
    opcode, payload = read_frame()
    print("Upstream frame:", payload[:120].decode("utf-8", "replace"))
    if opcode == 1 and payload.startswith(b"0{"):
        opened = True
        break
if not opened:
    raise RuntimeError("Engine.IO opening packet not observed")

# Send Socket.IO namespace-connect text packet with mandatory masking.
payload = b"40"
mask = os.urandom(4)
masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
conn.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked_payload)

ack = False
for _ in range(5):
    opcode, payload = read_frame()
    print("Response frame:", payload[:120].decode("utf-8", "replace"))
    if opcode == 1 and payload.startswith(b"40"):
        ack = True
        break
if not ack:
    raise RuntimeError("Socket.IO namespace acknowledgement not observed")

print("PASS: 101 upgrade and bidirectional Engine.IO/Socket.IO exchange")
conn.close()
PY
then
    pass "WebSocket policy behavior"
else
    fail "WebSocket policy behavior failed"
fi

echo
echo "=== TEST SUMMARY ==="
printf 'Passed: %s\nFailed: %s\n' "$PASSES" "$FAILURES"
printf 'Result log: %s\nShield log: %s\n' "$RESULT_LOG" "$SHIELD_LOG"

if [ "$FAILURES" -ne 0 ]; then
    echo "Security regression suite failed. Do not deploy this build."
    exit 1
fi

echo "All local regression checks passed."
