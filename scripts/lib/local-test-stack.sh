#!/usr/bin/env bash
# Shared loopback-only fixture launcher for Quantum Shield integration tests.
set -Eeuo pipefail

qs_stack_init() {
    QS_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
    QS_BIN="$QS_ROOT/target/debug/qsctl"
    QS_UPSTREAM="$QS_ROOT/target/debug/examples/test_upstream"
    QS_CONFIG="$QS_ROOT/config.example.toml"
    QS_DOMAIN="app.example.com"
    QS_TMP="$(mktemp -d /tmp/qs-local-smoke.XXXXXX)"
    QS_UP_PID=""
    QS_PROXY_PID=""
    QS_OWN_UPSTREAM=0
    QS_OWN_PROXY=0
    QS_UP_LOG="$QS_TMP/upstream.log"
    QS_PROXY_LOG="$QS_TMP/proxy.log"
    trap qs_stack_cleanup EXIT

    for tool in cargo curl openssl ss; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "ERROR: required tool missing: $tool" >&2
            return 1
        }
    done
    [[ -f "$QS_CONFIG" ]] || {
        echo "ERROR: example configuration missing: $QS_CONFIG" >&2
        return 1
    }

    echo "Building the CLI and local test upstream..."
    cargo build --quiet --bin qsctl --example test_upstream
}

qs_stack_cleanup() {
    set +e
    for pid in "${QS_PROXY_PID:-}" "${QS_UP_PID:-}"; do
        [[ -n "$pid" ]] || continue
        kill -INT "$pid" 2>/dev/null
        for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -TERM "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    if [[ "${QS_TEST_KEEP_LOGS:-0}" == "1" && -n "${QS_TMP:-}" && -d "$QS_TMP" ]]; then
        echo "Test service logs: $QS_TMP"
    else
        [[ -z "${QS_TMP:-}" ]] || rm -rf -- "$QS_TMP"
    fi
}

qs_stack_upstream_ready() {
    curl --noproxy '*' --silent --fail --max-time 1 \
        -H "Host: $QS_DOMAIN" http://127.0.0.1:3000/ 2>/dev/null |
        grep -Fqx 'Quantum Shield Rust test upstream'
}

qs_stack_start_upstream() {
    if qs_stack_upstream_ready; then
        echo "Using the already-running expected test upstream on 127.0.0.1:3000."
        return 0
    fi
    if ss -ltn 'sport = :3000' | grep -q LISTEN; then
        echo "ERROR: port 3000 is occupied by an unexpected service; refusing to stop it." >&2
        return 1
    fi

    "$QS_UPSTREAM" >"$QS_UP_LOG" 2>&1 &
    QS_UP_PID=$!
    QS_OWN_UPSTREAM=1

    for _ in $(seq 1 50); do
        if qs_stack_upstream_ready; then
            echo "PASS: test upstream ready on 127.0.0.1:3000."
            return 0
        fi
        kill -0 "$QS_UP_PID" 2>/dev/null || break
        sleep 0.1
    done

    echo "ERROR: local test upstream failed to start." >&2
    cat "$QS_UP_LOG" >&2 || true
    return 1
}

qs_stack_check_free_port() {
    local port="$1"
    if ss -ltn "sport = :$port" | grep -q LISTEN; then
        echo "ERROR: test port $port is occupied; refusing to stop an unknown process." >&2
        return 1
    fi
}

qs_stack_start_http() {
    local port="${1:-18082}"
    qs_stack_check_free_port "$port" || return 1

    "$QS_BIN" serve-http "$QS_CONFIG" \
        --listen "127.0.0.1:$port" >"$QS_PROXY_LOG" 2>&1 &
    QS_PROXY_PID=$!
    QS_OWN_PROXY=1

    for _ in $(seq 1 60); do
        if curl --noproxy '*' --silent --fail --max-time 1 \
            -H "Host: $QS_DOMAIN" "http://127.0.0.1:$port/" 2>/dev/null |
            grep -Fqx 'Quantum Shield Rust test upstream'; then
            echo "PASS: HTTP proxy ready on 127.0.0.1:$port."
            return 0
        fi
        kill -0 "$QS_PROXY_PID" 2>/dev/null || break
        sleep 0.1
    done

    echo "ERROR: local HTTP proxy failed to start." >&2
    cat "$QS_PROXY_LOG" >&2 || true
    return 1
}

qs_stack_start_https() {
    local port="${1:-18443}"
    local cert="$QS_TMP/cert.pem"
    local key="$QS_TMP/key.pem"

    qs_stack_check_free_port "$port" || return 1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -sha256 -days 1 -nodes -keyout "$key" -out "$cert" \
        -subj "/CN=$QS_DOMAIN" \
        -addext "subjectAltName=DNS:$QS_DOMAIN" >/dev/null 2>&1
    chmod 600 "$key"

    "$QS_BIN" serve-https "$QS_CONFIG" \
        --listen "127.0.0.1:$port" --cert "$cert" --key "$key" \
        >"$QS_PROXY_LOG" 2>&1 &
    QS_PROXY_PID=$!
    QS_OWN_PROXY=1

    for _ in $(seq 1 60); do
        if curl --noproxy '*' --insecure --silent --fail --max-time 2 \
            --tlsv1.3 --tls-max 1.3 \
            --resolve "$QS_DOMAIN:$port:127.0.0.1" \
            "https://$QS_DOMAIN:$port/" 2>/dev/null |
            grep -Fqx 'Quantum Shield Rust test upstream'; then
            echo "PASS: HTTPS proxy ready on 127.0.0.1:$port (TLS 1.3)."
            return 0
        fi
        kill -0 "$QS_PROXY_PID" 2>/dev/null || break
        sleep 0.1
    done

    echo "ERROR: local HTTPS proxy failed to start." >&2
    cat "$QS_PROXY_LOG" >&2 || true
    return 1
}
