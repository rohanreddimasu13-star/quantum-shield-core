#!/usr/bin/env bash
# Verify the built-in AI crawler/agent policy against a running shield.
#
# Defaults match the local demo listener:
#   QS_TEST_URL=https://127.0.0.1:18443/ QS_TEST_HOST=localhost
set -euo pipefail

BASE_URL="${QS_TEST_URL:-https://127.0.0.1:${QS_TEST_PORT:-18443}/}"
HOST_HEADER="${QS_TEST_HOST:-app.example.com}"
INSECURE="${QS_TEST_INSECURE:-1}"

# AI_AGENT_LOCAL_STACK_SETUP: create an isolated local test stack by default.
if [[ "${QS_TEST_EXTERNAL_SERVER:-0}" != "1" ]]; then
  ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
  source "$ROOT/scripts/lib/local-test-stack.sh"
  qs_stack_init

  # Set the agent identifiers for this test server process only.
  export QS_BLOCKED_USER_AGENTS="${QS_BLOCKED_USER_AGENTS:-GPTBot,ChatGPT-User,OAI-SearchBot,ClaudeBot,Claude-User,PerplexityBot,CCBot,Bytespider,Amazonbot,meta-externalagent,cohere-ai,Diffbot,YouBot,AI2Bot-Dolma,GoogleOther,LangChain,ARTEX,nuclei,sqlmap,HeadlessChrome,Playwright,Puppeteer,Selenium}"

  qs_stack_start_upstream
  qs_stack_start_https "${QS_TEST_PORT:-18443}"
fi


CURL=(curl --silent --show-error --max-time 10 -H "Host: $HOST_HEADER"
  --output /dev/null --write-out '%{http_code}')
if [[ "$INSECURE" == "1" && "$BASE_URL" == https://* ]]; then
  CURL+=(--insecure)
fi

PASSES=0
FAILURES=0

check() {
  local label="$1"
  local expected="$2"
  shift 2

  local actual
  if ! actual="$("${CURL[@]}" "$@" "$BASE_URL" 2>/dev/null)"; then
    actual=000
  fi
  if [[ "$actual" == "$expected" ]]; then
    printf 'PASS: %s (HTTP %s)\n' "$label" "$actual"
    PASSES=$((PASSES + 1))
  else
    printf 'FAIL: %s (expected HTTP %s, got %s)\n' "$label" "$expected" "$actual"
    FAILURES=$((FAILURES + 1))
  fi
}

printf 'Quantum Shield AI crawler/agent blocking suite\n'
printf 'Target: %s (Host: %s)\n\n' "$BASE_URL" "$HOST_HEADER"

AI_AGENTS=(
  'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)'
  'Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)'
  'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)'
  'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)'
  'Mozilla/5.0 (compatible; Claude-User/1.0; +https://www.anthropic.com)'
  'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)'
  'CCBot/2.0 (https://commoncrawl.org/faq/)'
  'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)'
  'Mozilla/5.0 (compatible; Amazonbot/0.1)'
  'Mozilla/5.0 (compatible; meta-externalagent/1.1)'
  'Mozilla/5.0 (compatible; cohere-ai)'
  'Mozilla/5.0 (compatible; Diffbot/1.0)'
  'Mozilla/5.0 (compatible; YouBot)'
  'Mozilla/5.0 (compatible; AI2Bot-Dolma)'
  'Mozilla/5.0 (compatible; GoogleOther)'
  'LangChain/0.1'
  'ARTEX/1.0'
  'Mozilla/5.0 (compatible; nuclei/3.0.0)'
  'sqlmap/1.7.2#stable (https://sqlmap.org)'
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0 Safari/537.36'
  'Mozilla/5.0 (X11; Linux x86_64) Playwright/1.40.0'
  'Mozilla/5.0 (X11; Linux x86_64) Puppeteer/21.0.0'
  'Mozilla/5.0 (X11; Linux x86_64) Selenium/4.15.0'
)

for user_agent in "${AI_AGENTS[@]}"; do
  check "AI agent blocked: ${user_agent:0:52}" 403 -H "User-Agent: $user_agent"
done

printf '\n'
check "Normal Chrome browser allowed" 200 -H \
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
check "Normal Firefox browser allowed" 200 -H \
  'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
check "Search crawler Googlebot still allowed" 200 -H \
  'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

POLICY_HEADER="$(curl --silent --show-error --max-time 10 --insecure \
  -H "Host: $HOST_HEADER" -H 'User-Agent: GPTBot/1.2' \
  --dump-header - --output /dev/null "$BASE_URL" 2>/dev/null \
  | tr -d '\r' \
  | awk -F': ' 'tolower($1) == "x-quantum-shield-policy" { print $2 }')"
if [[ "$POLICY_HEADER" == "ai-agent-blocked" ]]; then
  printf 'PASS: blocked response advertises x-quantum-shield-policy\n'
  PASSES=$((PASSES + 1))
else
  printf 'FAIL: expected x-quantum-shield-policy: ai-agent-blocked, got %q\n' "$POLICY_HEADER"
  FAILURES=$((FAILURES + 1))
fi

printf '\nPassed: %s\nFailed: %s\n' "$PASSES" "$FAILURES"
if [[ "$FAILURES" -ne 0 ]]; then
  echo 'AI agent blocking suite failed.'
  exit 1
fi
echo 'All AI agent blocking checks passed.'
