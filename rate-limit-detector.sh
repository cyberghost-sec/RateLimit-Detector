#!/usr/bin/env bash
# RateLimit-Detector: bounded, sequential HTTP rate-limit assessment.
# Use only against systems you own or are explicitly authorized to test.
set -Eeuo pipefail

VERSION="1.0.0"
URL=""
REQUESTS=12
DELAY=1
TIMEOUT=10
METHOD="GET"
OUTPUT=""
USER_AGENT="RateLimit-Detector/${VERSION}"
CURL_EXTRA_ARGS=()

usage() {
  cat <<'EOF'
RateLimit-Detector - defensive HTTP rate-limit assessment

Usage:
  ./rate-limit-detector.sh --url https://example.com/login [options]

Required:
  -u, --url URL             Target URL (http:// or https://)

Options:
  -n, --requests N          Number of sequential requests (default: 12; max: 30)
  -d, --delay SECONDS       Delay between requests (default: 1; min: 0.5)
  -t, --timeout SECONDS     Per-request timeout (default: 10)
  -m, --method METHOD       GET, HEAD, or OPTIONS (default: GET)
  -H, --header HEADER       Add a request header; may be repeated
  -o, --output FILE         Write JSON report to FILE
      --user-agent VALUE    Set User-Agent
  -h, --help                Show this help

Examples:
  ./rate-limit-detector.sh -u https://example.com/api/profile
  ./rate-limit-detector.sh -u https://example.com/login -n 10 -d 2 -o report.json
  ./rate-limit-detector.sh -u https://example.com/health -m HEAD

Safety:
  * Requests are sequential and deliberately bounded (maximum 30).
  * No credentials, payload mutation, concurrency, evasion, or bypass attempts.
  * Start with a staging environment and obtain written authorization.
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*" >&2; }

while (($#)); do
  case "$1" in
    -u|--url) [[ $# -ge 2 ]] || die "Missing value for $1"; URL="$2"; shift 2 ;;
    -n|--requests) [[ $# -ge 2 ]] || die "Missing value for $1"; REQUESTS="$2"; shift 2 ;;
    -d|--delay) [[ $# -ge 2 ]] || die "Missing value for $1"; DELAY="$2"; shift 2 ;;
    -t|--timeout) [[ $# -ge 2 ]] || die "Missing value for $1"; TIMEOUT="$2"; shift 2 ;;
    -m|--method) [[ $# -ge 2 ]] || die "Missing value for $1"; METHOD="${2^^}"; shift 2 ;;
    -H|--header) [[ $# -ge 2 ]] || die "Missing value for $1"; CURL_EXTRA_ARGS+=(-H "$2"); shift 2 ;;
    -o|--output) [[ $# -ge 2 ]] || die "Missing value for $1"; OUTPUT="$2"; shift 2 ;;
    --user-agent) [[ $# -ge 2 ]] || die "Missing value for $1"; USER_AGENT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ -n "$URL" ]] || { usage >&2; die "A target URL is required."; }
[[ "$URL" =~ ^https?://[^[:space:]]+$ ]] || die "URL must begin with http:// or https:// and contain no spaces."
command -v curl >/dev/null 2>&1 || die "curl is required."
command -v jq >/dev/null 2>&1 || die "jq is required for JSON reporting."
[[ "$REQUESTS" =~ ^[0-9]+$ ]] || die "--requests must be an integer."
(( REQUESTS >= 1 && REQUESTS <= 30 )) || die "--requests must be between 1 and 30."
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && (( TIMEOUT >= 1 && TIMEOUT <= 120 )) || die "--timeout must be an integer from 1 to 120."
[[ "$DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--delay must be a number."
awk -v d="$DELAY" 'BEGIN { exit !(d >= 0.5 && d <= 60) }' || die "--delay must be between 0.5 and 60 seconds."
case "$METHOD" in GET|HEAD|OPTIONS) ;; *) die "Only GET, HEAD, and OPTIONS are supported." ;; esac

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
: > "$TMP_DIR/statuses"
: > "$TMP_DIR/times"
: > "$TMP_DIR/header_hits"

log "RateLimit-Detector v${VERSION}"
log "Target: ${URL}"
log "Method: ${METHOD} | Requests: ${REQUESTS} | Delay: ${DELAY}s"
log "Sending bounded sequential requests..."

rate_header_seen=false
retry_after_seen=false
rate_limit_statuses=0
http_errors=0
completed=0
total_time=0

for ((i=1; i<=REQUESTS; i++)); do
  headers_file="$TMP_DIR/headers_${i}.txt"
  body_file="$TMP_DIR/body_${i}.txt"

  curl_args=(--silent --show-error --location --max-redirs 3
    --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT"
    --request "$METHOD" --user-agent "$USER_AGENT"
    --dump-header "$headers_file" --output "$body_file"
    --write-out '%{http_code} %{time_total}'
    "${CURL_EXTRA_ARGS[@]}" "$URL")

  if ! result="$(curl "${curl_args[@]}" 2>"$TMP_DIR/curl_error")"; then
    log "Request ${i}/${REQUESTS}: transport error ($(tr '\n' ' ' < "$TMP_DIR/curl_error"))"
    printf '000 0\n' >> "$TMP_DIR/statuses"
    printf '0\n' >> "$TMP_DIR/times"
  else
    status="${result%% *}"
    elapsed="${result#* }"
    [[ "$status" =~ ^[0-9]{3}$ ]] || status="000"
    [[ "$elapsed" =~ ^[0-9]+([.][0-9]+)?$ ]] || elapsed="0"
    printf '%s\n' "$status" >> "$TMP_DIR/statuses"
    printf '%s\n' "$elapsed" >> "$TMP_DIR/times"
    completed=$((completed + 1))
    total_time="$(awk -v a="$total_time" -v b="$elapsed" 'BEGIN { printf "%.6f", a+b }')"

    if [[ "$status" == "429" ]]; then
      rate_limit_statuses=$((rate_limit_statuses + 1))
      log "Request ${i}/${REQUESTS}: HTTP ${status} - rate limit response"
    else
      log "Request ${i}/${REQUESTS}: HTTP ${status} (${elapsed}s)"
      if [[ "$status" =~ ^(4|5)[0-9][0-9]$ ]]; then http_errors=$((http_errors + 1)); fi
    fi
  fi

  if [[ -s "$headers_file" ]]; then
    if grep -Eiq '^[[:space:]]*(ratelimit-|x-ratelimit-|x-rate-limit-)' "$headers_file"; then
      rate_header_seen=true
    fi
    if grep -Eiq '^[[:space:]]*retry-after[[:space:]]*:' "$headers_file"; then
      retry_after_seen=true
    fi
    grep -Eih '^[[:space:]]*(ratelimit-[^:]*|x-ratelimit-[^:]*|x-rate-limit-[^:]*|retry-after)[[:space:]]*:' "$headers_file" \
      | tr -d '\r' >> "$TMP_DIR/header_hits" || true
  fi

  if (( i < REQUESTS )); then sleep "$DELAY"; fi
done

avg_time="$(awk -v t="$total_time" -v n="$completed" 'BEGIN { if(n>0) printf "%.4f",t/n; else print "0" }')"
status_429="$rate_limit_statuses"
if (( rate_limit_statuses > 0 )); then
  verdict="RATE_LIMITING_DETECTED"
  explanation="The server returned HTTP 429 for one or more requests."
elif [[ "$rate_header_seen" == true || "$retry_after_seen" == true ]]; then
  verdict="RATE_LIMIT_SIGNALS_FOUND"
  explanation="Rate-limit-related response headers were observed, but no HTTP 429 was returned."
else
  verdict="NO_RATE_LIMIT_EVIDENCE"
  explanation="No HTTP 429 or recognized rate-limit response headers were observed during this bounded test. This does not prove that rate limiting is absent."
fi

header_json="$(jq -Rsc 'split("\n") | map(select(length > 0))' < "$TMP_DIR/header_hits")"
status_json="$(jq -Rsc 'split("\n") | map(select(length > 0)) | map(tonumber)' < "$TMP_DIR/statuses")"
report="$(jq -n \
  --arg tool "RateLimit-Detector" --arg version "$VERSION" \
  --arg target "$URL" --arg method "$METHOD" \
  --arg verdict "$verdict" --arg explanation "$explanation" \
  --argjson requested "$REQUESTS" --argjson completed "$completed" \
  --argjson delay "$DELAY" --argjson timeout "$TIMEOUT" \
  --argjson rate429 "$status_429" --argjson errors "$http_errors" \
  --argjson average "$avg_time" --argjson rate_headers "$rate_header_seen" \
  --argjson retry_after "$retry_after_seen" \
  --argjson statuses "$status_json" --argjson headers "$header_json" \
  '{tool:$tool,version:$version,target:$target,method:$method,
    test:{requests_requested:$requested,requests_completed:$completed,delay_seconds:$delay,timeout_seconds:$timeout},
    results:{verdict:$verdict,explanation:$explanation,http_statuses:$statuses,http_429_count:$rate429,http_error_count:$errors,average_response_time_seconds:$average,rate_limit_headers_seen:$rate_headers,retry_after_seen:$retry_after,observed_rate_limit_headers:$headers},
    note:"A limited black-box test is indicative, not proof. Validate controls with application-side logs and tests."}')"

printf '%s\n' "$report" | jq .
if [[ -n "$OUTPUT" ]]; then
  printf '%s\n' "$report" | jq . > "$OUTPUT" || die "Could not write report to $OUTPUT"
  log "JSON report written to: $OUTPUT"
fi

log "Verdict: ${verdict}"
