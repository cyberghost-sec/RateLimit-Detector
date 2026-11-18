# RateLimit-Detector

A lightweight Bash tool for **authorized, defensive** black-box checks of HTTP rate-limiting behavior in modern web applications and APIs.

It sends a small, configurable number of sequential requests to one URL and inspects HTTP status codes and common rate-limit response headers. It is intended to help security analysts document whether a target visibly signals throttling during a controlled assessment.

> **Authorization required:** Only test systems you own or have explicit written permission to assess. Prefer staging environments. Even a small number of requests can trigger account lockouts, alerts, or service-side side effects.

## Features

- Detects HTTP `429 Too Many Requests`.
- Recognizes common headers such as `Retry-After`, `RateLimit-*`, `X-RateLimit-*`, and `X-Rate-Limit-*`.
- Records HTTP status codes and average response time.
- Sequential requests only; no concurrency.
- Configurable request count, delay, timeout, method, and request headers.
- JSON report suitable for assessment evidence and CI artifact storage.
- Input validation, bounded request count, cleanup of temporary files, and clear exit errors.

## Requirements

- Bash 4+
- `curl`
- `jq`
- Standard Unix utilities: `awk`, `grep`, `sed`, `tr`, `mktemp`, `sleep`

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y curl jq
```

macOS (Homebrew):

```bash
brew install curl jq
```

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/RateLimit-Detector.git
cd RateLimit-Detector
chmod +x rate-limit-detector.sh
```

Replace `YOUR_USERNAME` with your GitHub username after creating the repository.

## Usage

```bash
./rate-limit-detector.sh --url https://staging.example.com/login
```

### Options

| Option | Description | Default |
|---|---|---|
| `-u`, `--url` | Target URL (required; HTTP or HTTPS) | — |
| `-n`, `--requests` | Number of sequential requests (1–30) | `12` |
| `-d`, `--delay` | Delay between requests, seconds (0.5–60) | `1` |
| `-t`, `--timeout` | Per-request timeout, seconds (1–120) | `10` |
| `-m`, `--method` | `GET`, `HEAD`, or `OPTIONS` | `GET` |
| `-H`, `--header` | Additional request header; repeatable | — |
| `-o`, `--output` | Save JSON report to a file | stdout only |
| `--user-agent` | Set User-Agent | `RateLimit-Detector/1.0.0` |
| `-h`, `--help` | Display help | — |

### Examples

Conservative baseline:

```bash
./rate-limit-detector.sh \
  --url https://staging.example.com/api/profile \
  --requests 6 \
  --delay 2
```

Save evidence as JSON:

```bash
./rate-limit-detector.sh \
  --url https://staging.example.com/login \
  --requests 10 \
  --delay 2 \
  --output rate-limit-report.json
```

Include a non-secret header:

```bash
./rate-limit-detector.sh \
  --url https://staging.example.com/api/status \
  --header "Accept: application/json"
```

Check an OPTIONS route:

```bash
./rate-limit-detector.sh \
  --url https://staging.example.com/api/ \
  --method OPTIONS
```

## Interpreting results

| Verdict | Meaning |
|---|---|
| `RATE_LIMITING_DETECTED` | At least one response returned HTTP 429. |
| `RATE_LIMIT_SIGNALS_FOUND` | Recognized rate-limit headers were observed, but no 429 occurred. |
| `NO_RATE_LIMIT_EVIDENCE` | No recognized signal was observed in this test window. This is not proof that rate limiting is absent. |

A `403` or `503` is recorded as an HTTP error but is **not** automatically classified as rate limiting: those statuses can have many causes.

### Important testing limitations

- This is a black-box indicator, not a full rate-limit validation framework.
- The scanner sends the same request repeatedly. It does not submit login credentials, change passwords, or attempt account access.
- Only `GET`, `HEAD`, and `OPTIONS` are supported to reduce the chance of state-changing actions. Many login and password-reset routes accept `POST`; assess those with a purpose-built staging test harness and test accounts, not by pointing this tool at production.
- A server may rate-limit by account, IP, session, API key, route, device, or a combination. This scanner tests only the request context you provide.
- A reverse proxy, CDN, WAF, or gateway may generate the observed response rather than the application itself.
- Header names and semantics vary by implementation. The script recognizes common conventions but cannot understand every proprietary format.
- Redirects are followed up to three times. The final response status and response headers are used.
- A successful response does not establish that brute-force protection is missing. Confirm with server-side configuration, logs, and controlled integration tests.

## Recommended defensive controls

For authentication and other sensitive routes, consider layered controls:

1. Apply throttling by multiple dimensions (account identifier, source IP, session, API key, and route) rather than relying on IP alone.
2. Use progressive delays and carefully designed temporary lockouts; avoid permanent lockout designs that enable denial of service against victims.
3. Return consistent, non-enumerating authentication errors.
4. Use MFA or passkeys where appropriate.
5. Monitor bursts, distributed attempts, password-reset abuse, and unusual failure ratios.
6. Ensure limits are enforced at the application or trusted gateway layer and are consistent across horizontally scaled instances.
7. Test legitimate-user impact, proxy behavior, IPv4/IPv6 handling, and shared NAT scenarios.
8. Log throttling decisions and alert on suspicious patterns without logging passwords, tokens, or other secrets.

## Sample report shape

The JSON output includes:

- Target and method
- Requested and completed request counts
- Delay and timeout
- Observed HTTP status codes
- HTTP 429 and other HTTP error counts
- Average response time
- Whether rate-limit headers and `Retry-After` were seen
- Overall verdict and explanatory note

Do not publish reports containing internal hostnames, session identifiers, tokens, or other sensitive assessment data.

## Exit behavior

- `0`: Test completed and a report was produced (regardless of verdict).
- Non-zero: Invalid input, missing dependency, or another execution/reporting error.

## Responsible use

This project is intended for defensive testing, education, and authorized security assessments. You are responsible for obtaining permission, defining an acceptable test window, and ensuring that the test does not disrupt service or lock out users.

## Contributing

Issues and pull requests are welcome. Please include reproducible test cases and avoid submitting sensitive target information.

## License

MIT. See [LICENSE](LICENSE).
