# Sentinel Audit

**Automated pre-penetration-test security audit tool**

Sentinel Audit runs a battery of automated security checks against a target — URL, codebase, or host — before a formal pen test engagement. It surfaces findings in prioritized, actionable reports so pen testers land on real vulnerabilities instead of low-hanging fruit.

---

## What It Does

Sentinel runs **6 core security scanners** against every target:

| Scanner | What It Checks |
|---------|---------------|
| **dependency-scanner** | Known CVEs in npm/pip packages via `npm audit` / `pip audit` |
| **secrets-scanner** | Hardcoded API keys, tokens, passwords, private keys via gitleaks + regex |
| **headers-scanner** | HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **ports-scanner** | Exposed network ports: SSH, RDP, databases, admin panels |
| **auth-scanner** | JWT analysis (alg:none, missing exp), rate limiting, Basic Auth over HTTP |
| **ssl-scanner** | Certificate expiry, weak ciphers, hostname mismatch, deprecated TLS versions |

---

## Why

Most security debt accumulates between pen tests. Sentinel closes that gap by running the same checks that catch the most common high-severity findings — every commit, every deploy, every sprint.

---

## Installation

```bash
npm install -g sentinel-audit
```

Requires: Node.js >= 18.0.0

For full secrets scanning, install gitleaks:
```bash
# macOS
brew install gitleaks

# Linux
sudo apt install gitleaks
```

For full port scanning, install nmap (optional):
```bash
# macOS
brew install nmap

# Linux
sudo apt install nmap
```

---

## CLI Usage

```bash
# Scan a live URL
sentinel-audit scan --target https://api.myapp.com

# Scan a codebase directory
sentinel-audit scan --target ./src --format markdown -o findings.md

# Scan a URL with JSON output (CI/CD friendly)
sentinel-audit scan --target https://api.myapp.com --format json -o findings.json

# Run specific scanners only
sentinel-audit scan --target https://api.myapp.com --scopes headers,ssl

# Scan a directory with all checks
sentinel-audit scan --target ./ --dir ./src -o output/report.md
```

### Options

| Flag | Description |
|------|-------------|
| `--target, -t` | Target: URL, directory path, or host |
| `--dir, -d` | Directory path (for dependency/secrets scanners) |
| `--output, -o` | Output file path |
| `--format, -f` | Output format: `json` or `markdown` (default: markdown) |
| `--scopes, -s` | Comma-separated scanner IDs to run |
| `--min-severity` | Minimum severity to report |
| `--no-color` | Disable colored output |
| `--verbose` | Show verbose output |

### List Available Scanners

```bash
sentinel-audit list
```

---

## Output Formats

### Markdown (default)

Generated report includes:
- Executive summary with risk score (0-100)
- Findings grouped by severity (Critical → Info)
- Per-finding: description, evidence, CWE, CVSS score, remediation steps
- Scanner execution summary

### JSON (CI/CD)

SARIF-compatible JSON output, ready for:
- GitHub Code Scanning upload
- DefectDojo integration
- Custom dashboards

---

## Checks Performed

### Dependency CVE Scan
- Runs `npm audit --json` on Node.js projects
- Runs `pip audit --json` on Python projects
- Maps npm/pip severity to CVSS scores
- Prioritizes findings by exploitability

### Secrets & Credential Leak Detection
- gitleaks full git history scan (all branches, all commits)
- Regex patterns for: AWS keys, GitHub tokens, Stripe keys, Slack tokens, private keys, database connection strings, JWTs
- Per-file regex scan for unstaged secrets
- Evidence includes file path and line number

### Security Headers Audit
| Header | Expected |
|--------|----------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `Content-Security-Policy` | No `unsafe-inline` / `unsafe-eval` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | At minimum disables unused features |
| `X-Powered-By` | **Absent** (information disclosure) |
| `Server` | **Absent** or generic |

### Network Ports Scan
Scans 50+ common ports. Critical findings:
- Port 22/3389/5900 without IP allowlist
- Ports 1433/3306/5432/27017/6379 (databases) without auth
- Port 9200 (Elasticsearch) without auth
- Port 23 (Telnet), Port 445 (SMB) exposed

### Authentication Security
- **JWT analysis**: alg:none bypass, missing exp/iat claims, weak HS256 secrets, kid path traversal
- **Rate limiting**: brute-force probe on login endpoints (20 rapid requests)
- **Basic Auth over HTTP**: credentials transmitted in cleartext
- **Missing WWW-Authenticate** on 401 responses

### SSL/TLS Certificate Validation
- Certificate expired or expires < 30 days
- Weak RSA key (< 2048 bits) or EC key (< 256 bits)
- TLS 1.0/1.1 enabled (deprecated)
- SSLv2/SSLv3 enabled (critical)
- Weak cipher suites (RC4, 3DES, NULL)
- Hostname mismatch
- Self-signed certificate

---

## Configuration

Edit `config/default.json` to:
- Set per-scanner timeouts
- Configure which scanners are enabled by default
- Set severity thresholds for CI/CD gate decisions
- Configure port exclusion lists

---

## Severity & Risk Scoring

| Level | CVSS Range | CI/CD Gate |
|-------|-----------|------------|
| Critical | 9.0–10.0 | Block deploy |
| High | 7.0–8.9 | Block deploy |
| Medium | 4.0–6.9 | Warn |
| Low | 0.1–3.9 | Log |
| Info | 0.0 | Log only |

**Risk Score (0–100):** Composite score based on finding count and severity. 50+ = critical risk, do not deploy.

---

## Architecture

```
sentinel-audit/
├── cli.js                  ← Commander.js CLI entry point
├── core/
│   ├── scanner-engine.js   ← Parallel scanner runner
│   ├── findings.js         ← Findings aggregator, deduplication, sorting
│   ├── severity.js         ← CVSS/CWE severity scoring
│   └── types.js            ← Shared TypeScript-like types
├── scanners/
│   ├── dependency-scanner.js   ← npm/pip audit
│   ├── secrets-scanner.js      ← gitleaks + regex
│   ├── headers-scanner.js      ← HTTP security headers
│   ├── ports-scanner.js        ← TCP port scan
│   ├── auth-scanner.js          ← JWT + rate limiting
│   └── ssl-scanner.js          ← TLS certificate check
├── reporter/
│   ├── json-reporter.js     ← JSON output
│   └── markdown-reporter.js ← Markdown report
├── config/
│   └── default.json         ← Default configuration
└── output/                  ← Generated reports
```

---

## License

MIT — Michael Ortiz / Batcave
