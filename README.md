# 🛡️ Sentinel Audit

**CLI pre-penetration-test security audit tool**

Sentinel Audit runs automated security checks against a target (live URL, hostname, or local codebase) and outputs prioritized findings in Markdown and JSON format.

## Installation

```bash
git clone https://github.com/meo68gto/sentinel-audit.git
cd sentinel-audit
npm install
```

## Usage

```bash
# Scan a live URL (headers, ports, SSL, auth)
node cli.js scan --target https://myapp.com

# Scan a live URL with local code analysis (all 6 scanners)
node cli.js scan --target https://myapp.com --dir ./src

# Output as JSON
node cli.js scan --target https://myapp.com --format json --output output/report.json

# Scan a local codebase only
node cli.js scan --target localhost --dir ./src
```

## Scanners

| Scanner | What it checks |
|---------|---------------|
| **headers-scan** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **ports-scan** | TCP connect on common ports (21, 22, 80, 443, 3306, 5432, 6379, 27017, etc.) |
| **ssl-scan** | TLS certificate expiry, weak ciphers, self-signed certs, HTTPS redirect |
| **auth-scan** | Basic/Bearer auth over HTTP, tokens in URL, missing cookie flags |
| **dependency-scan** | `npm audit` findings from local package.json |
| **secrets-scan** | Gitleaks-style regex patterns for API keys, tokens, private keys in local files |

## Severity Rankings

Every finding is ranked: **CRITICAL → HIGH → MEDIUM → LOW → INFO**

Each finding includes:
- `severity` — CRITICAL/HIGH/MEDIUM/LOW/INFO
- `title` — Short finding name
- `description` — What the issue is
- `remediation` — How to fix it
- `cwe` — CWE reference number

## Output

Reports are saved to `output/` with timestamps:

```
output/
├── sentinel-audit-2026-03-30T14-00-00.md
└── sentinel-audit-2026-03-30T14-00-00.json
```

## License

MIT — Michael Ortiz (Batcave)
