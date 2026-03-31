# Sentinel Audit Report

**Scan ID:** `scan_20260331042819`
**Target:** https://example.com
**Type:** url
**Timestamp:** 2026-03-31T04:28:26.047Z
**Duration:** 6.0s
**Risk Score:** 47/100

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High     | 3 |
| 🟡 Medium   | 3 |
| 🟢 Low      | 5 |
| 🔵 Info     | 0 |

**Total Findings:** 11

**Risk Level:** 🟠 HIGH
**Advice:** High risk. Block deployment until critical findings resolved.

---

## Detailed Findings

### 🟠 HIGH (3)

#### 1. Strict-Transport-Security: Header missing — HTTPS downgrades possible

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-001` |
| **Scanner** | headers |
| **Severity** | HIGH |
| **CWE** | CWE-523 |
| **CVSS** | 8.9 |
| **Target** | https://example.com |

**Description:**

Header missing — HTTPS downgrades possible

**Evidence:**

```
{
  "header": "Strict-Transport-Security",
  "actualValue": "(not set)"
}
```

**Remediation:**

Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

---

#### 2. Content-Security-Policy: CSP missing — XSS and data injection possible

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-003` |
| **Scanner** | headers |
| **Severity** | HIGH |
| **CWE** | CWE-346 |
| **CVSS** | 8.9 |
| **Target** | https://example.com |

**Description:**

CSP missing — XSS and data injection possible

**Evidence:**

```
{
  "header": "Content-Security-Policy",
  "actualValue": "(not set)"
}
```

**Remediation:**

Define strict CSP: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'

---

#### 3. No rate limiting on /login

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-007` |
| **Scanner** | auth |
| **Severity** | HIGH |
| **CWE** | CWE-307 |
| **CVSS** | 7.5 |
| **Target** | https://example.com/login |

**Description:**

Sent 20 rapid POST requests without any rate limiting response (no 429, no lockout). Enables unlimited brute-force attacks.

**Evidence:**

```
{
  "endpoint": "https://example.com/login",
  "requestsSent": 20,
  "responses": [
    {
      "status": 405,
      "i": 0
    },
    {
      "status": 405,
      "i": 1
    },
    {
      "status": 405,
      "i": 2
    },
    {
      "status": 405,
      "i": 3
    },
    {
      "status": 405,
      "i": 4
    }
  ]
}
```

**Remediation:**

Implement rate limiting: 5 attempts per minute per IP for login endpoints. Return 429 with Retry-After header.

---

### 🟡 MEDIUM (3)

#### 1. X-Frame-Options: Header missing — clickjacking possible

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-002` |
| **Scanner** | headers |
| **Severity** | MEDIUM |
| **CWE** | CWE-346 |
| **CVSS** | 6.9 |
| **Target** | https://example.com |

**Description:**

Header missing — clickjacking possible

**Evidence:**

```
{
  "header": "X-Frame-Options",
  "actualValue": "(not set)"
}
```

**Remediation:**

Set: X-Frame-Options: DENY

---

#### 2. Port 8080 (HTTP-Alt) is open

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-010` |
| **Scanner** | ports |
| **Severity** | MEDIUM |
| **CWE** | CWE-200 |
| **CVSS** | 6.9 |
| **Target** | example.com:8080 |

**Description:**

Often dev/debug interfaces — review if intentional

**Evidence:**

```
{
  "host": "example.com",
  "ip": "104.18.26.120",
  "port": 8080,
  "service": "HTTP-Alt"
}
```

**Remediation:**

Database port 8080 must NEVER be internet-facing. Bind to 127.0.0.1 or internal network.

---

#### 3. Port 8443 (HTTPS-Alt) is open

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-011` |
| **Scanner** | ports |
| **Severity** | MEDIUM |
| **CWE** | CWE-200 |
| **CVSS** | 6.9 |
| **Target** | example.com:8443 |

**Description:**

Often admin/debug interfaces — verify TLS certs

**Evidence:**

```
{
  "host": "example.com",
  "ip": "104.18.26.120",
  "port": 8443,
  "service": "HTTPS-Alt"
}
```

**Remediation:**

Database port 8443 must NEVER be internet-facing. Bind to 127.0.0.1 or internal network.

---

### 🟢 LOW (5)

#### 1. X-Content-Type-Options: Invalid value "undefined" — must be "nosniff"

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-004` |
| **Scanner** | headers |
| **Severity** | LOW |
| **CWE** | CWE-693 |
| **CVSS** | 3.9 |
| **Target** | https://example.com |

**Description:**

Invalid value "undefined" — must be "nosniff"

**Evidence:**

```
{
  "header": "X-Content-Type-Options",
  "actualValue": "(not set)"
}
```

**Remediation:**

Set: X-Content-Type-Options: nosniff

---

#### 2. Referrer-Policy: Referrer-Policy missing — referrer leaks possible

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-005` |
| **Scanner** | headers |
| **Severity** | LOW |
| **CWE** | CWE-688 |
| **CVSS** | 3.9 |
| **Target** | https://example.com |

**Description:**

Referrer-Policy missing — referrer leaks possible

**Evidence:**

```
{
  "header": "Referrer-Policy",
  "actualValue": "(not set)"
}
```

**Remediation:**

Set: Referrer-Policy: strict-origin-when-cross-origin

---

#### 3. Permissions-Policy: Permissions-Policy missing — unused browser features accessible

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-006` |
| **Scanner** | headers |
| **Severity** | LOW |
| **CWE** | CWE-693 |
| **CVSS** | 3.9 |
| **Target** | https://example.com |

**Description:**

Permissions-Policy missing — unused browser features accessible

**Evidence:**

```
{
  "header": "Permissions-Policy",
  "actualValue": "(not set)"
}
```

**Remediation:**

Set Permissions-Policy to disable unused features: geolocation=(), camera=(), microphone=()

---

#### 4. Port 80 (HTTP) is open

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-008` |
| **Scanner** | ports |
| **Severity** | LOW |
| **CWE** | CWE-200 |
| **CVSS** | 3.9 |
| **Target** | example.com:80 |

**Description:**

Unencrypted web traffic; should redirect to HTTPS

**Evidence:**

```
{
  "host": "example.com",
  "ip": "104.18.26.120",
  "port": 80,
  "service": "HTTP"
}
```

**Remediation:**

Review whether port 80 needs to be internet-facing. If not, block it via firewall.

---

#### 5. Port 443 (HTTPS) is open

| Field | Value |
|-------|-------|
| **ID** | `SENTINEL-009` |
| **Scanner** | ports |
| **Severity** | LOW |
| **CWE** | CWE-200 |
| **CVSS** | 3.9 |
| **Target** | example.com:443 |

**Description:**

Check SSL/TLS separately

**Evidence:**

```
{
  "host": "example.com",
  "ip": "104.18.26.120",
  "port": 443,
  "service": "HTTPS"
}
```

**Remediation:**

Review whether port 443 needs to be internet-facing. If not, block it via firewall.

---


## Scanner Execution Summary

| Scanner | Status | Duration | Findings |
|---------|--------|----------|----------|
| Authentication Security Scanner | ✅ complete | 0.3s | 1 |
| Dependency CVE Scanner | ✅ complete | 0.0s | 0 |
| Security Headers Scanner | ✅ complete | 0.1s | 6 |
| Network Ports Scanner | ✅ complete | 6.0s | 4 |
| Secrets & Credential Scanner | ✅ complete | 0.0s | 0 |
| SSL/TLS Certificate Scanner | ✅ complete | 0.0s | 0 |

---

*Generated by Sentinel Audit v1.0.0 — Batcave Security*
*Report date: 2026-03-31T04:28:26.050Z*