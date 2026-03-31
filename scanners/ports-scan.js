/**
 * Sentinel Audit — Port Scanner
 * Performs TCP connect scans against common ports on a target host.
 */

const net = require('net');

const DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 8080, 8443, 3000, 3001, 3306, 5000, 5432, 6379, 27017, 9200, 11211];

const PORT_INFO = {
  21: { service: 'FTP', severity: 'HIGH', cwe: 'CWE-200', reason: 'FTP transmits credentials in plaintext. Direct file access may be exposed.' },
  22: { service: 'SSH', severity: 'LOW', cwe: 'N/A', reason: 'SSH is generally secure but may be targeted for brute-force attacks if exposed to the internet.' },
  23: { service: 'Telnet', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'Telnet transmits all data, including passwords, in plaintext. Should never be exposed.' },
  25: { service: 'SMTP', severity: 'MEDIUM', cwe: 'CWE-200', reason: 'SMTP may expose mail relay capabilities. Ensure authentication is required.' },
  80: { service: 'HTTP', severity: 'MEDIUM', cwe: 'CWE-319', reason: 'HTTP does not encrypt traffic in transit. Should redirect to HTTPS.' },
  443: { service: 'HTTPS', severity: 'LOW', cwe: 'N/A', reason: 'HTTPS is expected for secure communication.' },
  8080: { service: 'HTTP-Alt', severity: 'HIGH', cwe: 'CWE-319', reason: 'HTTP alternative port often used for dev servers or proxies. May expose internal services.' },
  8443: { service: 'HTTPS-Alt', severity: 'MEDIUM', cwe: 'N/A', reason: 'HTTPS alternative port. Verify it serves valid TLS certificates.' },
  3000: { service: 'Node/Dev', severity: 'HIGH', cwe: 'CWE-200', reason: 'Common development server port. Often unauthenticated and exposed unintentionally.' },
  3001: { service: 'Node/Dev', severity: 'HIGH', cwe: 'CWE-200', reason: 'Common development server port. May expose unauthenticated dev tooling.' },
  3306: { service: 'MySQL', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'Database port exposed to the internet. Unauthorized access could lead to full data compromise.' },
  5000: { service: 'Dev Server', severity: 'HIGH', cwe: 'CWE-200', reason: 'Common Python/Flask/Node dev server. Usually unauthenticated.' },
  5432: { service: 'PostgreSQL', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'Database port exposed. Unauthorized access leads to full data compromise.' },
  6379: { service: 'Redis', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'Redis has no authentication by default. Remote access = full data/state compromise.' },
  27017: { service: 'MongoDB', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'MongoDB port exposed. Default installs have no auth. Full database compromise possible.' },
  9200: { service: 'Elasticsearch', severity: 'CRITICAL', cwe: 'CWE-200', reason: 'Elasticsearch often has no auth. Exposed cluster = data exfiltration and manipulation.' },
  11211: { service: 'Memcached', severity: 'HIGH', cwe: 'CWE-200', reason: 'Memcached has no auth. Can be abused for DDoS reflection attacks and data exposure.' },
};

const TIMEOUT_MS = 3000;

/**
 * Attempt TCP connection to a single port.
 * @param {string} host - Target hostname or IP
 * @param {number} port - Port number
 * @returns {Promise<boolean>} true if open, false if closed/timeout
 */
function checkPort(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(TIMEOUT_MS);

    socket.on('connect', () => {
      cleanup();
      resolve(true);
    });

    socket.on('timeout', () => {
      cleanup();
      resolve(false);
    });

    socket.on('error', () => {
      cleanup();
      resolve(false);
    });

    socket.connect(port, host);
  });
}

/**
 * Extract host from URL or use directly.
 */
function extractHost(target) {
  if (!target) return null;
  // If it's a URL, extract host
  try {
    const url = new URL(target.startsWith('http') ? target : 'https://' + target);
    return url.hostname;
  } catch {
    return target; // treat as raw hostname/IP
  }
}

/**
 * Scan target for open ports.
 * @param {string} target - URL or hostname
 * @param {object} config - Config with optional `ports` array
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(target, config) {
  const findings = [];

  const host = extractHost(target);
  if (!host) {
    findings.push({
      severity: 'INFO',
      title: 'Port Scan Skipped',
      description: 'No valid target hostname or IP provided.',
      remediation: 'Provide a hostname or IP address with --target flag.',
      cwe: 'N/A',
    });
    return findings;
  }

  const ports = (config && config.ports) || DEFAULT_PORTS;
  const openPorts = [];

  // Scan all ports in parallel with a concurrency limit
  const concurrency = 20;
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(batch.map((port) => checkPort(host, port)));
    for (let j = 0; j < batch.length; j++) {
      if (results[j]) openPorts.push(batch[j]);
    }
  }

  if (openPorts.length === 0) {
    findings.push({
      severity: 'INFO',
      title: 'No Open Ports Detected',
      description: `Scanned ${ports.length} common ports on ${host} — all appear closed or filtered.`,
      remediation: 'Confirm the target is reachable. Firewalls may be blocking the scan.',
      cwe: 'N/A',
    });
    return findings;
  }

  for (const port of openPorts) {
    const info = PORT_INFO[port] || { service: 'Unknown', severity: 'MEDIUM', cwe: 'CWE-200', reason: `Port ${port} is open.` };
    findings.push({
      severity: info.severity,
      title: `Open Port Detected: ${port}/TCP (${info.service})`,
      description: `${info.reason} Host: ${host}, Port: ${port}/TCP`,
      remediation: getRemediation(port, info),
      cwe: info.cwe,
    });
  }

  return findings;
}

function getRemediation(port, info) {
  const base = `Review whether port ${port} (${info.service}) needs to be exposed. `;
  switch (port) {
    case 21: return base + 'Disable FTP and use SFTP instead. Firewall off port 21 if not needed.';
    case 23: return base + 'Disable Telnet immediately. Use SSH for remote access.';
    case 3306: return base + 'Bind MySQL to localhost (127.0.0.1) or ensure firewall restricts access to authorized IPs only.';
    case 5432: return base + 'Set pg_hba.conf to reject remote connections or restrict to specific IPs. Use SSL.';
    case 6379: return base + 'Bind Redis to 127.0.0.1 or set `requirepass` and enable TLS.';
    case 27017: return base + 'Enable authentication (--auth flag) and bind to localhost or restrict via firewall.';
    case 9200: return base + 'Enable X-Pack security or a reverse proxy with authentication. Firewall off if not needed.';
    case 11211: return base + 'Bind to localhost or enable SASL authentication. Firewall off if not needed.';
    case 3000:
    case 3001:
    case 5000: return base + 'Dev server ports should not be exposed to the internet. Use a production web server with proper hardening.';
    case 8080: return base + 'Block port 8080 at the firewall unless intentionally serving a public service. Verify the service requires internet access.';
    default: return base + 'Verify this port needs to be internet-accessible. Apply principle of least privilege.';
  }
}

module.exports = { scan };
