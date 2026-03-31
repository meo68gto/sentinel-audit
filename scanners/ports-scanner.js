/**
 * Sentinel Audit — Ports Scanner
 * Scans common TCP ports to detect exposed services
 * Uses native Node.js net module (no nmap required)
 */

const net = require('net');
const dns = require('dns');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'ports';
const SCANNER_NAME = 'Network Ports Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-PORT-${String(findingCounter).padStart(3, '0')}`;
}

// Top 50 critical ports to scan
const PORTS = [
  { port: 21,    name: 'FTP',          severity: 'high',   reason: 'Unencrypted file transfer — credentials and files exposed' },
  { port: 22,    name: 'SSH',          severity: 'medium', reason: 'If exposed to internet without IP allowlist, brute-force risk' },
  { port: 23,    name: 'Telnet',       severity: 'critical', reason: 'Unencrypted — all traffic including passwords visible' },
  { port: 25,    name: 'SMTP',         severity: 'medium', reason: 'Open relay risk; unencrypted email transmission' },
  { port: 53,    name: 'DNS',          severity: 'medium', reason: 'DNS amplification attacks; zone transfer if misconfigured' },
  { port: 80,    name: 'HTTP',         severity: 'low',    reason: 'Unencrypted web traffic; should redirect to HTTPS' },
  { port: 110,   name: 'POP3',         severity: 'high',   reason: 'Unencrypted email retrieval — credentials exposed' },
  { port: 135,   name: 'MSRPC',        severity: 'high',   reason: 'Windows RPC endpoint — used in lateral movement' },
  { port: 139,   name: 'NetBIOS',      severity: 'high',   reason: 'SMB/netbios — lateral movement and data exfil risk' },
  { port: 143,   name: 'IMAP',         severity: 'high',   reason: 'Unencrypted email — credentials exposed' },
  { port: 443,   name: 'HTTPS',        severity: 'low',    reason: 'Check SSL/TLS separately (ssl-scanner)' },
  { port: 445,   name: 'SMB',          severity: 'critical', reason: 'EternalBlue, SMBleed — remote code execution risk' },
  { port: 465,   name: 'SMTPS',        severity: 'medium', reason: 'Encrypted SMTP submission' },
  { port: 587,   name: 'SMTP-Sub',     severity: 'medium', reason: 'Email submission port — check auth requirements' },
  { port: 993,   name: 'IMAPS',        severity: 'low',    reason: 'Encrypted IMAP' },
  { port: 995,   name: 'POP3S',        severity: 'low',    reason: 'Encrypted POP3' },
  { port: 1433,  name: 'MSSQL',        severity: 'critical', reason: 'Database port — rarely needs to be internet-facing' },
  { port: 1521,  name: 'Oracle',       severity: 'critical', reason: 'Oracle DB — rarely needs to be internet-facing' },
  { port: 2049,  name: 'NFS',          severity: 'critical', reason: 'Network File System — unauthenticated file access risk' },
  { port: 3306,  name: 'MySQL',        severity: 'critical', reason: 'MySQL — rarely needs to be internet-facing; often no root password' },
  { port: 3389,  name: 'RDP',          severity: 'high',   reason: 'RDP exposed to internet — BlueKeep and brute-force risk' },
  { port: 5432,  name: 'PostgreSQL',   severity: 'critical', reason: 'PostgreSQL — rarely needs to be internet-facing' },
  { port: 5900,  name: 'VNC',          severity: 'critical', reason: 'VNC with no encryption by default — screen access risk' },
  { port: 5985,  name: 'WinRM',        severity: 'high',   reason: 'Windows Remote Management — lateral movement risk' },
  { port: 6379,  name: 'Redis',        severity: 'critical', reason: 'Redis default: no authentication — full data access' },
  { port: 8080,  name: 'HTTP-Alt',     severity: 'medium', reason: 'Alternative HTTP port — often dev/debug interfaces' },
  { port: 8443,  name: 'HTTPS-Alt',    severity: 'medium', reason: 'Alternative HTTPS — often admin/debug interfaces' },
  { port: 9200,  name: 'Elasticsearch', severity: 'critical', reason: 'Elasticsearch default: no auth — full document access + cluster access' },
  { port: 27017, name: 'MongoDB',      severity: 'critical', reason: 'MongoDB default: no auth — full database access' },
  { port: 27018, name: 'MongoDB-Shard', severity: 'critical', reason: 'MongoDB shard port — unauthenticated cluster access' },
];

/**
 * Scan a single TCP port
 * @param {string} host
 * @param {number} port
 * @param {number} timeout
 * @returns {Promise<{port: number, status: string}>}
 */
function scanPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve({ port, status: 'open' });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, status: 'timeout' });
    });

    socket.on('error', () => {
      socket.destroy();
      resolve({ port, status: 'closed' });
    });

    try {
      socket.connect(port, host);
    } catch {
      resolve({ port, status: 'closed' });
    }
  });
}

/**
 * Resolve hostname to IP
 * @param {string} hostname
 * @returns {Promise<string|null>}
 */
async function resolveHost(hostname) {
  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      resolve(err ? null : address);
    });
  });
}

/**
 * Main scan function
 * @param {Object} context
 * @param {Object} config
 * @returns {Promise<Array>}
 */
async function run(context, config) {
  const { target, targetUrl } = context;

  // Determine host to scan
  let host;
  if (target.startsWith('http')) {
    try {
      const url = new URL(target);
      host = url.hostname;
    } catch {
      return [];
    }
  } else {
    host = target;
  }

  // Resolve hostname to IP
  const ip = await resolveHost(host);
  if (!ip) {
    return [createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: `Cannot resolve host: ${host}`,
      description: `DNS resolution failed for ${host}`,
      target: target,
      remediation: 'Verify the hostname is correct and DNS is working.'
    })];
  }

  const findings = [];
  const portsToScan = (config.scanners?.ports?.excludePorts || []).length > 0
    ? PORTS.filter(p => !(config.scanners.ports.excludePorts || []).includes(p.port))
    : PORTS;

  // Scan all ports in parallel (limited concurrency)
  const CONCURRENCY = 20;
  for (let i = 0; i < portsToScan.length; i += CONCURRENCY) {
    const batch = portsToScan.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(p => scanPort(ip, p.port, 3000)));

    for (const result of results) {
      if (result.status === 'open') {
        const portDef = portsToScan.find(p => p.port === result.port) || { name: 'Unknown', severity: 'medium', reason: 'Unknown service detected' };
        findings.push(createFinding({
          scanner: SCANNER_ID,
          severity: portDef.severity,
          title: `Port ${result.port} (${portDef.name}) is open`,
          description: portDef.reason,
          cwe: 'CWE-200', // Exposure of Sensitive Information to an Unauthorized Actor
          target: `${host}:${result.port}`,
          evidence: { host, ip, port: result.port, service: portDef.name, status: 'open' },
          remediation: portDef.port === 22 || portDef.port === 3389 || portDef.port === 5900
            ? `Restrict access to port ${result.port} via firewall IP allowlist (e.g., AWS Security Group).`
            : portDef.port >= 1433 && portDef.port <= 27017
            ? `Database port ${result.port} must NEVER be internet-facing. Bind to 127.0.0.1 or internal network only.`
            : portDef.port === 9200
            ? `Elasticsearch must be behind auth or firewall. Never expose to internet.`
            : portDef.port === 6379
            ? `Redis must have auth enabled (requirepass) and be bound to internal network only.`
            : `Review whether port ${result.port} needs to be internet-facing. If not, block it via firewall.`
        }));
      }
    }
  }

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Scans common TCP ports for exposed services (SSH, RDP, databases, admin panels)', run, defaultTimeout: 120000 };
