/**
 * Sentinel Audit — Network Ports Scanner
 * Scans common TCP ports for exposed services using Node.js net module
 */

const net = require('net');
const dns = require('dns');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'ports';
const SCANNER_NAME = 'Network Ports Scanner';

const PORTS = [
  { port: 21,    name: 'FTP',       severity: 'high',   reason: 'Unencrypted file transfer — credentials exposed' },
  { port: 22,    name: 'SSH',       severity: 'medium', reason: 'If exposed to internet without allowlist, brute-force risk' },
  { port: 23,    name: 'Telnet',    severity: 'critical', reason: 'Unencrypted — all traffic including passwords visible' },
  { port: 25,    name: 'SMTP',      severity: 'medium', reason: 'Open relay risk; unencrypted email' },
  { port: 53,    name: 'DNS',       severity: 'medium', reason: 'DNS amplification attacks; zone transfer risk' },
  { port: 80,    name: 'HTTP',      severity: 'low',    reason: 'Unencrypted web traffic; should redirect to HTTPS' },
  { port: 110,   name: 'POP3',      severity: 'high',   reason: 'Unencrypted email — credentials exposed' },
  { port: 135,   name: 'MSRPC',     severity: 'high',   reason: 'Windows RPC endpoint — lateral movement' },
  { port: 139,   name: 'NetBIOS',  severity: 'high',   reason: 'SMB/netbios — lateral movement and data exfil' },
  { port: 143,   name: 'IMAP',      severity: 'high',   reason: 'Unencrypted email — credentials exposed' },
  { port: 443,   name: 'HTTPS',     severity: 'low',    reason: 'Check SSL/TLS separately' },
  { port: 445,   name: 'SMB',       severity: 'critical', reason: 'EternalBlue, SMBleed — remote code execution' },
  { port: 465,   name: 'SMTPS',     severity: 'medium', reason: 'Encrypted SMTP submission' },
  { port: 587,   name: 'SMTP-Sub', severity: 'medium', reason: 'Email submission — check auth requirements' },
  { port: 993,   name: 'IMAPS',     severity: 'low',    reason: 'Encrypted IMAP' },
  { port: 995,   name: 'POP3S',     severity: 'low',    reason: 'Encrypted POP3' },
  { port: 1433,  name: 'MSSQL',     severity: 'critical', reason: 'Database — rarely needs to be internet-facing' },
  { port: 1521,  name: 'Oracle',    severity: 'critical', reason: 'Oracle DB — rarely needs to be internet-facing' },
  { port: 2049,  name: 'NFS',       severity: 'critical', reason: 'Network File System — unauthenticated file access' },
  { port: 3306,  name: 'MySQL',     severity: 'critical', reason: 'MySQL — often no root password; rarely internet-facing' },
  { port: 3389,  name: 'RDP',       severity: 'high',   reason: 'RDP exposed to internet — BlueKeep and brute-force risk' },
  { port: 5432,  name: 'PostgreSQL', severity: 'critical', reason: 'PostgreSQL — rarely needs to be internet-facing' },
  { port: 5900,  name: 'VNC',       severity: 'critical', reason: 'VNC — screen access risk, often no encryption' },
  { port: 5985,  name: 'WinRM',     severity: 'high',   reason: 'Windows Remote Management — lateral movement' },
  { port: 6379,  name: 'Redis',     severity: 'critical', reason: 'Redis default: no authentication — full data access' },
  { port: 8080,  name: 'HTTP-Alt', severity: 'medium', reason: 'Often dev/debug interfaces — review if intentional' },
  { port: 8443,  name: 'HTTPS-Alt', severity: 'medium', reason: 'Often admin/debug interfaces — verify TLS certs' },
  { port: 9200,  name: 'Elasticsearch', severity: 'critical', reason: 'Elasticsearch default: no auth — full document access' },
  { port: 27017, name: 'MongoDB',   severity: 'critical', reason: 'MongoDB default: no auth — full database access' },
];

function scanPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve({ port, status: 'open' }); });
    socket.on('timeout', () => { socket.destroy(); resolve({ port, status: 'timeout' }); });
    socket.on('error', () => { socket.destroy(); resolve({ port, status: 'closed' }); });
    try { socket.connect(port, host); } catch { resolve({ port, status: 'closed' }); }
  });
}

function resolveHost(hostname) {
  return new Promise((resolve) => { dns.lookup(hostname, (err, address) => resolve(err ? null : address)); });
}

async function run(context) {
  const { target, targetUrl } = context;
  let host;
  if (target.startsWith('http')) {
    try { host = new URL(target).hostname; } catch { return []; }
  } else { host = target; }
  const ip = await resolveHost(host);
  if (!ip) return [createFinding({ scanner: SCANNER_ID, severity: 'high', title: `Cannot resolve host: ${host}`, description: `DNS resolution failed for ${host}`, target, remediation: 'Verify the hostname is correct.' })];
  const findings = [];
  const CONCURRENCY = 20;
  for (let i = 0; i < PORTS.length; i += CONCURRENCY) {
    const batch = PORTS.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(p => scanPort(ip, p.port, 3000)));
    for (const result of results) {
      if (result.status === 'open') {
        const def = PORTS.find(p => p.port === result.port) || { name: 'Unknown', severity: 'medium', reason: 'Unknown service detected' };
        const { cvss } = normalizeSeverity(def.severity);
        findings.push(createFinding({ scanner: SCANNER_ID, severity: def.severity, title: `Port ${result.port} (${def.name}) is open`,
          description: def.reason, cwe: 'CWE-200', cvss, target: `${host}:${result.port}`,
          evidence: { host, ip, port: result.port, service: def.name },
          remediation: result.port >= 1433 && result.port <= 27017 ? `Database port ${result.port} must NEVER be internet-facing. Bind to 127.0.0.1 or internal network.` : result.port === 6379 ? `Redis must have auth (requirepass) and be bound to internal network only.` : result.port === 9200 ? `Elasticsearch must be behind auth or firewall. Never expose to internet.` : `Review whether port ${result.port} needs to be internet-facing. If not, block it via firewall.` }));
      }
    }
  }
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Scans common TCP ports for exposed services (SSH, RDP, databases, admin panels)', run, defaultTimeout: 120000 };
