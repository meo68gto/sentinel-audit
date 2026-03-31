/**
 * Sentinel Audit — Core Scanner Types
 * Shared type definitions for all scanner modules
 */

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * @typedef {'critical'|'high'|'medium'|'low'|'info'} Severity
 */

/**
 * @typedef {'dependency'|'secrets'|'headers'|'ports'|'auth'|'ssl'} ScannerId
 */

/**
 * @typedef {Object} Finding
 * @property {string} id - Unique finding ID (e.g. "SENTINEL-001")
 * @property {ScannerId} scanner - Which scanner produced this finding
 * @property {Severity} severity - Severity level
 * @property {string} title - Short finding title
 * @property {string} description - Detailed description
 * @property {string} [cwe] - CWE identifier (e.g. "CWE-798")
 * @property {number} [cvss] - CVSS score 0.0-10.0
 * @property {string} [target] - Target URL or path this finding applies to
 * @property {Object} [evidence] - Raw evidence (headers, response body, etc.)
 * @property {string} [filePath] - File path if code-based finding
 * @property {number} [lineNumber] - Line number if code-based finding
 * @property {string} [remediation] - How to fix this finding
 */

/**
 * @typedef {Object} ScanResult
 * @property {string} scanId - Unique scan identifier (scan_YYYYMMDD_HHMMSS)
 * @property {string} target - Target that was scanned
 * @property {string} targetType - 'url', 'directory', or 'host'
 * @property {Date} startedAt - When the scan started
 * @property {Date} completedAt - When the scan completed
 * @property {number} durationMs - Total duration in milliseconds
 * @property {Finding[]} findings - All findings from all scanners
 * @property {Object} summary - Count breakdown by severity
 * @property {Object} scannerResults - Per-scanner metadata
 */

/**
 * @typedef {Object} ScannerModule
 * @property {ScannerId} id - Unique scanner identifier
 * @property {string} name - Human-readable name
 * @property {string} description - What this scanner checks
 * @property {Function} run - Async function that executes the scan
 */

module.exports = {
  SEVERITY_LEVELS,
  SEVERITY_WEIGHTS: {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  }
};
