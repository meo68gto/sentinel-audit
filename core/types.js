/**
 * Sentinel Audit — Core Scanner Types
 * Shared type definitions for all scanner modules
 */

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_WEIGHTS = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

module.exports = { SEVERITY_LEVELS, SEVERITY_WEIGHTS };
