/**
 * DarkTunnel PKI Web - Audit Logger Service
 * 
 * Provides security event logging with sensitive field sanitization.
 * All security-relevant events (logins, cert operations, message sends)
 * are logged for monitoring and forensic analysis.
 * 
 * Sensitive fields (passwords, private keys, session keys) are automatically
 * stripped from log entries to prevent credential leakage in audit trails.
 */

const db = require('../models/db');

// Fields that must never appear in audit log details
const SENSITIVE_FIELDS = [
  'password', 'password_hash', 'privatekey', 'private_key',
  'sessionkey', 'aeskey', 'plaintext', 'secret', 'token'
];

class AuditLogger {
  /**
   * Log a security event to the audit_logs table.
   * 
   * @param {string} eventType - Event category (e.g., 'USER_LOGIN', 'CERT_ISSUED')
   * @param {Object} details - Additional event details (sensitive fields auto-stripped)
   * @param {number|null} userId - Associated user ID (null for system events)
   */
  log(eventType, details = {}, userId = null) {
    const sanitized = this._sanitize(details);
    const stmt = db.prepare(
      'INSERT INTO audit_logs (event_type, details, user_id) VALUES (?, ?, ?)'
    );
    stmt.run(eventType, JSON.stringify(sanitized), userId);
  }

  /**
   * Retrieve audit log entries with optional filtering.
   * 
   * @param {Object} filters - Query filters
   * @param {string} [filters.eventType] - Filter by event type
   * @param {string} [filters.from] - Filter entries after this timestamp
   * @param {string} [filters.to] - Filter entries before this timestamp
   * @returns {Array} Array of audit log entries (max 100, newest first)
   */
  getEntries(filters = {}) {
    let query = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];

    if (filters.eventType) {
      query += ' AND event_type = ?';
      params.push(filters.eventType);
    }
    if (filters.from) {
      query += ' AND timestamp >= ?';
      params.push(filters.from);
    }
    if (filters.to) {
      query += ' AND timestamp <= ?';
      params.push(filters.to);
    }

    query += ' ORDER BY timestamp DESC LIMIT 100';
    return db.prepare(query).all(...params);
  }

  /**
   * Remove sensitive fields from log details.
   * Strips password hashes, private keys, session keys, and PEM-encoded secrets.
   * 
   * @param {Object} obj - Raw details object
   * @returns {Object} Sanitized copy with sensitive fields removed
   * @private
   */
  _sanitize(obj) {
    if (!obj || typeof obj !== 'object') return {};
    const clean = {};
    for (const [key, value] of Object.entries(obj)) {
      // Skip known sensitive field names (case-insensitive check)
      if (SENSITIVE_FIELDS.includes(key.toLowerCase())) continue;
      // Skip PEM-encoded private keys/secrets
      if (typeof value === 'string' && value.includes('-----BEGIN')) continue;
      clean[key] = value;
    }
    return clean;
  }
}

module.exports = new AuditLogger();
