/**
 * DarkTunnel PKI Web - Admin Controller
 * 
 * Handles administrative operations:
 * - Audit log retrieval with filtering
 * 
 * All endpoints require JWT authentication with admin role.
 * 
 * GET /api/admin/logs - Retrieve audit log entries
 */

const auditLogger = require('../services/auditLogger');

/**
 * GET /api/admin/logs
 * Retrieve audit log entries with optional filtering.
 * 
 * Requires: JWT authentication + admin role
 * Query params:
 *   - eventType: Filter by event type (e.g., 'USER_LOGIN')
 *   - from: Filter entries after this ISO timestamp
 *   - to: Filter entries before this ISO timestamp
 * 
 * Response 200: { success: true, data: [ audit log entries ] }
 * Response 403: { success: false, error: string }
 */
exports.getLogs = (req, res, next) => {
  try {
    // Check admin role
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin role required to view audit logs'
      });
    }

    const filters = {};
    if (req.query.eventType) filters.eventType = req.query.eventType;
    if (req.query.from) filters.from = req.query.from;
    if (req.query.to) filters.to = req.query.to;

    const entries = auditLogger.getEntries(filters);

    res.status(200).json({
      success: true,
      data: entries
    });
  } catch (err) {
    next(err);
  }
};
