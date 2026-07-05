/**
 * DarkTunnel PKI Web - Admin Routes
 * 
 * Defines routes for admin operations (audit logs, system management).
 * All endpoints require JWT authentication with admin role.
 * 
 * GET /api/admin/logs - Retrieve audit log entries
 */

const router = require('express').Router();
const adminController = require('../controllers/adminController');

// Retrieve audit logs with optional filtering
router.get('/logs', adminController.getLogs);

module.exports = router;
