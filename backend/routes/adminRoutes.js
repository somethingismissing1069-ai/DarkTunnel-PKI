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
const authMiddleware = require('../middleware/authMiddleware');

// All admin routes require authentication (role checked in controller)
router.use(authMiddleware);

// Retrieve audit logs with optional filtering
router.get('/logs', adminController.getLogs);

module.exports = router;
