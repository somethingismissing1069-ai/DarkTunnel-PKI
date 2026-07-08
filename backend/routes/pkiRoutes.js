/**
 * DarkTunnel PKI Web - PKI Routes
 * 
 * Defines routes for certificate lifecycle management.
 * All endpoints require JWT authentication.
 * 
 * POST /api/pki/generate-cert - Generate certificate for user
 * GET  /api/pki/verify/:id    - Verify certificate by serial number
 * POST /api/pki/revoke        - Revoke a certificate (admin only)
 */

const router = require('express').Router();
const pkiController = require('../controllers/pkiController');
const authMiddleware = require('../middleware/authMiddleware');

// All PKI routes require authentication
router.use(authMiddleware);

// Generate a new certificate for the authenticated user
router.post('/generate-cert', pkiController.generateCert);

// Verify a certificate by its serial number
router.get('/verify/:id', pkiController.verifyCert);

// Revoke a certificate (admin role required - checked in controller)
router.post('/revoke', pkiController.revokeCert);

module.exports = router;
