/**
 * DarkTunnel PKI Web - PKI Controller
 * 
 * Handles certificate lifecycle management HTTP requests.
 * All endpoints require JWT authentication.
 * Certificate revocation requires admin role.
 * 
 * POST /api/pki/generate-cert - Generate certificate for authenticated user
 * GET  /api/pki/verify/:id    - Verify certificate by serial number
 * POST /api/pki/revoke        - Revoke a certificate (admin only)
 */

const pkiService = require('../services/pkiService');
const db = require('../models/db');

/**
 * POST /api/pki/generate-cert
 * Generate a new certificate for the authenticated user.
 * Issues a certificate signed by the CA with the user's public key.
 * 
 * Requires: JWT authentication
 * Response 200: { success: true, data: { certificate } }
 */
exports.generateCert = (req, res, next) => {
  try {
    const user = db.prepare('SELECT public_key, username FROM users WHERE id = ?').get(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const certificate = pkiService.issueCertificate(user.username, user.public_key);

    // Update user's certificate in database
    db.prepare('UPDATE users SET certificate = ? WHERE id = ?')
      .run(JSON.stringify(certificate), req.user.userId);

    res.status(200).json({
      success: true,
      data: { certificate }
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/pki/verify/:id
 * Verify a certificate by its serial number.
 * Looks up the certificate in user or node records and validates it.
 * 
 * Requires: JWT authentication
 * Params: id - certificate serial number
 * Response 200: { success: true, data: { valid, reason } }
 */
exports.verifyCert = (req, res, next) => {
  try {
    const serialNumber = parseInt(req.params.id, 10);
    if (isNaN(serialNumber)) {
      return res.status(400).json({ success: false, error: 'Invalid serial number' });
    }

    // Search in users first, then nodes
    let certificate = null;

    const users = db.prepare('SELECT certificate FROM users').all();
    for (const row of users) {
      const cert = JSON.parse(row.certificate);
      if (cert.serialNumber === serialNumber) {
        certificate = cert;
        break;
      }
    }

    if (!certificate) {
      const nodes = db.prepare('SELECT certificate FROM nodes').all();
      for (const row of nodes) {
        const cert = JSON.parse(row.certificate);
        if (cert.serialNumber === serialNumber) {
          certificate = cert;
          break;
        }
      }
    }

    if (!certificate) {
      return res.status(404).json({
        success: false,
        error: 'Certificate not found'
      });
    }

    const result = pkiService.verifyCertificate(certificate);
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/pki/revoke
 * Revoke a certificate by serial number.
 * Requires admin role - adds certificate to the CRL.
 * 
 * Requires: JWT authentication + admin role
 * Body: { serialNumber: number }
 * Response 200: { success: true, data: { revoked, serialNumber } }
 * Response 403: { success: false, error: string }
 */
exports.revokeCert = (req, res, next) => {
  try {
    // Check admin role
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin role required for certificate revocation'
      });
    }

    const { serialNumber } = req.body;
    if (!serialNumber || typeof serialNumber !== 'number') {
      return res.status(400).json({
        success: false,
        error: 'Valid serialNumber is required'
      });
    }

    const result = pkiService.revokeCertificate(serialNumber);
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};
