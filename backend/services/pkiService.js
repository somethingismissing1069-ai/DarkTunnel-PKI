/**
 * DarkTunnel PKI Web - PKI Service
 * 
 * Manages the Public Key Infrastructure for the DarkTunnel system:
 * - Certificate Authority (CA) initialization with 4096-bit RSA root key
 * - Relay node creation (NodeA, NodeB, NodeC) with 2048-bit keys
 * - Certificate issuance, verification, and revocation
 * - Certificate Revocation List (CRL) management
 * 
 * Certificate Format:
 * {
 *   version: 1,
 *   serialNumber: <auto-increment from 1000>,
 *   subject: <entity name>,
 *   issuer: "DarkTunnel-CA",
 *   publicKey: <PEM-encoded public key>,
 *   notBefore: <ISO timestamp>,
 *   notAfter: <ISO timestamp>,
 *   signature: <hex-encoded RSA-PSS signature>
 * }
 * 
 * Signing uses canonical JSON (sorted keys, no whitespace) to ensure
 * deterministic signature verification.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const keyGen = require('../crypto/keyGen');
const rsaPss = require('../crypto/rsaPss');
const db = require('../models/db');
const auditLogger = require('./auditLogger');
const constants = require('../config/constants');

// CRL file path for persisting revoked serial numbers
const CRL_PATH = path.resolve(__dirname, '..', 'data', 'crl.json');

class PKIService {
  constructor() {
    this.caKeyPair = null;      // { publicKey, privateKey } - CA root keys
    this.caCertificate = null;  // Self-signed CA certificate
    this.nextSerial = 1000;     // Auto-incrementing serial number
    this.crl = new Set();       // In-memory CRL for fast lookup
    this.initialized = false;
  }

  /**
   * Initialize the PKI system:
   * 1. Generate CA key pair (4096-bit RSA)
   * 2. Create self-signed CA certificate
   * 3. Load CRL from disk
   * 4. Create relay nodes if they don't exist
   */
  initialize() {
    if (this.initialized) return;

    console.log('[PKI] Initializing Certificate Authority...');

    // Generate 4096-bit RSA key pair for the CA
    this.caKeyPair = keyGen.generateCAKeyPair();

    // Create self-signed CA certificate
    this.caCertificate = this._createCACertificate();
    this.nextSerial = 1001; // CA cert gets serial 1000

    // Mark as initialized before relay node creation (which calls issueCertificate)
    this.initialized = true;

    // Load persisted CRL
    this._loadCRL();

    // Initialize relay nodes (calls issueCertificate internally)
    this._initializeRelayNodes();

    console.log('[PKI] Certificate Authority initialized successfully');
    auditLogger.log('PKI_INITIALIZED', { caSubject: 'DarkTunnel-CA' });
  }

  /**
   * Issue a certificate for a subject (user or node).
   * 
   * @param {string} subjectName - The entity name for the certificate
   * @param {string} publicKey - PEM-encoded public key of the subject
   * @returns {Object} Signed certificate object
   */
  issueCertificate(subjectName, publicKey) {
    if (!this.initialized) {
      throw new Error('PKI service not initialized');
    }

    const now = new Date();
    const notAfter = new Date(now);
    notAfter.setDate(notAfter.getDate() + constants.CERT_VALIDITY_DAYS);

    const serialNumber = this.nextSerial++;

    // Certificate body (all fields except signature)
    const certBody = {
      version: 1,
      serialNumber,
      subject: subjectName,
      issuer: 'DarkTunnel-CA',
      publicKey,
      notBefore: now.toISOString(),
      notAfter: notAfter.toISOString()
    };

    // Sign the canonical JSON representation
    const canonical = this._canonicalJSON(certBody);
    const signature = rsaPss.sign(canonical, this.caKeyPair.privateKey);

    const certificate = {
      ...certBody,
      signature: signature.toString('hex')
    };

    auditLogger.log('CERT_ISSUED', {
      serialNumber,
      subject: subjectName,
      notBefore: certBody.notBefore,
      notAfter: certBody.notAfter
    });

    return certificate;
  }

  /**
   * Verify a certificate's signature, validity period, and revocation status.
   * 
   * @param {Object} certificate - Certificate object to verify
   * @returns {{ valid: boolean, reason: string }} Verification result
   */
  verifyCertificate(certificate) {
    if (!certificate || !certificate.signature) {
      return { valid: false, reason: 'Invalid certificate format' };
    }

    // Check revocation status
    if (this.crl.has(certificate.serialNumber)) {
      return { valid: false, reason: 'Certificate has been revoked' };
    }

    // Check validity period
    const now = new Date();
    if (new Date(certificate.notBefore) > now) {
      return { valid: false, reason: 'Certificate not yet valid' };
    }
    if (new Date(certificate.notAfter) < now) {
      return { valid: false, reason: 'Certificate has expired' };
    }

    // Verify CA signature
    const { signature, ...certBody } = certificate;
    const canonical = this._canonicalJSON(certBody);
    const sigBuffer = Buffer.from(signature, 'hex');

    const isValid = rsaPss.verify(canonical, sigBuffer, this.caKeyPair.publicKey);
    if (!isValid) {
      return { valid: false, reason: 'Invalid CA signature' };
    }

    return { valid: true, reason: 'Certificate is valid' };
  }

  /**
   * Revoke a certificate by serial number.
   * Adds to in-memory CRL and persists to disk.
   * 
   * @param {number} serialNumber - Serial number of certificate to revoke
   * @returns {{ revoked: boolean, serialNumber: number }}
   */
  revokeCertificate(serialNumber) {
    this.crl.add(serialNumber);
    this._saveCRL();

    auditLogger.log('CERT_REVOKED', { serialNumber });
    return { revoked: true, serialNumber };
  }

  /**
   * Get the CA's public key for external verification.
   * @returns {string} PEM-encoded CA public key
   */
  getCAPublicKey() {
    return this.caKeyPair.publicKey;
  }

  /**
   * Get the CA certificate.
   * @returns {Object} CA certificate object
   */
  getCACertificate() {
    return this.caCertificate;
  }

  // ─── Private Methods ───────────────────────────────────────────────────────

  /**
   * Create the self-signed CA certificate (serial 1000).
   * @returns {Object} Self-signed CA certificate
   * @private
   */
  _createCACertificate() {
    const now = new Date();
    const notAfter = new Date(now);
    notAfter.setFullYear(notAfter.getFullYear() + 10); // CA cert valid for 10 years

    const certBody = {
      version: 1,
      serialNumber: 1000,
      subject: 'DarkTunnel-CA',
      issuer: 'DarkTunnel-CA',
      publicKey: this.caKeyPair.publicKey,
      notBefore: now.toISOString(),
      notAfter: notAfter.toISOString()
    };

    const canonical = this._canonicalJSON(certBody);
    const signature = rsaPss.sign(canonical, this.caKeyPair.privateKey);

    return {
      ...certBody,
      signature: signature.toString('hex')
    };
  }

  /**
   * Initialize the 3 relay nodes (NodeA, NodeB, NodeC).
   * Skips creation if nodes already exist in the database.
   * @private
   */
  _initializeRelayNodes() {
    const existingNodes = db.prepare('SELECT COUNT(*) as count FROM nodes').get();

    if (existingNodes.count >= 3) {
      console.log('[PKI] Relay nodes already exist, skipping creation');
      // Update serial counter based on existing certs
      const maxNode = db.prepare('SELECT certificate FROM nodes ORDER BY id DESC LIMIT 1').get();
      if (maxNode) {
        const cert = JSON.parse(maxNode.certificate);
        if (cert.serialNumber >= this.nextSerial) {
          this.nextSerial = cert.serialNumber + 1;
        }
      }
      return;
    }

    console.log('[PKI] Creating relay nodes...');

    for (const nodeName of constants.RELAY_NODES) {
      const { publicKey, privateKey } = keyGen.generateNodeKeyPair();
      const certificate = this.issueCertificate(nodeName, publicKey);

      db.prepare(
        'INSERT INTO nodes (name, public_key, private_key, certificate) VALUES (?, ?, ?, ?)'
      ).run(nodeName, publicKey, privateKey, JSON.stringify(certificate));

      console.log(`[PKI] Created relay node: ${nodeName} (serial: ${certificate.serialNumber})`);
    }

    auditLogger.log('RELAY_NODES_CREATED', { nodes: constants.RELAY_NODES });
  }

  /**
   * Create canonical JSON for deterministic signing.
   * Keys are sorted alphabetically, no whitespace.
   * 
   * @param {Object} obj - Object to serialize
   * @returns {string} Canonical JSON string
   * @private
   */
  _canonicalJSON(obj) {
    return JSON.stringify(obj, Object.keys(obj).sort());
  }

  /**
   * Load CRL from disk on startup.
   * @private
   */
  _loadCRL() {
    try {
      if (fs.existsSync(CRL_PATH)) {
        const data = JSON.parse(fs.readFileSync(CRL_PATH, 'utf-8'));
        this.crl = new Set(data);
        console.log(`[PKI] Loaded CRL with ${this.crl.size} revoked certificates`);
      }
    } catch (err) {
      console.warn('[PKI] Could not load CRL, starting fresh:', err.message);
      this.crl = new Set();
    }
  }

  /**
   * Persist CRL to disk.
   * @private
   */
  _saveCRL() {
    try {
      const dir = path.dirname(CRL_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(CRL_PATH, JSON.stringify([...this.crl]));
    } catch (err) {
      console.error('[PKI] Failed to save CRL:', err.message);
    }
  }
}

// Singleton instance
const pkiService = new PKIService();
module.exports = pkiService;
