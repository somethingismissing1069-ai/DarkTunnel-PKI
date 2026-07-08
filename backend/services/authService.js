/**
 * DarkTunnel PKI Web - Authentication Service
 * 
 * Handles user registration and login:
 * - Registration: validates input, hashes password, generates RSA key pair,
 *   issues PKI certificate, stores user in database
 * - Login: verifies credentials, generates JWT session token
 * - Token verification: validates JWT tokens for protected routes
 * 
 * Security measures:
 * - bcrypt password hashing (12 rounds)
 * - RSA-2048 key pair per user for digital signatures
 * - CA-issued certificate per user for identity binding
 * - JWT with 24h expiry for session management
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keyGen = require('../crypto/keyGen');
const pkiService = require('./pkiService');
const db = require('../models/db');
const auditLogger = require('./auditLogger');
const constants = require('../config/constants');

/**
 * Register a new user account.
 * 
 * 1. Validate username and password
 * 2. Check username uniqueness
 * 3. Hash password with bcrypt
 * 4. Generate 2048-bit RSA key pair
 * 5. Issue PKI certificate from CA
 * 6. Store user record in database
 * 
 * @param {string} username - Desired username (3-30 characters)
 * @param {string} password - Password (8+ characters)
 * @returns {{ userId: number, username: string }} Created user info
 * @throws {Error} On validation failure or duplicate username
 */
function register(username, password) {
  // Input validation
  if (!username || username.length < constants.USERNAME_MIN_LENGTH ||
      username.length > constants.USERNAME_MAX_LENGTH) {
    const err = new Error(`Username must be ${constants.USERNAME_MIN_LENGTH}-${constants.USERNAME_MAX_LENGTH} characters`);
    err.statusCode = 400;
    throw err;
  }

  if (!password || password.length < constants.PASSWORD_MIN_LENGTH) {
    const err = new Error(`Password must be at least ${constants.PASSWORD_MIN_LENGTH} characters`);
    err.statusCode = 400;
    throw err;
  }

  // Check username uniqueness
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    const err = new Error('Username already exists');
    err.statusCode = 409;
    throw err;
  }

  // Hash password with bcrypt (12 rounds ≈ 300ms)
  const passwordHash = bcrypt.hashSync(password, constants.BCRYPT_ROUNDS);

  // Generate 2048-bit RSA key pair for digital signatures
  const { publicKey, privateKey } = keyGen.generateUserKeyPair();

  // Issue PKI certificate from the CA
  const certificate = pkiService.issueCertificate(username, publicKey);

  // Store user in database
  const result = db.prepare(
    'INSERT INTO users (username, password_hash, public_key, private_key, certificate, role) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(username, passwordHash, publicKey, privateKey, JSON.stringify(certificate), 'user');

  const userId = result.lastInsertRowid;

  auditLogger.log('USER_REGISTERED', { userId, username }, userId);

  return { userId, username };
}

/**
 * Authenticate a user and generate a JWT session token.
 * 
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @returns {{ token: string }} JWT session token
 * @throws {Error} On invalid credentials
 */
function login(username, password) {
  // Find user by username
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    const err = new Error('Invalid username or password');
    err.statusCode = 401;
    throw err;
  }

  // Verify password with bcrypt
  const passwordValid = bcrypt.compareSync(password, user.password_hash);
  if (!passwordValid) {
    auditLogger.log('LOGIN_FAILED', { username, reason: 'invalid_password' });
    const err = new Error('Invalid username or password');
    err.statusCode = 401;
    throw err;
  }

  // Generate JWT with user payload
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: constants.JWT_EXPIRY }
  );

  auditLogger.log('USER_LOGIN', { userId: user.id, username }, user.id);

  return { token };
}

/**
 * Verify a JWT token and return the decoded payload.
 * 
 * @param {string} token - JWT token to verify
 * @returns {{ userId: number, username: string, role: string }} Decoded payload
 * @throws {Error} On invalid or expired token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    const error = new Error('Invalid or expired token');
    error.statusCode = 401;
    throw error;
  }
}

module.exports = { register, login, verifyToken };
