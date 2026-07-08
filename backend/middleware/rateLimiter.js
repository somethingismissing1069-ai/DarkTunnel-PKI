/**
 * DarkTunnel PKI Web - Rate Limiting Middleware
 * 
 * Protects against brute-force attacks and DoS:
 * - generalLimiter: 100 requests per 15 minutes per IP (all endpoints)
 * - loginLimiter: 5 failed login attempts per 15 minutes per IP
 * 
 * Uses express-rate-limit for sliding window rate limiting.
 * The login limiter only counts failed attempts (skipSuccessfulRequests).
 */

const rateLimit = require('express-rate-limit');
const constants = require('../config/constants');

/**
 * General rate limiter - applies to all API endpoints.
 * Limits each IP to 100 requests per 15-minute window.
 */
const generalLimiter = rateLimit({
  windowMs: constants.RATE_LIMIT_WINDOW_MS,  // 15 minutes
  max: constants.RATE_LIMIT_MAX_REQUESTS,    // 100 requests per window
  message: {
    success: false,
    error: 'Too many requests, please try again later'
  },
  standardHeaders: true,  // Return rate limit info in RateLimit-* headers
  legacyHeaders: false    // Disable X-RateLimit-* headers
});

/**
 * Login rate limiter - applies to authentication endpoints.
 * Limits each IP to 5 failed login attempts per 15-minute window.
 * Successful requests are not counted (skipSuccessfulRequests).
 */
const loginLimiter = rateLimit({
  windowMs: constants.RATE_LIMIT_WINDOW_MS,  // 15 minutes
  max: constants.RATE_LIMIT_MAX_LOGIN,       // 5 failed attempts per window
  skipSuccessfulRequests: true,              // Only count failures
  message: {
    success: false,
    error: 'Too many failed login attempts, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = { generalLimiter, loginLimiter };
