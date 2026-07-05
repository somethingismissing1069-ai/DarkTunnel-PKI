# Implementation Plan: DarkTunnel PKI Web

## Overview

This plan implements a full-stack anonymous communication system using onion routing and PKI. The implementation follows a 9-step approach: backend setup, crypto module, PKI module, relay simulation, messaging API, frontend UI, API integration, security protections, and logging + testing. The backend uses Node.js + Express + SQLite (better-sqlite3) and the frontend uses React (Vite) + Tailwind CSS.

## Tasks

- [ ] 1. Set up backend project structure and core infrastructure
  - [ ] 1.1 Initialize backend project with package.json and dependencies
    - Create `backend/package.json` with dependencies: express, better-sqlite3, bcryptjs, jsonwebtoken, express-rate-limit, cors, dotenv
    - Create `backend/.env.example` with JWT_SECRET, PORT, DB_PATH
    - Create `backend/config/constants.js` with crypto params, rate limits, JWT config
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 19.1, 19.2_

  - [ ] 1.2 Set up SQLite database initialization and schema
    - Create `backend/models/db.js` with better-sqlite3 connection and table creation
    - Implement schema for users, nodes, messages, audit_logs, and nonces tables
    - Create indexes for nonce timestamps, message sender, and audit log filtering
    - _Requirements: 18.1, 18.2, 18.3, 18.4_

  - [ ] 1.3 Create Express application entry point with middleware and routes
    - Create `backend/index.js` with Express app, JSON body parser, CORS, and error handler
    - Register route files for auth, pki, message, relay, and admin
    - Implement global error handler returning consistent JSON error responses
    - _Requirements: 19.1, 19.2, 19.3_

  - [ ] 1.4 Create route and controller skeleton files
    - Create `backend/routes/authRoutes.js`, `pkiRoutes.js`, `messageRoutes.js`, `relayRoutes.js`, `adminRoutes.js`
    - Create `backend/controllers/authController.js`, `pkiController.js`, `messageController.js`, `relayController.js`, `adminController.js`
    - Wire routes to controller stubs
    - _Requirements: 19.3_

- [ ] 2. Implement cryptographic primitives module
  - [ ] 2.1 Implement AES-256-GCM encryption/decryption
    - Create `backend/crypto/aesGcm.js` with encrypt and decrypt functions
    - Use 32-byte key, 12-byte random IV, 16-byte auth tag
    - Return object with ciphertext, iv, and tag (all as Buffer or hex strings)
    - _Requirements: 5.1, 5.4_

  - [ ] 2.2 Implement RSA-OAEP key wrapping/unwrapping
    - Create `backend/crypto/rsaOaep.js` with wrapKey and unwrapKey functions
    - Use RSA_PKCS1_OAEP_PADDING with SHA-256 for wrapping 32-byte AES keys
    - _Requirements: 5.2_

  - [ ] 2.3 Implement RSA-PSS signing/verification
    - Create `backend/crypto/rsaPss.js` with sign and verify functions
    - Use RSA-SHA256 with RSA_PKCS1_PSS_PADDING and max salt length
    - _Requirements: 6.1, 6.2_

  - [ ] 2.4 Implement RSA key pair generation
    - Create `backend/crypto/keyGen.js` with generateKeyPair (2048-bit) and generateCAKeyPair (4096-bit) functions
    - Output keys in PEM format (spki/pkcs8)
    - _Requirements: 3.1, 3.2, 1.1_

  - [ ]* 2.5 Write property tests for crypto round-trips
    - **Property 10: RSA-OAEP Key Wrap Round-Trip**
    - **Property 13: Digital Signature Round-Trip**
    - **Validates: Requirements 4.2, 5.2, 6.1, 6.2, 6.3**

- [ ] 3. Checkpoint - Verify crypto primitives
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement PKI module (Certificate Authority)
  - [ ] 4.1 Implement PKI service with CA initialization
    - Create `backend/services/pkiService.js` with initialize() method
    - Generate 4096-bit RSA CA key pair and self-signed certificate on first run
    - Create 3 relay node entries (NodeA, NodeB, NodeC) with 2048-bit keys and certificates
    - Store CA and node data in database
    - _Requirements: 3.1, 3.5_

  - [ ] 4.2 Implement certificate issuance and verification
    - Add issueCertificate(subjectName, publicKey) to PKI service
    - Create JSON certificate with subject, publicKey, issuer, serialNumber, notBefore, notAfter, version
    - Sign certificate using CA private key with RSA-PSS SHA-256 over canonical JSON
    - Add verifyCertificate(certificate) checking temporal validity, CRL, and CA signature
    - _Requirements: 3.2, 3.3, 3.6_

  - [ ] 4.3 Implement certificate revocation and CRL management
    - Add revokeCertificate(serialNumber) to PKI service
    - Persist CRL in database and check during verification
    - _Requirements: 3.4_

  - [ ]* 4.4 Write property tests for PKI service
    - **Property 7: Certificate Issuance Completeness**
    - **Property 8: Certificate Verification Correctness**
    - **Property 9: Revocation Invalidates Certificates**
    - **Validates: Requirements 3.2, 3.3, 3.4, 3.6**

- [ ] 5. Implement relay simulation (3-node onion routing)
  - [ ] 5.1 Implement encryption service with onion packet construction
    - Create `backend/services/encryptionService.js` with createOnionPacket method
    - Implement 3-layer encryption: Layer 3 (Node C innermost), Layer 2 (Node B), Layer 1 (Node A outermost)
    - Generate unique AES-256 key per layer via crypto.randomBytes(32)
    - Wrap each AES key with corresponding node's RSA public key (RSA-OAEP)
    - Include nonce (16 bytes) and Unix timestamp in packet metadata
    - Delete ephemeral keys from memory after encryption
    - _Requirements: 4.1, 4.2, 5.1, 5.2, 5.3, 5.4, 7.1, 7.2, 7.3, 8.1_

  - [ ] 5.2 Implement relay engine with sequential node decryption
    - Create `backend/services/relayEngine.js` with processPacket method
    - Validate nonce (not seen in 60s window) and timestamp (within 60s of server time)
    - Sequentially process through Node A → B → C: verify cert, unwrap key, decrypt layer
    - Store nonce after successful processing
    - Halt and log on any failure (decryption, cert validation, signature)
    - _Requirements: 4.3, 4.4, 4.5, 4.6, 8.2, 8.3, 8.4, 20.1, 20.2_

  - [ ] 5.3 Implement signature service
    - Create `backend/services/signatureService.js` with sign and verify methods
    - Sign message plaintext with sender's RSA private key (RSA-PSS SHA-256)
    - Verify signature against sender's certificate public key during relay delivery
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ]* 5.4 Write property tests for onion routing
    - **Property 1: Onion Encryption Round-Trip**
    - **Property 11: Tampered Ciphertext Detection**
    - **Property 12: Encryption Layer Structure**
    - **Property 14: Replay Attack Rejection**
    - **Property 15: Timestamp Window Enforcement**
    - **Property 19: Certificate Trust Required for Relay**
    - **Validates: Requirements 4.1, 4.3, 4.4, 4.5, 4.6, 5.1, 5.3, 5.4, 8.2, 8.3, 8.4, 20.1, 20.2**

- [ ] 6. Checkpoint - Verify relay simulation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement messaging API and authentication
  - [ ] 7.1 Implement authentication service
    - Create `backend/services/authService.js` with register and login methods
    - Hash passwords with bcrypt (12 rounds)
    - Generate 2048-bit RSA key pair and certificate on registration
    - Generate JWT (HS256, 24h expiry) on login with { userId, username, role }
    - Implement verifyToken for JWT validation
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3_

  - [ ] 7.2 Implement auth controller and routes
    - Wire `backend/controllers/authController.js` for POST /api/register and POST /api/login
    - Return consistent JSON responses (success/error format)
    - Return generic error message on login failure (not revealing which field failed)
    - _Requirements: 1.1, 2.1, 2.2, 19.1, 19.2_

  - [ ] 7.3 Implement message service
    - Create `backend/services/messageService.js` with sendMessage, getMessageStatus, getUserMessages
    - Create message record (pending), invoke encryption service, process via relay, update status
    - Enforce ownership check (403 if userId doesn't match sender_id)
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 7.4 Implement message controller and routes
    - Wire `backend/controllers/messageController.js` for POST /api/message/send and GET /api/message/:id
    - Add GET /api/messages for listing user's messages
    - Require JWT auth middleware on all message endpoints
    - _Requirements: 11.1, 11.2, 11.3, 19.3_

  - [ ] 7.5 Implement PKI controller and routes
    - Wire `backend/controllers/pkiController.js` for POST /api/pki/generate-cert, GET /api/pki/verify/:id, POST /api/pki/revoke
    - Require JWT auth for all PKI endpoints, admin role for revocation
    - _Requirements: 3.2, 3.3, 3.4, 19.3_

  - [ ]* 7.6 Write property tests for authentication and messages
    - **Property 2: Invalid Input Rejection on Registration**
    - **Property 3: Duplicate Username Rejection**
    - **Property 4: Login Produces Valid JWT**
    - **Property 5: Authentication Error Indistinguishability**
    - **Property 6: Invalid JWT Rejection**
    - **Property 17: Message Ownership Authorization**
    - **Validates: Requirements 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 11.3**

- [ ] 8. Checkpoint - Verify backend API
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Build frontend UI (React + Vite + Tailwind)
  - [ ] 9.1 Initialize frontend project and configuration
    - Create `frontend/package.json` with React, Vite, Tailwind CSS, Axios, react-router-dom
    - Create `frontend/vite.config.js` with API proxy to backend
    - Create `frontend/tailwind.config.js` with dark theme, custom colors (#1a1a2e, #16213e, #00d4ff, #10b981, #f59e0b, #ef4444)
    - Create `frontend/postcss.config.js`, `frontend/index.html`
    - Create `frontend/src/index.css` with Tailwind directives and glassmorphism utilities
    - _Requirements: 13.5_

  - [ ] 9.2 Implement auth context and API service layer
    - Create `frontend/src/main.jsx` and `frontend/src/App.jsx` with React Router
    - Create `frontend/src/context/AuthContext.jsx` with JWT state management (localStorage)
    - Create `frontend/src/services/api.js` with Axios instance and JWT interceptor (auto-logout on 401)
    - Create `frontend/src/services/authApi.js`, `messageApi.js`, `adminApi.js`
    - _Requirements: 13.3, 14.3_

  - [ ] 9.3 Implement landing page and authentication pages
    - Create `frontend/src/pages/LandingPage.jsx` with hero section, feature cards, CTA buttons
    - Create `frontend/src/pages/RegisterPage.jsx` with form validation (username 3-30 chars, password 8+ chars)
    - Create `frontend/src/pages/LoginPage.jsx` with generic error messages
    - Create `frontend/src/components/Navbar.jsx` and `frontend/src/components/ProtectedRoute.jsx`
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [ ] 9.4 Implement dashboard page
    - Create `frontend/src/pages/DashboardPage.jsx` with username, certificate status badge, message stats cards
    - Add navigation cards to Send Message and Message Tracking pages
    - Redirect to login if JWT is missing/expired
    - _Requirements: 14.1, 14.2, 14.3_

  - [ ] 9.5 Implement send message and tracking pages
    - Create `frontend/src/pages/SendMessagePage.jsx` with text area, send button, and progress indicator showing onion encryption stages
    - Create `frontend/src/pages/TrackingPage.jsx` with message list and color-coded status badges
    - Create `frontend/src/components/StatusBadge.jsx` (green=delivered, yellow=pending, red=failed)
    - _Requirements: 15.1, 15.2, 15.3, 16.1, 16.2_

  - [ ] 9.6 Implement admin logs viewer page
    - Create `frontend/src/pages/AdminLogsPage.jsx` with filterable table (event type, date range)
    - Check admin role on mount, redirect non-admins to dashboard
    - Display event type, timestamp, and details for each log entry
    - _Requirements: 17.1, 17.2, 17.3_

- [ ] 10. Connect frontend and backend (API integration)
  - [ ] 10.1 Wire authentication flow end-to-end
    - Connect RegisterPage form submission to POST /api/register
    - Connect LoginPage form submission to POST /api/login, store JWT in AuthContext
    - Ensure ProtectedRoute redirects when token is expired/missing
    - Test complete registration → login → dashboard flow
    - _Requirements: 13.2, 13.3, 13.4, 14.3_

  - [ ] 10.2 Wire messaging flow end-to-end
    - Connect SendMessagePage to POST /api/message/send with JWT header
    - Connect TrackingPage to GET /api/messages with JWT header
    - Display real-time progress indicator during message sending
    - Display message list with status badges on tracking page
    - _Requirements: 15.1, 15.2, 15.3, 16.1, 16.2_

  - [ ] 10.3 Wire admin panel and dashboard data
    - Connect DashboardPage to backend APIs for cert status and message stats
    - Connect AdminLogsPage to GET /api/admin/logs with filters
    - Enforce admin role check for logs endpoint
    - _Requirements: 14.1, 17.1, 17.2, 17.3_

- [ ] 11. Add security protections
  - [ ] 11.1 Implement authentication middleware
    - Create `backend/middleware/authMiddleware.js` verifying Bearer JWT from Authorization header
    - Return 401 for missing, expired, or invalid tokens
    - Attach decoded user ({ userId, username, role }) to req.user
    - _Requirements: 2.3_

  - [ ] 11.2 Implement rate limiting middleware
    - Create `backend/middleware/rateLimiter.js` with general limiter (100 req/15min) and login limiter (5 failed/15min)
    - Return 429 with Retry-After header when exceeded
    - Log rate_limit_exceeded events via AuditLogger
    - _Requirements: 9.1, 9.2, 9.3_

  - [ ] 11.3 Implement input validation middleware
    - Create `backend/middleware/validator.js` with schema validation for all request bodies
    - Validate required fields, types, length constraints, and patterns
    - Sanitize string inputs (strip HTML entities, trim whitespace)
    - Return 400 with descriptive error messages for invalid input
    - _Requirements: 10.1, 10.2, 10.3_

  - [ ] 11.4 Implement MITM protection in encryption service
    - Verify each relay node certificate against CA before using its public key for wrapping
    - Halt with certificate trust failure if any node cert is invalid/revoked/expired
    - _Requirements: 20.1, 20.2, 20.3_

  - [ ]* 11.5 Write property tests for security protections
    - **Property 16: Input Validation Rejects Invalid Schemas**
    - **Property 22: Consistent API Response Format**
    - **Validates: Requirements 10.1, 10.3, 19.1, 19.2**

- [ ] 12. Implement audit logging and testing
  - [ ] 12.1 Implement audit logger service
    - Create `backend/services/auditLogger.js` with log(eventType, details, userId) method
    - Persist entries to audit_logs table with event_type, details (JSON), user_id, timestamp
    - Sanitize details to exclude passwords, private keys, session keys, plaintext messages
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

  - [ ] 12.2 Implement admin controller for log retrieval
    - Wire `backend/controllers/adminController.js` for GET /api/admin/logs
    - Support filtering by eventType and date range (from, to query params)
    - Require admin role via middleware
    - _Requirements: 17.1, 17.2_

  - [ ] 12.3 Integrate audit logging across all services
    - Add audit log calls to: registration, login success/failure, cert issuance/revocation, message sent/delivered/failed, relay errors, replay detection, signature failures, rate limit exceeded
    - _Requirements: 12.1_

  - [ ]* 12.4 Write property tests for audit logging
    - **Property 18: Audit Log Completeness and Safety**
    - **Validates: Requirements 12.2, 12.4**

  - [ ]* 12.5 Write integration tests for complete message flow
    - Test normal message flow (send → encrypt → relay → deliver)
    - Test tampered message detection (fail)
    - Test fake certificate rejection
    - Test replay attack rejection
    - _Requirements: 4.1, 4.4, 4.5, 8.2, 8.3_

- [ ] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The backend uses better-sqlite3 (synchronous) for simplicity — no async DB calls needed
- Frontend uses Vite dev server proxy to avoid CORS during development
- JWT secret should be set via environment variable (minimum 256 bits)
- CA and relay node keys are generated on first server start

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "2.1", "2.2", "2.3", "2.4"] },
    { "id": 3, "tasks": ["2.5", "4.1", "9.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "9.2"] },
    { "id": 5, "tasks": ["4.4", "5.1", "5.3", "9.3"] },
    { "id": 6, "tasks": ["5.2", "9.4", "9.5"] },
    { "id": 7, "tasks": ["5.4", "7.1", "9.6"] },
    { "id": 8, "tasks": ["7.2", "7.3", "11.1", "11.2", "11.3"] },
    { "id": 9, "tasks": ["7.4", "7.5", "11.4", "12.1"] },
    { "id": 10, "tasks": ["7.6", "10.1", "12.2", "12.3"] },
    { "id": 11, "tasks": ["10.2", "10.3", "11.5", "12.4"] },
    { "id": 12, "tasks": ["12.5"] }
  ]
}
```
