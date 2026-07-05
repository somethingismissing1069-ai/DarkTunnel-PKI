# Design Document: DarkTunnel PKI Web

## Introduction

This document describes the technical architecture and design of the DarkTunnel PKI Web application — a full-stack anonymous communication system that simulates Tor-like onion routing with a complete PKI infrastructure. The system is built with React (Vite) + Tailwind CSS on the frontend and Node.js + Express on the backend, using SQLite for persistence and the Node.js `crypto` module for all cryptographic operations.

## Architecture Overview

The system follows a layered architecture with clear separation between the presentation layer (React frontend), the API layer (Express routes), the service layer (business logic), and the data layer (SQLite).

```
┌─────────────────────────────────────────────────┐
│           React Frontend (Vite + Tailwind)       │
│  Pages: Landing | Auth | Dashboard | Messages   │
└───────────────────────┬─────────────────────────┘
                        │ HTTP/JSON (Axios)
                        ▼
┌─────────────────────────────────────────────────┐
│           Express Backend API                    │
│  Middleware: Auth | RateLimit | Validation       │
├─────────────────────────────────────────────────┤
│           Services Layer                         │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ AuthService  │  │ PKIService   │            │
│  └──────────────┘  └──────────────┘            │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ EncryptSvc   │  │ MessageSvc   │            │
│  └──────────────┘  └──────────────┘            │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ RelayEngine  │  │ AuditLogger  │            │
│  └──────────────┘  └──────────────┘            │
│  ┌──────────────┐                              │
│  │ SignatureSvc  │                              │
│  └──────────────┘                              │
├─────────────────────────────────────────────────┤
│           SQLite Database (better-sqlite3)       │
│  Tables: Users | Nodes | Messages | AuditLogs  │
└─────────────────────────────────────────────────┘
```



## Project Structure

```
backend/
  index.js                 # Express app entry point, middleware setup
  config/
    database.js            # SQLite connection and schema initialization
    constants.js           # Crypto params, rate limits, JWT config
  middleware/
    authMiddleware.js      # JWT verification middleware
    rateLimiter.js         # express-rate-limit configuration
    validator.js           # Request body schema validation
  routes/
    authRoutes.js          # POST /api/register, POST /api/login
    pkiRoutes.js           # POST /api/pki/generate-cert, GET /api/pki/verify/:id
    messageRoutes.js       # POST /api/message/send, GET /api/message/:id
    relayRoutes.js         # POST /api/relay/process
    adminRoutes.js         # GET /api/admin/logs
  controllers/
    authController.js      # Registration and login handlers
    pkiController.js       # Certificate generation and verification handlers
    messageController.js   # Message send and status handlers
    relayController.js     # Relay processing handler
    adminController.js     # Audit log retrieval handler
  services/
    authService.js         # Password hashing, JWT generation, user CRUD
    pkiService.js          # CA init, cert issuance, verification, CRL
    encryptionService.js   # AES-256-GCM, RSA-OAEP key wrap, onion layers
    signatureService.js    # RSA-PSS sign/verify
    messageService.js      # Message lifecycle management
    relayEngine.js         # Onion packet processing through 3 nodes
    auditLogger.js         # Event logging to AuditLogs table
  crypto/
    aesGcm.js             # AES-256-GCM encrypt/decrypt primitives
    rsaOaep.js            # RSA-OAEP key wrap/unwrap primitives
    rsaPss.js             # RSA-PSS sign/verify primitives
    keyGen.js             # RSA key pair generation (2048/4096-bit)
  models/
    db.js                 # Database initialization and table creation
    userModel.js          # Users table queries
    nodeModel.js          # Nodes table queries
    messageModel.js       # Messages table queries
    auditModel.js         # AuditLogs table queries
    nonceModel.js         # Nonces table queries

frontend/
  index.html
  vite.config.js
  tailwind.config.js
  postcss.config.js
  src/
    main.jsx              # React entry point
    App.jsx               # Router and layout
    context/
      AuthContext.jsx     # JWT state, login/logout, protected route logic
    pages/
      LandingPage.jsx     # System description, feature highlights
      LoginPage.jsx       # Login form
      RegisterPage.jsx    # Registration form
      DashboardPage.jsx   # User overview, cert status, message summary
      SendMessagePage.jsx # Message composition and send
      TrackingPage.jsx    # Message status list
      AdminLogsPage.jsx   # Audit log viewer (admin only)
    components/
      Navbar.jsx          # Navigation bar
      ProtectedRoute.jsx  # JWT-gated route wrapper
      MessageCard.jsx     # Message status display card
      LoadingOverlay.jsx  # Onion encryption animation
      StatusBadge.jsx     # Color-coded status indicator
    services/
      api.js              # Axios instance with JWT interceptor
      authApi.js          # Register, login API calls
      pkiApi.js           # Certificate API calls
      messageApi.js       # Send message, get status API calls
      adminApi.js         # Audit log API calls
    hooks/
      useAuth.js          # Auth context consumer hook
      useMessages.js      # Message fetching hook
```



## Component Design

### 1. Authentication Service (`authService.js`)

Responsible for user registration, login, and JWT session management.

```javascript
// authService.js - Core interface
class AuthService {
  constructor(db, pkiService) { /* inject dependencies */ }

  async register(username, password) {
    // 1. Validate inputs (length constraints)
    // 2. Check username uniqueness
    // 3. Hash password with bcrypt (12 rounds)
    // 4. Generate 2048-bit RSA key pair
    // 5. Request certificate from PKI service
    // 6. Store user record in transaction
    // 7. Return { userId, username }
  }

  async login(username, password) {
    // 1. Look up user by username
    // 2. Compare password with bcrypt hash
    // 3. Generate JWT { userId, username, role } with 24h expiry
    // 4. Log event via AuditLogger
    // 5. Return { token }
  }

  verifyToken(token) {
    // 1. Verify JWT signature (HS256)
    // 2. Check expiration
    // 3. Return decoded payload or throw
  }
}
```

**Password Hashing**: bcrypt with 12 salt rounds. This provides ~300ms computation per hash on modern hardware, making brute-force attacks expensive.

**JWT Configuration**:
- Algorithm: HS256
- Secret: 256-bit random key from environment variable
- Expiry: 24 hours
- Payload: `{ userId, username, role, iat, exp }`

### 2. PKI Service (`pkiService.js`)

Manages the internal Certificate Authority, certificate issuance, verification, and revocation.

```javascript
// pkiService.js - Core interface
class PKIService {
  constructor(db) { /* inject dependencies */ }

  initialize() {
    // 1. Check if CA exists in DB
    // 2. If not, generate 4096-bit RSA key pair
    // 3. Create self-signed CA certificate
    // 4. Initialize CRL as empty array
    // 5. Create 3 relay nodes with 2048-bit keys and certificates
  }

  issueCertificate(subjectName, publicKey) {
    // 1. Create certificate object:
    //    { subject, publicKey, issuer: "DarkTunnel-CA",
    //      serialNumber, notBefore, notAfter, version: 1 }
    // 2. Compute canonical JSON of cert body
    // 3. Sign with CA private key using RSA-PSS SHA-256
    // 4. Return { ...certBody, signature }
  }

  verifyCertificate(certificate) {
    // 1. Check temporal validity (notBefore <= now <= notAfter)
    // 2. Check serial not in CRL
    // 3. Verify CA signature over canonical cert body
    // 4. Return { valid: true } or { valid: false, reason: string }
  }

  revokeCertificate(serialNumber) {
    // 1. Add serial to CRL
    // 2. Persist updated CRL
    // 3. Log revocation event
  }
}
```

**Certificate Format** (JSON):
```json
{
  "version": 1,
  "serialNumber": "1001",
  "subject": "alice",
  "issuer": "DarkTunnel-CA",
  "publicKey": "<PEM-encoded RSA public key>",
  "notBefore": 1704067200,
  "notAfter": 1735689600,
  "signature": "<Base64-encoded RSA-PSS signature>"
}
```

**Canonical JSON**: Sorted keys, no whitespace, UTF-8 encoding. Used as the signing input to ensure deterministic signature verification.



### 3. Encryption Service (`encryptionService.js`)

Performs hybrid encryption and constructs multi-layered onion packets.

```javascript
// encryptionService.js - Core interface
class EncryptionService {
  constructor(pkiService) { /* inject dependencies */ }

  createOnionPacket(plaintext, senderPrivateKey, senderCert) {
    // 1. Verify all 3 relay node certificates
    // 2. Sign plaintext with sender's RSA-PSS key
    // 3. Generate nonce (16 bytes) and timestamp
    // 4. Layer 3 (innermost - Node C):
    //    a. Generate random AES-256 key (32 bytes)
    //    b. Encrypt (plaintext + signature) with AES-256-GCM
    //    c. Wrap AES key with Node C's RSA public key (RSA-OAEP)
    // 5. Layer 2 (middle - Node B):
    //    a. Generate random AES-256 key (32 bytes)
    //    b. Encrypt (layer3_output) with AES-256-GCM
    //    c. Wrap AES key with Node B's RSA public key
    // 6. Layer 1 (outermost - Node A):
    //    a. Generate random AES-256 key (32 bytes)
    //    b. Encrypt (layer2_output) with AES-256-GCM
    //    c. Wrap AES key with Node A's RSA public key
    // 7. Delete all ephemeral keys from memory
    // 8. Return onion packet with metadata
  }
}
```

**Onion Packet Structure**:
```json
{
  "version": 1,
  "nonce": "<16 bytes hex>",
  "timestamp": 1704067200,
  "senderId": 1,
  "senderCertSerial": "1001",
  "layers": {
    "wrappedKey": "<RSA-OAEP wrapped AES key for Node A>",
    "iv": "<12 bytes hex>",
    "tag": "<16 bytes hex>",
    "ciphertext": "<encrypted payload containing next layers>"
  }
}
```

**Encryption Parameters**:
- AES-256-GCM: 32-byte key, 12-byte IV (crypto.randomBytes), 16-byte auth tag
- RSA-OAEP: SHA-256 hash, SHA-256 MGF1, for wrapping 32-byte AES keys
- Each layer generates its own independent AES key via `crypto.randomBytes(32)`

### 4. Relay Engine (`relayEngine.js`)

Processes onion packets through the three-node simulated relay.

```javascript
// relayEngine.js - Core interface
class RelayEngine {
  constructor(pkiService, signatureService, auditLogger) { /* inject */ }

  async processPacket(onionPacket) {
    // 1. Validate nonce (not seen in last 60s)
    // 2. Validate timestamp (within 60s of server time)
    // 3. Process Node A:
    //    a. Verify Node A certificate
    //    b. Unwrap AES key with Node A private key (RSA-OAEP)
    //    c. Decrypt layer 1 (AES-256-GCM)
    // 4. Process Node B:
    //    a. Verify Node B certificate
    //    b. Unwrap AES key with Node B private key
    //    c. Decrypt layer 2
    // 5. Process Node C:
    //    a. Verify Node C certificate
    //    b. Unwrap AES key with Node C private key
    //    c. Decrypt layer 3 → plaintext + signature
    // 6. Verify sender signature on plaintext
    // 7. Store nonce to prevent replay
    // 8. Return decrypted message
  }
}
```

**Error Handling in Relay**:
- Decryption failure at any node → halt immediately, mark message "failed"
- Certificate validation failure → halt, log "certificate_trust_failure"
- Signature verification failure → mark "signature-invalid"
- Replay detected → reject, log "replay_attack_detected"
- Timestamp out of window → reject, log "timestamp_validation_failure"



### 5. Signature Service (`signatureService.js`)

Handles RSA-PSS digital signatures for message authentication.

```javascript
// signatureService.js - Core interface
class SignatureService {
  sign(plaintext, privateKey) {
    // 1. Create SHA-256 hash of plaintext
    // 2. Sign with RSA-PSS (saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN)
    // 3. Return base64-encoded signature
  }

  verify(plaintext, signature, publicKey) {
    // 1. Create SHA-256 hash of plaintext
    // 2. Verify RSA-PSS signature against public key
    // 3. Return boolean
  }
}
```

**Parameters**:
- Algorithm: RSA-PSS with SHA-256
- Salt length: Maximum (equal to hash length, 32 bytes)
- Key size: 2048-bit for users

### 6. Message Service (`messageService.js`)

Manages the message lifecycle from creation through delivery.

```javascript
// messageService.js - Core interface
class MessageService {
  constructor(db, encryptionService, relayEngine, auditLogger) { /* inject */ }

  async sendMessage(userId, content) {
    // 1. Create message record (status: "pending")
    // 2. Get sender's private key and certificate
    // 3. Create onion packet via EncryptionService
    // 4. Process packet via RelayEngine
    // 5. Update message status (delivered/failed/signature-invalid)
    // 6. Log event
    // 7. Return message ID and status
  }

  getMessageStatus(messageId, userId) {
    // 1. Look up message by ID
    // 2. Verify sender_id matches userId (else 403)
    // 3. Return { id, status, createdAt }
  }

  getUserMessages(userId) {
    // 1. Query messages where sender_id = userId
    // 2. Return list with { id, status, createdAt }
  }
}
```

### 7. Audit Logger (`auditLogger.js`)

Records all security-relevant events for monitoring and forensics.

```javascript
// auditLogger.js - Core interface
class AuditLogger {
  constructor(db) { /* inject */ }

  log(eventType, details, userId = null) {
    // 1. Sanitize details (remove sensitive fields)
    // 2. Insert into AuditLogs table
    //    { event_type, details: JSON.stringify(sanitized), user_id, timestamp }
  }

  getEntries(filters = {}) {
    // 1. Build query with optional filters (eventType, dateFrom, dateTo)
    // 2. Return paginated results
  }
}
```

**Sensitive Data Exclusion**: The logger strips the following fields before persisting:
- `password`, `password_hash`
- `privateKey`, `private_key`
- `sessionKey`, `aesKey`
- `plaintext` (message content)

**Event Types**:
`user_registered`, `login_success`, `login_failure`, `cert_issued`, `cert_revoked`, `message_sent`, `message_delivered`, `message_failed`, `relay_error`, `replay_detected`, `signature_failure`, `rate_limit_exceeded`



## Data Models

### Database Schema (SQLite with better-sqlite3)

```sql
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  certificate TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  certificate TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  encrypted_payload TEXT NOT NULL,
  decrypted_content TEXT,
  status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'failed', 'signature-invalid')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sender_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  details TEXT,
  user_id INTEGER,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nonces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce TEXT UNIQUE NOT NULL,
  timestamp INTEGER NOT NULL
);

-- Index for nonce lookups within time window
CREATE INDEX IF NOT EXISTS idx_nonces_timestamp ON nonces(timestamp);
-- Index for user message queries
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
-- Index for audit log filtering
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
```

### API Response Format

All API responses follow a consistent JSON structure:

**Success Response**:
```json
{
  "success": true,
  "data": { /* response payload */ },
  "message": "Operation completed successfully"
}
```

**Error Response**:
```json
{
  "success": false,
  "error": "Description of what went wrong"
}
```

**HTTP Status Code Mapping**:
- 200: Successful operation
- 201: Resource created (registration, cert issuance)
- 400: Validation error (invalid input, missing fields)
- 401: Authentication failure (bad credentials, invalid/expired JWT)
- 403: Authorization failure (accessing another user's resources)
- 404: Resource not found
- 429: Rate limit exceeded
- 500: Internal server error (crypto failure, DB error)



## API Endpoints

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | None | Register new user |
| POST | `/api/login` | None | Login and get JWT |

**POST /api/register**
- Request: `{ "username": "alice", "password": "securePass123" }`
- Success (201): `{ "success": true, "data": { "userId": 1, "username": "alice" } }`
- Error (400): `{ "success": false, "error": "Username must be between 3 and 30 characters" }`

**POST /api/login**
- Request: `{ "username": "alice", "password": "securePass123" }`
- Success (200): `{ "success": true, "data": { "token": "<JWT>" } }`
- Error (401): `{ "success": false, "error": "Invalid credentials" }`

### PKI

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/pki/generate-cert` | JWT | Generate certificate for user |
| GET | `/api/pki/verify/:id` | JWT | Verify certificate by serial |
| POST | `/api/pki/revoke` | JWT (admin) | Revoke a certificate |

### Messaging

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/message/send` | JWT | Send encrypted message |
| GET | `/api/message/:id` | JWT | Get message status |
| GET | `/api/messages` | JWT | List user's messages |

**POST /api/message/send**
- Request: `{ "content": "Hello, this is a secret message" }`
- Success (201): `{ "success": true, "data": { "messageId": 42, "status": "delivered" } }`

### Relay

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/relay/process` | Internal | Process onion packet |

### Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin/logs` | JWT (admin) | Get audit logs |

**GET /api/admin/logs?eventType=login_failure&from=2024-01-01&to=2024-12-31**
- Success (200): `{ "success": true, "data": { "logs": [...], "total": 42 } }`

## Middleware

### Authentication Middleware (`authMiddleware.js`)

```javascript
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { userId, username, role }
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
}
```

### Rate Limiter (`rateLimiter.js`)

```javascript
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                   // 100 requests per window per IP
  standardHeaders: true,
  handler: (req, res) => {
    auditLogger.log('rate_limit_exceeded', { ip: req.ip });
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later'
    });
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                     // 5 failed attempts per window
  skipSuccessfulRequests: true
});
```

### Input Validator (`validator.js`)

Validates request bodies against predefined schemas. Uses field-level validation:
- Required fields: checks existence and non-empty
- Type validation: string, number, etc.
- Length constraints: min/max for strings
- Pattern matching: alphanumeric usernames
- Sanitization: strips HTML entities, trims whitespace



## Cryptographic Operations

### AES-256-GCM Encryption (`crypto/aesGcm.js`)

```javascript
const crypto = require('crypto');

function encrypt(plaintext, key) {
  // key: 32 bytes, iv: 12 bytes (NIST recommended for GCM)
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return { ciphertext: encrypted, iv, tag };
}

function decrypt(ciphertext, key, iv, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
}
```

### RSA-OAEP Key Wrapping (`crypto/rsaOaep.js`)

```javascript
function wrapKey(aesKey, publicKey) {
  return crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, aesKey);
}

function unwrapKey(wrappedKey, privateKey) {
  return crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, wrappedKey);
}
```

### RSA-PSS Signing (`crypto/rsaPss.js`)

```javascript
function sign(data, privateKey) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(data);
  return signer.sign({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
  });
}

function verify(data, signature, publicKey) {
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(data);
  return verifier.verify({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
  }, signature);
}
```

### Key Generation (`crypto/keyGen.js`)

```javascript
function generateKeyPair(modulusLength = 2048) {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function generateCAKeyPair() {
  return generateKeyPair(4096);
}
```

## Onion Encryption Flow (Detailed)

```
Input: plaintext message M, sender private key SK_s

Step 1: Sign
  signature = RSA-PSS-SHA256(M, SK_s)
  payload = { message: M, signature: signature, senderId: id }

Step 2: Layer 3 (Node C - innermost)
  key_c = crypto.randomBytes(32)
  iv_c = crypto.randomBytes(12)
  { ciphertext_3, tag_c } = AES-256-GCM(JSON(payload), key_c, iv_c)
  wrapped_key_c = RSA-OAEP(key_c, PK_nodeC)
  layer_3 = { wrappedKey: wrapped_key_c, iv: iv_c, tag: tag_c, data: ciphertext_3 }

Step 3: Layer 2 (Node B - middle)
  key_b = crypto.randomBytes(32)
  iv_b = crypto.randomBytes(12)
  { ciphertext_2, tag_b } = AES-256-GCM(JSON(layer_3), key_b, iv_b)
  wrapped_key_b = RSA-OAEP(key_b, PK_nodeB)
  layer_2 = { wrappedKey: wrapped_key_b, iv: iv_b, tag: tag_b, data: ciphertext_2 }

Step 4: Layer 1 (Node A - outermost)
  key_a = crypto.randomBytes(32)
  iv_a = crypto.randomBytes(12)
  { ciphertext_1, tag_a } = AES-256-GCM(JSON(layer_2), key_a, iv_a)
  wrapped_key_a = RSA-OAEP(key_a, PK_nodeA)
  layer_1 = { wrappedKey: wrapped_key_a, iv: iv_a, tag: tag_a, data: ciphertext_1 }

Step 5: Construct Packet
  onionPacket = {
    version: 1,
    nonce: crypto.randomBytes(16).toString('hex'),
    timestamp: Math.floor(Date.now() / 1000),
    senderId: userId,
    senderCertSerial: certSerial,
    layers: layer_1
  }

Step 6: Cleanup
  key_a = key_b = key_c = null  // Delete ephemeral keys
```



## Relay Decryption Flow (Detailed)

```
Input: onionPacket

Step 1: Validate Metadata
  if nonce in nonce_cache → REJECT (replay)
  if |timestamp - server_time| > 60 → REJECT (stale)

Step 2: Node A Decryption
  verify_cert(nodeA.certificate, CA)
  key_a = RSA-OAEP-Unwrap(packet.layers.wrappedKey, SK_nodeA)
  layer_2_json = AES-256-GCM-Decrypt(packet.layers.data, key_a, packet.layers.iv, packet.layers.tag)
  layer_2 = JSON.parse(layer_2_json)

Step 3: Node B Decryption
  verify_cert(nodeB.certificate, CA)
  key_b = RSA-OAEP-Unwrap(layer_2.wrappedKey, SK_nodeB)
  layer_3_json = AES-256-GCM-Decrypt(layer_2.data, key_b, layer_2.iv, layer_2.tag)
  layer_3 = JSON.parse(layer_3_json)

Step 4: Node C Decryption
  verify_cert(nodeC.certificate, CA)
  key_c = RSA-OAEP-Unwrap(layer_3.wrappedKey, SK_nodeC)
  payload_json = AES-256-GCM-Decrypt(layer_3.data, key_c, layer_3.iv, layer_3.tag)
  payload = JSON.parse(payload_json)

Step 5: Verify Signature
  senderCert = lookup(packet.senderCertSerial)
  verify_cert(senderCert, CA)
  valid = RSA-PSS-Verify(payload.message, payload.signature, senderCert.publicKey)
  if !valid → status = "signature-invalid"

Step 6: Store Nonce and Return
  store_nonce(packet.nonce, packet.timestamp)
  return { plaintext: payload.message, status: "delivered" }
```

## Frontend Architecture

### Auth Context (`context/AuthContext.jsx`)

```javascript
// Provides auth state to all components
const AuthContext = createContext({
  user: null,       // { userId, username, role }
  token: null,      // JWT string
  login: () => {},  // (username, password) => Promise
  logout: () => {}, // Clears localStorage and state
  isAuthenticated: false,
  isAdmin: false
});
```

- JWT stored in `localStorage` under key `darktunnel_token`
- On mount, checks localStorage for existing valid JWT
- Axios interceptor adds `Authorization: Bearer <token>` to all requests
- On 401 response, auto-clears token and redirects to login

### Page Components

**LandingPage**: Hero section with animated background, feature cards (PKI, Onion Routing, E2E Encryption), CTA buttons for Register/Login.

**RegisterPage / LoginPage**: Centered form cards with glassmorphism effect. Client-side validation with inline error messages. Submit triggers API call and redirects on success.

**DashboardPage**: Grid of info cards showing:
- User identity (username, registration date)
- Certificate status (valid/expired badge)
- Message stats (sent count, delivered count, failed count)
- Quick-action navigation cards

**SendMessagePage**: Text area for message composition, send button, and a real-time progress indicator showing:
1. "Signing message..." 
2. "Encrypting Layer 3 (Node C)..."
3. "Encrypting Layer 2 (Node B)..."
4. "Encrypting Layer 1 (Node A)..."
5. "Routing through relay network..."
6. "Message delivered!" or "Error: ..."

**TrackingPage**: Table/list view of sent messages with status badges:
- Green badge: "Delivered"
- Yellow badge: "Pending"  
- Red badge: "Failed" / "Signature Invalid"

**AdminLogsPage**: Filterable table of audit log entries with:
- Event type dropdown filter
- Date range picker
- Paginated results
- Admin role check on mount (redirect if non-admin)

### Styling

- **Theme**: Dark mode with CSS custom properties for color tokens
- **Glassmorphism**: `backdrop-filter: blur(10px)`, semi-transparent backgrounds
- **Typography**: Monospace accents for crypto-related data (hashes, certificates)
- **Color Palette**: Dark grays (#1a1a2e, #16213e), accent cyan (#00d4ff), success green (#10b981), warning amber (#f59e0b), error red (#ef4444)



## Error Handling Strategy

### Backend Error Hierarchy

```
AppError (base)
├── ValidationError (400) - Input validation failures
├── AuthenticationError (401) - Invalid credentials or token
├── AuthorizationError (403) - Insufficient permissions
├── NotFoundError (404) - Resource doesn't exist
├── RateLimitError (429) - Too many requests
└── CryptoError (500) - Encryption/decryption/signature failures
    ├── DecryptionFailure - AES-GCM tag mismatch
    ├── KeyUnwrapFailure - RSA-OAEP unwrap error
    ├── SignatureInvalid - RSA-PSS verification failed
    └── CertificateInvalid - Certificate validation failed
```

### Global Error Handler

```javascript
function errorHandler(err, req, res, next) {
  auditLogger.log(err.eventType || 'internal_error', {
    path: req.path,
    method: req.method,
    message: err.message
  }, req.user?.userId);

  const status = err.statusCode || 500;
  res.status(status).json({
    success: false,
    error: status === 500 ? 'Internal server error' : err.message
  });
}
```

### Frontend Error Handling

- API errors caught by Axios interceptor
- 401 errors trigger auto-logout
- 429 errors display retry countdown
- Network errors show "Connection lost" toast
- All errors display user-friendly messages (never raw stack traces)

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| MITM Attack | Certificate validation before every crypto operation |
| Replay Attack | Nonce + 60-second timestamp window |
| Tampered Messages | AES-GCM authentication tag + RSA-PSS signatures |
| Brute Force Login | bcrypt (12 rounds) + rate limiting (5 attempts/15min) |
| SQL Injection | Parameterized queries (better-sqlite3 prepared statements) |
| XSS | Input sanitization + React's built-in escaping |
| Key Compromise | Forward secrecy via ephemeral per-message keys |
| Token Theft | 24h JWT expiry + secure storage recommendations |

### Key Management

- CA private key: Stored in nodes table (in production would be HSM-backed)
- User private keys: Stored encrypted in users table (AES-256-GCM with password-derived key)
- Relay node private keys: Stored in nodes table (server-side only, never exposed via API)
- Ephemeral keys: Exist only in memory during encryption, nullified after use
- JWT secret: Environment variable, minimum 256 bits

## Configuration

```javascript
// config/constants.js
module.exports = {
  BCRYPT_ROUNDS: 12,
  JWT_EXPIRY: '24h',
  JWT_ALGORITHM: 'HS256',
  AES_KEY_LENGTH: 32,        // 256 bits
  AES_IV_LENGTH: 12,         // 96 bits (NIST GCM recommendation)
  AES_TAG_LENGTH: 16,        // 128 bits
  RSA_CA_KEY_SIZE: 4096,
  RSA_USER_KEY_SIZE: 2048,
  RSA_NODE_KEY_SIZE: 2048,
  NONCE_LENGTH: 16,          // 128 bits
  NONCE_WINDOW_SECONDS: 60,
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,  // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 100,
  RATE_LIMIT_MAX_LOGIN: 5,
  RELAY_NODES: ['NodeA', 'NodeB', 'NodeC'],
  CERT_VALIDITY_DAYS: 365
};
```



## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Onion Encryption Round-Trip

For any plaintext message and valid sender key pair, constructing an onion packet (encrypting through layers for Node C, Node B, Node A) and then processing it through the relay engine (decrypting Node A → Node B → Node C) SHALL recover the original plaintext message with a "delivered" status.

**Validates: Requirements 4.1, 4.3, 4.4**

### Property 2: Invalid Input Rejection on Registration

For any username string of length less than 3 or greater than 30, OR any password string of length less than 8, the Authentication_Service SHALL reject the registration request with a validation error and no user record shall be created in the database.

**Validates: Requirements 1.3, 1.4**

### Property 3: Duplicate Username Rejection

For any valid username, if a user with that username already exists in the database, a subsequent registration attempt with the same username SHALL be rejected with an error, regardless of the password provided.

**Validates: Requirements 1.2**

### Property 4: Login Produces Valid JWT

For any registered user, logging in with the correct password SHALL return a JWT that, when decoded, contains the user's ID, username, and an expiration time exactly 24 hours from issuance.

**Validates: Requirements 2.1**

### Property 5: Authentication Error Indistinguishability

For any login attempt that fails (whether due to non-existent username or incorrect password), the error response message SHALL be identical, preventing an attacker from determining which field was incorrect.

**Validates: Requirements 2.2**

### Property 6: Invalid JWT Rejection

For any malformed, expired, or incorrectly-signed JWT, all protected API endpoints SHALL return a 401 status code and deny access.

**Validates: Requirements 2.3**

### Property 7: Certificate Issuance Completeness

For any valid subject name and RSA public key, a certificate issued by the PKI_Service SHALL contain all required fields (subject, publicKey, issuer, serialNumber, notBefore, notAfter, version, signature), and the signature SHALL be verifiable using the CA's public key.

**Validates: Requirements 3.2**

### Property 8: Certificate Verification Correctness

For any certificate issued by the CA that is within its validity period and whose serial number is NOT in the CRL, verification SHALL succeed. For any certificate that is expired, revoked, or has a tampered signature, verification SHALL fail with a specific reason string identifying the failure type.

**Validates: Requirements 3.3, 3.6**

### Property 9: Revocation Invalidates Certificates

For any valid certificate, after its serial number is added to the CRL via revocation, subsequent verification of that certificate SHALL fail with reason "revoked".

**Validates: Requirements 3.4**

### Property 10: RSA-OAEP Key Wrap Round-Trip

For any 32-byte AES key and any relay node RSA key pair, wrapping the AES key with the node's public key (RSA-OAEP SHA-256) and then unwrapping with the node's private key SHALL recover the original AES key byte-for-byte.

**Validates: Requirements 4.2, 5.2**

### Property 11: Tampered Ciphertext Detection

For any valid onion packet, if any byte of the encrypted data is modified after encryption, the relay engine SHALL detect the tampering (via AES-GCM authentication tag mismatch), halt processing, and mark the message as "failed".

**Validates: Requirements 4.5**

### Property 12: Encryption Layer Structure

For any encryption operation, each layer of the onion packet SHALL contain a wrapped key (RSA-OAEP encrypted), a 12-byte IV, a 16-byte authentication tag, and ciphertext; and all three layers SHALL use distinct AES-256 keys (32 bytes each).

**Validates: Requirements 5.1, 5.3, 5.4**

### Property 13: Digital Signature Round-Trip

For any plaintext message and user RSA key pair, signing the message with the private key (RSA-PSS SHA-256) and then verifying with the corresponding public key SHALL succeed. If the plaintext is altered after signing, verification SHALL fail.

**Validates: Requirements 6.1, 6.2, 6.3**

### Property 14: Replay Attack Rejection

For any valid onion packet, if the same nonce is submitted twice within a 60-second window, the second submission SHALL be rejected with a replay attack error.

**Validates: Requirements 8.2, 8.3**

### Property 15: Timestamp Window Enforcement

For any onion packet whose timestamp differs from the server time by more than 60 seconds (either in the past or future), the relay engine SHALL reject the packet with a timestamp validation failure.

**Validates: Requirements 8.4**

### Property 16: Input Validation Rejects Invalid Schemas

For any API request body that is missing required fields, contains fields with incorrect types, or has string fields exceeding maximum length, the Backend SHALL reject the request with a 400 status code.

**Validates: Requirements 10.1, 10.3**

### Property 17: Message Ownership Authorization

For any message in the database, querying its status with a JWT belonging to a different user (not the sender) SHALL return a 403 forbidden response.

**Validates: Requirements 11.3**

### Property 18: Audit Log Completeness and Safety

For any audit log entry persisted to the database, it SHALL contain event_type, timestamp, and outcome fields; and it SHALL NOT contain any of the following sensitive values: password hashes, private keys, session keys, or plaintext message content.

**Validates: Requirements 12.2, 12.4**

### Property 19: Certificate Trust Required for Relay

For any relay node whose certificate is invalid, revoked, or expired, attempting to process an onion packet through that node SHALL halt with a certificate trust failure error, preventing any decryption from occurring.

**Validates: Requirements 4.6, 20.1, 20.2, 20.3**

### Property 20: Client-Side Validation Consistency

For any username input of length less than 3 or greater than 30, or any password input of length less than 8, the frontend registration form SHALL display a validation error and prevent form submission, matching the backend validation rules.

**Validates: Requirements 13.2**

### Property 21: Session Expiry Redirect

For any expired or missing JWT in the frontend auth context, navigation to any protected page (Dashboard, Send Message, Tracking, Admin Logs) SHALL redirect the user to the login page.

**Validates: Requirements 14.3**

### Property 22: Consistent API Response Format

For any successful API response, the response body SHALL contain `{ success: true, data: object }`. For any error API response, the response body SHALL contain `{ success: false, error: string }` with an HTTP status code matching the error category.

**Validates: Requirements 19.1, 19.2**
