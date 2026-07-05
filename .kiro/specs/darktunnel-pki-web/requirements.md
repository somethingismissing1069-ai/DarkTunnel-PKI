# Requirements Document

## Introduction

DarkTunnel PKI Web is a full-stack web application that provides anonymous communication through simulated onion routing and a Public Key Infrastructure (PKI) system. The application enables users to send encrypted messages that traverse a simulated three-node relay network (similar to Tor), where each node peels one encryption layer. The system uses hybrid encryption (AES-256-GCM + RSA), digital signatures, forward secrecy with ephemeral keys, and a complete certificate lifecycle with an internal Certificate Authority. The frontend provides a dark-themed cybersecurity-styled interface built with React and Tailwind CSS, while the backend uses Node.js with Express and SQLite for persistence.

## Glossary

- **System**: The DarkTunnel PKI Web application as a whole (frontend, backend, and relay simulation)
- **Backend**: The Node.js + Express server handling API requests, cryptography, and relay simulation
- **Frontend**: The React-based browser UI providing user interaction
- **Authentication_Service**: The backend component responsible for user registration, login, and JWT session management
- **PKI_Service**: The backend component managing the internal Certificate Authority, certificate issuance, verification, and revocation
- **Relay_Engine**: The backend component simulating the three-node onion routing path (Node A, Node B, Node C)
- **Encryption_Service**: The backend component performing hybrid encryption (AES-256-GCM for data, RSA for key wrapping) and layered onion encryption
- **Signature_Service**: The backend component responsible for creating and verifying digital signatures on messages
- **Message_Service**: The backend component handling message creation, storage, and retrieval
- **Audit_Logger**: The backend component recording security events and system activities
- **Relay_Node**: One of three simulated nodes (A, B, or C) in the onion routing path, each possessing its own RSA key pair and certificate
- **Onion_Packet**: A multi-layered encrypted payload where each layer is decryptable only by its corresponding Relay_Node
- **Certificate**: A JSON-based digital certificate binding a public key to an identity, signed by the internal CA
- **CRL**: Certificate Revocation List — a list of revoked certificate serial numbers maintained by the PKI_Service
- **Ephemeral_Key**: A per-session cryptographic key used once and then discarded, providing forward secrecy
- **JWT**: JSON Web Token used for authenticating API requests after login
- **Nonce**: A unique random value included in messages to prevent replay attacks
- **Rate_Limiter**: The backend middleware restricting the number of API requests per client within a time window

## Requirements

### Requirement 1: User Registration

**User Story:** As a new user, I want to register an account with a username and password, so that I can access the anonymous communication system.

#### Acceptance Criteria

1. WHEN a registration request is received with a valid username and password, THE Authentication_Service SHALL hash the password using bcrypt, generate an RSA key pair for the user, request a certificate from the PKI_Service, store the user record (username, password hash, public key, certificate) in the database, and return a success response with the user ID.
2. WHEN a registration request is received with a username that already exists in the database, THE Authentication_Service SHALL reject the request and return an error indicating the username is taken.
3. WHEN a registration request is received with a password shorter than 8 characters, THE Authentication_Service SHALL reject the request and return a validation error.
4. WHEN a registration request is received with a username shorter than 3 characters or longer than 30 characters, THE Authentication_Service SHALL reject the request and return a validation error.
5. IF the key generation or certificate issuance fails during registration, THEN THE Authentication_Service SHALL roll back the user record and return an internal error response.

### Requirement 2: User Login

**User Story:** As a registered user, I want to log in with my credentials, so that I receive a session token to access protected endpoints.

#### Acceptance Criteria

1. WHEN a login request is received with a valid username and correct password, THE Authentication_Service SHALL verify the password against the stored bcrypt hash, generate a JWT containing the user ID and username with a 24-hour expiration, and return the JWT in the response body.
2. WHEN a login request is received with an invalid username or incorrect password, THE Authentication_Service SHALL return an authentication error without revealing which field is incorrect.
3. WHILE a request targets a protected API endpoint, THE Backend SHALL verify the JWT from the Authorization header and reject the request with a 401 status if the token is missing, expired, or invalid.

### Requirement 3: Certificate Authority and PKI

**User Story:** As a system operator, I want an internal Certificate Authority that issues and manages certificates for users and relay nodes, so that all communication participants have verified identities.

#### Acceptance Criteria

1. WHEN the Backend starts for the first time, THE PKI_Service SHALL initialize a root CA by generating a 4096-bit RSA key pair and creating a self-signed CA certificate if no CA exists.
2. WHEN a certificate generation request is received for a valid user or relay node, THE PKI_Service SHALL create a JSON certificate containing the subject name, public key, issuer, serial number, validity period (default 365 days), and sign the certificate with the CA private key using RSA-PSS with SHA-256.
3. WHEN a certificate verification request is received, THE PKI_Service SHALL validate the certificate by checking temporal validity (not expired, not before start date), checking the serial number against the CRL, and verifying the CA signature over the certificate content.
4. WHEN a certificate revocation request is received for a valid serial number, THE PKI_Service SHALL add the serial number to the CRL and persist the updated CRL.
5. THE PKI_Service SHALL maintain three pre-configured Relay_Node entries (Node A, Node B, Node C), each with its own RSA key pair and valid certificate.
6. IF a certificate fails any validation check (expired, revoked, or invalid signature), THEN THE PKI_Service SHALL return a rejection with the specific failure reason.

### Requirement 4: Onion Routing Simulation

**User Story:** As a user, I want my messages to be routed through three simulated relay nodes with layered encryption, so that no single node can read the complete message.

#### Acceptance Criteria

1. WHEN a message send request is received, THE Encryption_Service SHALL construct an Onion_Packet by encrypting the plaintext message with a unique AES-256-GCM session key for Node C (innermost layer), then encrypting the result with a unique AES-256-GCM session key for Node B (middle layer), then encrypting the result with a unique AES-256-GCM session key for Node A (outermost layer).
2. THE Encryption_Service SHALL wrap each AES session key with the corresponding Relay_Node RSA public key using RSA-OAEP with SHA-256, and include the wrapped key in each encryption layer.
3. WHEN the Relay_Engine receives an Onion_Packet, THE Relay_Engine SHALL process the packet sequentially through Node A, Node B, and Node C, where each node unwraps its AES key using its RSA private key and decrypts its corresponding layer.
4. WHEN Node C completes decryption of the final layer, THE Relay_Engine SHALL extract the plaintext message and store it with a delivered status in the database.
5. IF any Relay_Node fails to decrypt its layer (invalid key, tampered ciphertext, or authentication tag mismatch), THEN THE Relay_Engine SHALL halt processing, log the failure event, mark the message as failed, and return an error response.
6. THE Relay_Engine SHALL verify the certificate of each Relay_Node against the CA before processing each layer.

### Requirement 5: Hybrid Encryption

**User Story:** As a user, I want messages encrypted using both symmetric and asymmetric cryptography, so that I benefit from the speed of AES and the key distribution of RSA.

#### Acceptance Criteria

1. THE Encryption_Service SHALL use AES-256-GCM with a 12-byte random IV and 16-byte authentication tag for all symmetric encryption of message data.
2. THE Encryption_Service SHALL use RSA-OAEP with SHA-256 for wrapping AES session keys, using the recipient Relay_Node public key.
3. THE Encryption_Service SHALL generate a fresh random AES-256 key (32 bytes) for each encryption layer using a cryptographically secure random number generator.
4. WHEN encrypting a message, THE Encryption_Service SHALL include the IV, authentication tag, and wrapped key in the encrypted output for each layer.

### Requirement 6: Digital Signatures

**User Story:** As a user, I want to sign my messages so that recipients can verify the message originated from me and has not been altered.

#### Acceptance Criteria

1. WHEN a user sends a message, THE Signature_Service SHALL sign the message plaintext using the sender's RSA private key with RSA-PSS and SHA-256, and include the signature in the message payload.
2. WHEN the Relay_Engine delivers a message, THE Signature_Service SHALL verify the sender's signature against the sender's certificate public key before marking the message as delivered.
3. IF signature verification fails, THEN THE Signature_Service SHALL reject the message, log the verification failure, and mark the message status as signature-invalid.

### Requirement 7: Forward Secrecy

**User Story:** As a user, I want each messaging session to use ephemeral keys, so that compromise of long-term keys does not reveal past messages.

#### Acceptance Criteria

1. WHEN the Encryption_Service generates AES session keys for onion layers, THE Encryption_Service SHALL use a unique Ephemeral_Key for each message send operation.
2. THE Encryption_Service SHALL delete all Ephemeral_Keys and derived AES session keys from memory immediately after the onion encryption is complete.
3. THE Encryption_Service SHALL generate Ephemeral_Keys using a cryptographically secure random number generator producing 256 bits of entropy.

### Requirement 8: Replay Protection

**User Story:** As a user, I want the system to reject duplicate or replayed messages, so that an attacker cannot re-send captured packets.

#### Acceptance Criteria

1. WHEN the Encryption_Service creates an Onion_Packet, THE Encryption_Service SHALL include a unique Nonce (16 bytes, randomly generated) and a Unix timestamp in the message metadata.
2. WHEN the Relay_Engine receives an Onion_Packet, THE Relay_Engine SHALL check whether the Nonce has been seen within a 60-second time window.
3. IF the Nonce has been seen previously within the time window, THEN THE Relay_Engine SHALL reject the message and log a replay attack attempt.
4. IF the timestamp in the message metadata differs from the server time by more than 60 seconds, THEN THE Relay_Engine SHALL reject the message and log a timestamp validation failure.

### Requirement 9: Rate Limiting

**User Story:** As a system operator, I want API endpoints protected by rate limiting, so that the system is resilient against abuse and denial-of-service attempts.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL restrict each client IP to a maximum of 100 requests per 15-minute window across all API endpoints.
2. THE Rate_Limiter SHALL restrict each client IP to a maximum of 5 failed login attempts per 15-minute window on the login endpoint.
3. WHEN a client exceeds the rate limit, THE Rate_Limiter SHALL return a 429 status code with a Retry-After header indicating the time until the limit resets.

### Requirement 10: Input Validation

**User Story:** As a system operator, I want all API inputs validated and sanitized, so that the system is protected against injection attacks and malformed data.

#### Acceptance Criteria

1. THE Backend SHALL validate all incoming request bodies against defined schemas before processing, rejecting requests with invalid or missing required fields with a 400 status code.
2. THE Backend SHALL sanitize all string inputs by removing or escaping characters that could enable injection attacks.
3. WHEN a request contains a field exceeding its maximum allowed length, THE Backend SHALL reject the request with a 400 status code and a descriptive error message.

### Requirement 11: Message Sending and Tracking

**User Story:** As a user, I want to send encrypted messages and track their delivery status, so that I know whether my communication was successful.

#### Acceptance Criteria

1. WHEN a send message request is received with valid content and authentication, THE Message_Service SHALL create a message record with status pending, invoke the Encryption_Service to create the Onion_Packet, pass the packet to the Relay_Engine, and update the message status based on the relay result.
2. WHEN a message status query is received for a valid message ID belonging to the authenticated user, THE Message_Service SHALL return the current message status (pending, delivered, or failed) and timestamp.
3. WHEN a message status query is received for a message ID that does not belong to the authenticated user, THE Message_Service SHALL return a 403 forbidden response.
4. THE Message_Service SHALL store the encrypted payload, sender ID, status, and creation timestamp for each message.

### Requirement 12: Audit Logging

**User Story:** As a system administrator, I want all security-relevant events logged, so that I can investigate incidents and monitor system health.

#### Acceptance Criteria

1. THE Audit_Logger SHALL record an event for each of the following operations: user registration, login success, login failure, certificate issuance, certificate revocation, message sent, message delivered, message failed, relay processing error, replay attack detected, signature verification failure, and rate limit exceeded.
2. THE Audit_Logger SHALL include the event type, timestamp, relevant entity ID, and outcome (success or failure) in each log entry.
3. THE Audit_Logger SHALL persist audit log entries to the AuditLogs database table.
4. THE Audit_Logger SHALL exclude sensitive data (passwords, private keys, session keys, plaintext messages) from log entries.

### Requirement 13: Frontend Landing and Authentication Pages

**User Story:** As a user, I want a visually appealing landing page and authentication forms, so that I can understand the system and access my account.

#### Acceptance Criteria

1. THE Frontend SHALL display a landing page with a system description, feature highlights, and navigation to the registration and login pages.
2. THE Frontend SHALL provide a registration form accepting username and password with client-side validation matching the backend rules (username 3-30 characters, password minimum 8 characters).
3. THE Frontend SHALL provide a login form accepting username and password, storing the returned JWT in local storage upon successful authentication.
4. WHEN authentication fails, THE Frontend SHALL display an error message without revealing which field (username or password) was incorrect.
5. THE Frontend SHALL apply a dark theme with glassmorphism styling and cybersecurity-inspired visual design across all pages.

### Requirement 14: Frontend Dashboard

**User Story:** As an authenticated user, I want a dashboard showing my account information and recent activity, so that I have an overview of my communication status.

#### Acceptance Criteria

1. WHEN an authenticated user navigates to the dashboard, THE Frontend SHALL display the username, certificate status (valid or expired), and a summary of recent messages (count of sent, delivered, and failed).
2. THE Frontend SHALL provide navigation cards to the Send Message page and the Message Tracking page.
3. WHILE the user session JWT is expired or missing, THE Frontend SHALL redirect the user to the login page.

### Requirement 15: Frontend Send Message Page

**User Story:** As an authenticated user, I want a page where I can compose and send encrypted messages, so that I can communicate anonymously through the onion routing system.

#### Acceptance Criteria

1. THE Frontend SHALL provide a message composition form with a text input field and a send button.
2. WHEN the user submits a message, THE Frontend SHALL send the message content to the Backend send message API endpoint with the JWT authorization header and display a confirmation or error based on the response.
3. WHILE a message is being processed, THE Frontend SHALL display a loading indicator showing the onion encryption stages (encrypting layers, routing through nodes).

### Requirement 16: Frontend Message Tracking Page

**User Story:** As an authenticated user, I want to view the status of my sent messages, so that I can track delivery progress.

#### Acceptance Criteria

1. WHEN an authenticated user navigates to the message tracking page, THE Frontend SHALL retrieve and display a list of the user's sent messages with their status (pending, delivered, or failed) and timestamp.
2. THE Frontend SHALL visually distinguish message statuses using color coding (green for delivered, yellow for pending, red for failed).

### Requirement 17: Frontend Admin Logs Viewer

**User Story:** As an administrator, I want to view system audit logs, so that I can monitor security events and investigate incidents.

#### Acceptance Criteria

1. WHEN an administrator navigates to the logs viewer page, THE Frontend SHALL retrieve and display audit log entries from the Backend with event type, timestamp, and details.
2. THE Frontend SHALL provide filtering controls to filter logs by event type and date range.
3. WHILE a non-administrator user attempts to access the logs viewer, THE Frontend SHALL deny access and redirect to the dashboard.

### Requirement 18: Database Schema

**User Story:** As a developer, I want a well-defined database schema, so that all application data is persisted reliably with proper relationships.

#### Acceptance Criteria

1. THE Backend SHALL maintain a Users table with columns: id (primary key, auto-increment), username (unique, not null), password_hash (not null), public_key (text, not null), and certificate (text, not null).
2. THE Backend SHALL maintain a Nodes table with columns: id (primary key, auto-increment), name (unique, not null), public_key (text, not null), and certificate (text, not null).
3. THE Backend SHALL maintain a Messages table with columns: id (primary key, auto-increment), sender_id (foreign key to Users), encrypted_payload (text, not null), status (text, not null, one of pending, delivered, or failed), and created_at (timestamp, not null, default current time).
4. THE Backend SHALL maintain an AuditLogs table with columns: id (primary key, auto-increment), event_type (text, not null), details (text), and timestamp (timestamp, not null, default current time).

### Requirement 19: API Structure and Error Handling

**User Story:** As a developer, I want consistent API response formats and error handling, so that the frontend can reliably process responses.

#### Acceptance Criteria

1. THE Backend SHALL return successful responses in JSON format with a structure containing a success boolean, data object, and optional message string.
2. THE Backend SHALL return error responses in JSON format with a structure containing a success boolean (false), error string describing the issue, and HTTP status code appropriate to the error type (400 for validation, 401 for authentication, 403 for authorization, 404 for not found, 429 for rate limit, 500 for internal errors).
3. THE Backend SHALL expose the following API endpoints: POST /api/register, POST /api/login, POST /api/pki/generate-cert, GET /api/pki/verify/:id, POST /api/message/send, GET /api/message/:id, and POST /api/relay/process.

### Requirement 20: MITM Protection

**User Story:** As a user, I want the system to protect against man-in-the-middle attacks, so that I can trust the identity of relay nodes handling my messages.

#### Acceptance Criteria

1. WHEN the Relay_Engine processes an Onion_Packet through a Relay_Node, THE Relay_Engine SHALL validate the Relay_Node certificate against the CA certificate before allowing decryption.
2. IF a Relay_Node certificate is invalid, revoked, or expired, THEN THE Relay_Engine SHALL halt message processing and return an error indicating a certificate trust failure.
3. WHEN the Encryption_Service wraps AES keys for Relay_Nodes, THE Encryption_Service SHALL verify each Relay_Node certificate against the CA before using its public key.
