/**
 * DarkTunnel PKI Web - Database Initialization
 * 
 * Uses better-sqlite3 for synchronous SQLite operations.
 * Creates the database file and all required tables on first run.
 * 
 * Tables:
 * - users: Registered user accounts with keys and certificates
 * - nodes: Relay nodes (NodeA, NodeB, NodeC) with their crypto material
 * - messages: Encrypted message records with delivery status
 * - audit_logs: Security event records for monitoring and forensics
 * - nonces: Seen nonces for replay attack protection (60s window)
 */

const path = require('path');
const fs = require('fs');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const DB_PATH = process.env.DB_PATH || './data/darktunnel.db';

// Ensure the data directory exists before opening the database
const dbDir = path.dirname(path.resolve(__dirname, '..', DB_PATH));
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const Database = require('better-sqlite3');
const db = new Database(path.resolve(__dirname, '..', DB_PATH));

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
// Enable foreign key enforcement
db.pragma('foreign_keys = ON');

/**
 * Initialize all database tables and indexes.
 * Uses IF NOT EXISTS to be idempotent (safe to call multiple times).
 */
function initializeDatabase() {
  // Users table - stores registered accounts with their cryptographic identity
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key TEXT NOT NULL,
      private_key TEXT NOT NULL,
      certificate TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Nodes table - relay nodes with their RSA keys and CA-issued certificates
  db.exec(`
    CREATE TABLE IF NOT EXISTS nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      private_key TEXT NOT NULL,
      certificate TEXT NOT NULL
    )
  `);

  // Messages table - encrypted message records with delivery tracking
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      encrypted_payload TEXT NOT NULL,
      decrypted_content TEXT,
      status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'failed', 'signature-invalid')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users(id)
    )
  `);

  // Audit logs table - security event records for monitoring and forensics
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      details TEXT,
      user_id INTEGER,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Nonces table - tracks seen nonces to prevent replay attacks
  db.exec(`
    CREATE TABLE IF NOT EXISTS nonces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nonce TEXT UNIQUE NOT NULL,
      timestamp INTEGER NOT NULL
    )
  `);

  // Indexes for query performance
  db.exec(`CREATE INDEX IF NOT EXISTS idx_nonces_timestamp ON nonces(timestamp)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)`);

  console.log('[DB] Database initialized successfully');
}

// Run initialization on module load
initializeDatabase();

module.exports = db;
