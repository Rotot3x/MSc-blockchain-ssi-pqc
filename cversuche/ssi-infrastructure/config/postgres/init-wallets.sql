-- PostgreSQL Initialization Script for ACA-Py Wallets
-- Creates separate databases for each agent wallet

-- Create wallets for Issuer, Holder, and Verifier
CREATE DATABASE issuer_wallet;
CREATE DATABASE holder_wallet;
CREATE DATABASE verifier_wallet;

-- Grant permissions to acapy user
GRANT ALL PRIVILEGES ON DATABASE issuer_wallet TO acapy;
GRANT ALL PRIVILEGES ON DATABASE holder_wallet TO acapy;
GRANT ALL PRIVILEGES ON DATABASE verifier_wallet TO acapy;

-- Connect to each database and enable required extensions
\c issuer_wallet;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

\c holder_wallet;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

\c verifier_wallet;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Return to main database
\c acapy_wallets;

-- Create indexes for better performance
\c issuer_wallet;
CREATE INDEX IF NOT EXISTS idx_items_name ON items(name);
CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);

\c holder_wallet;
CREATE INDEX IF NOT EXISTS idx_items_name ON items(name);
CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);

\c verifier_wallet;
CREATE INDEX IF NOT EXISTS idx_items_name ON items(name);
CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);

-- Return to main database
\c acapy_wallets;