-- Migration: align schema with application v2.

-- Rename reconciliation_findings to discrepancies
ALTER TABLE IF EXISTS reconciliation_findings RENAME TO discrepancies;

-- Add new outcome columns to reconciliation_runs
ALTER TABLE reconciliation_runs
    ADD COLUMN IF NOT EXISTS full_match INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mixed INTEGER NOT NULL DEFAULT 0;

-- Ensure users table has all required fields
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Rename users.password to password_hash if it still has the old name
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'password'
    ) THEN
        ALTER TABLE users RENAME COLUMN password TO password_hash;
    END IF;
END $$;

-- Add ip_address column to audit_log
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

-- Add resolution-tracking columns to discrepancies
ALTER TABLE discrepancies
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(100);

-- Seed default admin user (bcrypt hash of 'admin123' — replace before deployment)
INSERT INTO users (username, password_hash, role, full_name)
VALUES (
    'admin',
    '$2b$12$placeholder_replace_with_real_bcrypt_hash',
    'admin',
    'Faisal Sanad'
)
ON CONFLICT (username) DO NOTHING;
