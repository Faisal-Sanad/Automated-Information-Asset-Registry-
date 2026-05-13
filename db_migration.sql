-- ============================================================
-- Migration: Align database schema with application v2
-- Run once on the Supabase PostgreSQL instance
-- ============================================================

-- 1. Rename reconciliation_findings to discrepancies
ALTER TABLE IF EXISTS reconciliation_findings RENAME TO discrepancies;

-- 2. Add full_match and mixed outcome columns to reconciliation_runs
ALTER TABLE reconciliation_runs
    ADD COLUMN IF NOT EXISTS full_match INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mixed INTEGER NOT NULL DEFAULT 0;

-- 3. Add run_timestamp alias (column already exists as run_at; add alias view)
-- The application uses run_at; thesis refers to run_timestamp.
-- Adding run_timestamp as a generated column for compatibility.
-- (No schema change needed if application consistently uses run_at)

-- 4. Ensure users table has all required fields
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 5. Ensure password_hash column exists (rename password if needed)
-- If the column is named 'password', rename to password_hash:
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'password'
    ) THEN
        ALTER TABLE users RENAME COLUMN password TO password_hash;
    END IF;
END $$;

-- 6. Ensure audit_log has ip_address column
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

-- 7. Ensure discrepancies table has resolved_at and resolved_by
ALTER TABLE discrepancies
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(100);

-- ============================================================
-- Seed default admin user with bcrypt password 'admin123'
-- Hash generated with: bcrypt.hashpw(b'admin123', bcrypt.gensalt())
-- Replace the hash below with a freshly generated one before deployment.
-- ============================================================
INSERT INTO users (username, password_hash, role, full_name)
VALUES (
    'admin',
    '$2b$12$placeholder_replace_with_real_bcrypt_hash',
    'admin',
    'Faisal Sanad'
)
ON CONFLICT (username) DO NOTHING;
