-- ============================================================
-- Migration: Add pending_changes table and registration table
-- Run in Supabase SQL Editor
-- ============================================================

-- 1. Pending changes table (maker-checker)
CREATE TABLE IF NOT EXISTS pending_changes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        VARCHAR(50),
    action          VARCHAR(20) NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    proposed_data   JSONB,
    field_changed   VARCHAR(100),
    old_value       TEXT,
    new_value       TEXT,
    submitted_by    VARCHAR(100) NOT NULL,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    reviewed_by     VARCHAR(100),
    reviewed_at     TIMESTAMPTZ,
    review_comment  TEXT
);

-- 2. Add email and 2FA fields to users table
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS tfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS tfa_code VARCHAR(10),
    ADD COLUMN IF NOT EXISTS tfa_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_approved BOOLEAN NOT NULL DEFAULT TRUE;

-- 3. Add VIEW action to audit_log
-- (no schema change needed - action field is VARCHAR, just start inserting VIEW events)

-- 4. Update existing admin user with email placeholder
UPDATE users SET email = 'faisal.sanad@outlook.com' WHERE username = 'admin';
UPDATE users SET email = 'faisalsanad07@gmail.com' WHERE username = 'viewer';
