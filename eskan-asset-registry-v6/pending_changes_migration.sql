-- Migration: add pending_changes table and update users for email and reset codes.

-- Pending changes table (maker-checker workflow)
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

-- Add email and reset-code columns to users.
-- (Note: tfa_* columns are used for email-based password-reset codes,
--  not full two-factor authentication. Naming preserved for compatibility.)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS tfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS tfa_code VARCHAR(10),
    ADD COLUMN IF NOT EXISTS tfa_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_approved BOOLEAN NOT NULL DEFAULT TRUE;

-- Backfill emails on the seed admin and viewer accounts
UPDATE users SET email = 'faisal.sanad@outlook.com' WHERE username = 'admin';
UPDATE users SET email = 'faisalsanad07@gmail.com' WHERE username = 'viewer';
