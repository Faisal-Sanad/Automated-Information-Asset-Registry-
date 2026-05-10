-- Migration: rebuild compliance_dashboard view with strict 9-field logic.
-- Safe to re-run; uses CREATE OR REPLACE VIEW.

-- The view is the canonical source of compliance status, consumed by:
--   GET /api/stats        (dashboard counts)
--   GET /api/dashboard    (compliance table)
--   report.py             (Excel report Compliance Dashboard sheet)
--   main.py               (CLI compliance dashboard)
--
-- An asset is Compliant only when all 9 mandatory fields are populated.
-- This matches MANDATORY_ASSET_FIELDS in app.py and MANDATORY_FIELDS in
-- reconciliation.py.
--
-- Mandatory fields (CBB OM-5.5 / ISO 27001 A.5.9 alignment):
--   asset_id, system_name, data_category, data_owner, data_classification,
--   encryption_in_transit, encryption_at_rest, retention_period, control_mapping.
--
-- Review status is derived from last_review_date:
--   'Up to Date'     reviewed within the last 12 months
--   'Review Overdue' reviewed more than 12 months ago
--   'Never Reviewed' last_review_date is NULL


CREATE OR REPLACE VIEW compliance_dashboard AS
WITH field_status AS (
    SELECT
        asset_id,
        system_name,
        data_classification,
        data_category,
        last_review_date,
        -- Count populated mandatory fields
        (CASE WHEN asset_id             IS NOT NULL AND TRIM(COALESCE(asset_id::text, ''))             != '' THEN 1 ELSE 0 END +
         CASE WHEN system_name          IS NOT NULL AND TRIM(COALESCE(system_name::text, ''))          != '' THEN 1 ELSE 0 END +
         CASE WHEN data_category        IS NOT NULL AND TRIM(COALESCE(data_category::text, ''))        != '' THEN 1 ELSE 0 END +
         CASE WHEN data_owner           IS NOT NULL AND TRIM(COALESCE(data_owner::text, ''))           != '' THEN 1 ELSE 0 END +
         CASE WHEN data_classification  IS NOT NULL AND TRIM(COALESCE(data_classification::text, ''))  != '' THEN 1 ELSE 0 END +
         CASE WHEN encryption_in_transit IS NOT NULL AND TRIM(COALESCE(encryption_in_transit::text, '')) != '' THEN 1 ELSE 0 END +
         CASE WHEN encryption_at_rest   IS NOT NULL AND TRIM(COALESCE(encryption_at_rest::text, ''))   != '' THEN 1 ELSE 0 END +
         CASE WHEN retention_period     IS NOT NULL AND TRIM(COALESCE(retention_period::text, ''))     != '' THEN 1 ELSE 0 END +
         CASE WHEN control_mapping      IS NOT NULL AND TRIM(COALESCE(control_mapping::text, ''))      != '' THEN 1 ELSE 0 END
        ) AS mandatory_score,
        -- Build a comma-separated list of missing field names for display
        TRIM(BOTH ', ' FROM CONCAT_WS(', ',
            CASE WHEN asset_id             IS NULL OR TRIM(COALESCE(asset_id::text, ''))             = '' THEN 'asset_id'             END,
            CASE WHEN system_name          IS NULL OR TRIM(COALESCE(system_name::text, ''))          = '' THEN 'system_name'          END,
            CASE WHEN data_category        IS NULL OR TRIM(COALESCE(data_category::text, ''))        = '' THEN 'data_category'        END,
            CASE WHEN data_owner           IS NULL OR TRIM(COALESCE(data_owner::text, ''))           = '' THEN 'data_owner'           END,
            CASE WHEN data_classification  IS NULL OR TRIM(COALESCE(data_classification::text, ''))  = '' THEN 'data_classification'  END,
            CASE WHEN encryption_in_transit IS NULL OR TRIM(COALESCE(encryption_in_transit::text, '')) = '' THEN 'encryption_in_transit' END,
            CASE WHEN encryption_at_rest   IS NULL OR TRIM(COALESCE(encryption_at_rest::text, ''))   = '' THEN 'encryption_at_rest'   END,
            CASE WHEN retention_period     IS NULL OR TRIM(COALESCE(retention_period::text, ''))     = '' THEN 'retention_period'     END,
            CASE WHEN control_mapping      IS NULL OR TRIM(COALESCE(control_mapping::text, ''))      = '' THEN 'control_mapping'      END
        )) AS missing_fields_list
    FROM assets
    WHERE is_active = TRUE
)
SELECT
    asset_id,
    system_name,
    data_classification,
    data_category,
    last_review_date,
    NULLIF(missing_fields_list, '') AS missing_fields,
    CASE
        WHEN mandatory_score = 9 THEN 'Compliant'
        ELSE 'Non-Compliant'
    END AS compliance_status,
    CASE
        WHEN last_review_date IS NULL THEN 'Never Reviewed'
        WHEN last_review_date < (CURRENT_DATE - INTERVAL '12 months') THEN 'Review Overdue'
        ELSE 'Up to Date'
    END AS review_status
FROM field_status
ORDER BY asset_id;


-- Sanity-check query (run after applying the migration to verify):
-- SELECT
--     COUNT(*) AS total_assets,
--     SUM(CASE WHEN compliance_status = 'Compliant' THEN 1 ELSE 0 END) AS compliant,
--     SUM(CASE WHEN compliance_status = 'Non-Compliant' THEN 1 ELSE 0 END) AS non_compliant,
--     SUM(CASE WHEN review_status = 'Review Overdue' THEN 1 ELSE 0 END) AS overdue
-- FROM compliance_dashboard;
