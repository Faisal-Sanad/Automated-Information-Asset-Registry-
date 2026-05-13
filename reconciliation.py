import csv
import json
import db
from datetime import datetime
import os

MANDATORY_FIELDS = [
    "asset_id", "system_name", "data_category", "data_owner",
    "data_classification", "encryption_in_transit", "encryption_at_rest",
    "retention_period", "control_mapping"
]

VALID_CLASSIFICATIONS = {"Public", "Internal", "Restricted", "Confidential"}


def load_register():
    cols, rows = db.fetch_all("SELECT * FROM assets WHERE is_active = TRUE")
    return [dict(zip(cols, row)) for row in rows]


def load_csv(filepath):
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def check_missing_fields(register, csv_rows=None):
    """
    Identify register rows that have empty mandatory fields.

    If a csv_rows list is provided and the CSV contains a value for the
    missing field on the same asset, that value is captured as csv_value
    so that the Apply Fix flow can patch the register from the CSV.
    Otherwise csv_value is left blank and the finding must be resolved
    manually through the Asset Register UI.
    """
    findings = []
    # Build an index of CSV rows keyed by upper-cased asset_id for O(1) lookup
    csv_index = {}
    if csv_rows:
        for row in csv_rows:
            cid = str(row.get("asset_id", "")).strip().upper()
            if cid:
                csv_index[cid] = row

    for row in register:
        asset_id_upper = str(row.get("asset_id", "")).strip().upper()
        csv_row = csv_index.get(asset_id_upper, {})
        for field in MANDATORY_FIELDS:
            val = row.get(field, "")
            if val is None or str(val).strip() == "" or str(val) == "None":
                csv_val = str(csv_row.get(field, "")).strip() if csv_row else ""
                findings.append({
                    "asset_id": row["asset_id"],
                    "finding_type": "Missing Fields",
                    "detail": f"Mandatory field '{field}' is empty",
                    "csv_value": csv_val,
                    "register_value": ""
                })
    return findings


def check_undocumented(register, csv_rows):
    findings = []
    if not csv_rows or "asset_id" not in csv_rows[0]:
        return findings
    registered_ids = {str(row["asset_id"]).strip().upper() for row in register}
    for row in csv_rows:
        csv_id = str(row.get("asset_id", "")).strip().upper()
        if csv_id and csv_id not in registered_ids:
            # Capture the full CSV row so Apply Fix can pre-fill the Add Asset
            # modal with every column the CSV provided, not just the asset_id.
            # Strings are stripped to remove trailing whitespace and the dict
            # is JSON-safe (only str/None values from csv.DictReader).
            csv_row_data = {
                k: (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
                if k
            }
            findings.append({
                "asset_id": row["asset_id"],
                "finding_type": "Undocumented",
                "detail": f"Asset '{row['asset_id']}' exists in CSV but not in the register",
                "csv_value": row["asset_id"],
                "register_value": "",
                "csv_row_data": csv_row_data
            })
    return findings


def check_misclassified(register, csv_rows):
    findings = []
    if not csv_rows or "asset_id" not in csv_rows[0] or "data_classification" not in csv_rows[0]:
        return findings
    register_map = {
        str(row["asset_id"]).strip().upper(): str(row.get("data_classification", "")).strip()
        for row in register
    }
    for row in csv_rows:
        csv_id = str(row.get("asset_id", "")).strip().upper()
        csv_class = str(row.get("data_classification", "")).strip()
        if csv_id in register_map:
            reg_class = register_map[csv_id]
            if csv_class.lower() != reg_class.lower():
                findings.append({
                    "asset_id": row["asset_id"],
                    "finding_type": "Misclassified",
                    "detail": f"Classification mismatch for '{row['asset_id']}'",
                    "csv_value": csv_class,
                    "register_value": reg_class
                })
    return findings


def categorise_outcomes(register, csv_rows, missing_findings, undocumented_findings, misclassified_findings):
    """
    Categorise each asset into one of five outcomes:
      Full Match     - asset in both register and CSV with no issues
      Undocumented   - asset in CSV but not in register
      Misclassified  - classification mismatch between CSV and register
      Missing Fields - one or more mandatory fields are empty in the register
      Mixed          - asset has both a misclassification and missing fields
    Returns counts for the summary record.
    """
    if not csv_rows or "asset_id" not in csv_rows[0]:
        return 0, 0, 0, 0, 0

    registered_ids = {str(row["asset_id"]).strip().upper() for row in register}
    undoc_ids = {str(f["asset_id"]).strip().upper() for f in undocumented_findings}
    miscls_ids = {str(f["asset_id"]).strip().upper() for f in misclassified_findings}
    missing_ids = {str(f["asset_id"]).strip().upper() for f in missing_findings}

    full_match = 0
    undocumented = len(undoc_ids)
    mixed = 0

    for row in csv_rows:
        csv_id = str(row.get("asset_id", "")).strip().upper()
        if not csv_id or csv_id not in registered_ids:
            continue
        has_miscls = csv_id in miscls_ids
        has_missing = csv_id in missing_ids
        if has_miscls and has_missing:
            mixed += 1
        elif not has_miscls and not has_missing:
            full_match += 1

    misclassified = len(miscls_ids) - mixed
    missing = len({f["asset_id"] for f in missing_findings}) - mixed

    return full_match, undocumented, misclassified, missing, mixed


def save_run(csv_filename, total_csv, full_match, undocumented, misclassified, missing_fields, mixed, findings, run_by):
    db.execute("""
        INSERT INTO reconciliation_runs (
            csv_filename, total_csv_records, full_match,
            undocumented, misclassified, missing_fields, mixed, run_by
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (csv_filename, total_csv, full_match, undocumented, misclassified, missing_fields, mixed, run_by))

    cols, rows = db.fetch_all("SELECT id FROM reconciliation_runs ORDER BY run_at DESC LIMIT 1")
    run_id = rows[0][0]

    for f in findings:
        # csv_row_data is JSONB on the discrepancies table. Only present for
        # Undocumented findings; for others we insert NULL.
        row_data = f.get("csv_row_data")
        row_data_json = json.dumps(row_data) if row_data else None
        db.execute("""
            INSERT INTO discrepancies (run_id, asset_id, finding_type, detail, csv_value, register_value, csv_row_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (run_id, f["asset_id"], f["finding_type"], f["detail"], f["csv_value"], f["register_value"], row_data_json))

    return run_id


def run_reconciliation(csv_filepath, run_by="system"):
    print(f"\n{'='*60}")
    print(f"  Reconciliation Run — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  CSV: {csv_filepath}")
    print(f"{'='*60}")

    register = load_register()
    csv_rows = load_csv(csv_filepath)
    total_csv = len(csv_rows)

    print(f"\n  Register records : {len(register)}")
    print(f"  CSV records      : {total_csv}")

    missing_findings = check_missing_fields(register, csv_rows)
    undoc_findings = check_undocumented(register, csv_rows)
    miscls_findings = check_misclassified(register, csv_rows)

    all_findings = missing_findings + undoc_findings + miscls_findings

    full_match, undocumented, misclassified, missing, mixed = categorise_outcomes(
        register, csv_rows, missing_findings, undoc_findings, miscls_findings
    )

    run_id = save_run(
        os.path.basename(csv_filepath), total_csv,
        full_match, undocumented, misclassified, missing, mixed,
        all_findings, run_by
    )

    print(f"\n  Results saved — Run ID: {run_id}")
    print(f"  Full Match      : {full_match}")
    print(f"  Undocumented    : {undocumented}")
    print(f"  Misclassified   : {misclassified}")
    print(f"  Missing Fields  : {missing}")
    print(f"  Mixed           : {mixed}")
    print(f"  Total findings  : {len(all_findings)}")
    print(f"{'='*60}\n")

    return run_id, all_findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python reconciliation.py <path_to_csv>")
    else:
        run_reconciliation(sys.argv[1])