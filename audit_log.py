import db
from datetime import datetime


def log_change(asset_id, action, field_changed=None, old_value=None, new_value=None, changed_by="faisal.sanad", notes=None):
    """
    Manually append an entry to the audit log.

    Parameters:
        asset_id     : e.g. "ESK-001"
        action       : "INSERT", "UPDATE", or "DELETE"
        field_changed: the field that changed (for UPDATE only)
        old_value    : previous value (for UPDATE only)
        new_value    : new value (for UPDATE only)
        changed_by   : who made the change
        notes        : optional free-text note
    """
    db.execute("""
        INSERT INTO audit_log (asset_id, action, field_changed, old_value, new_value, changed_by, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (asset_id, action, field_changed, old_value, new_value, changed_by, notes))

    print(f"  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Audit entry logged — "
          f"Asset: {asset_id} | Action: {action}"
          + (f" | Field: {field_changed}" if field_changed else ""))


def view_log(asset_id=None, limit=20):
    """Print recent audit log entries, optionally filtered by asset_id."""
    if asset_id:
        cols, rows = db.fetch_all("""
            SELECT changed_at, asset_id, action, field_changed, old_value, new_value, changed_by, notes
            FROM audit_log WHERE asset_id = %s ORDER BY changed_at DESC LIMIT %s
        """, (asset_id, limit))
    else:
        cols, rows = db.fetch_all("""
            SELECT changed_at, asset_id, action, field_changed, old_value, new_value, changed_by, notes
            FROM audit_log ORDER BY changed_at DESC LIMIT %s
        """, (limit,))

    print(f"\n{'='*80}")
    print(f"  Audit Log — {len(rows)} entries")
    print(f"{'='*80}")
    print(f"  {'Timestamp':<26} {'Asset':<10} {'Action':<10} {'Field':<22} {'Old':<16} {'New':<16} {'By'}")
    print(f"  {'-'*76}")
    for row in rows:
        changed_at   = str(row[0])[:19]
        asset        = str(row[1] or "")
        action       = str(row[2] or "")
        field        = str(row[3] or "")[:20]
        old_val      = str(row[4] or "")[:14]
        new_val      = str(row[5] or "")[:14]
        by           = str(row[6] or "")
        print(f"  {changed_at:<26} {asset:<10} {action:<10} {field:<22} {old_val:<16} {new_val:<16} {by}")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    # Example usage — log a manual change and view the log
    print("\nLogging a manual audit entry...")
    log_change(
        asset_id="ESK-001",
        action="UPDATE",
        field_changed="last_review_date",
        old_value="2025-01-15",
        new_value="2026-04-09",
        changed_by="faisal.sanad",
        notes="Annual review completed — no changes required."
    )

    print("\nViewing last 10 audit entries...")
    view_log(limit=10)
