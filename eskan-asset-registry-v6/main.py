import os
import sys
from datetime import datetime


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def banner():
    print("=" * 60)
    print("   ESKAN BANK — Information Asset Registry System")
    print("   CBB OM-5.5 Compliant | ISO 27001:2022 A.5.9")
    print("=" * 60)
    print(f"   {datetime.now().strftime('%A, %d %B %Y  %H:%M:%S')}")
    print("=" * 60)
    print()


def main_menu():
    print("   MAIN MENU")
    print()
    print("   1.  View Compliance Dashboard")
    print("   2.  Generate Excel Report")
    print("   3.  Run Reconciliation (CSV)")
    print("   4.  View Audit Log")
    print("   5.  Add Manual Audit Entry")
    print("   6.  View Asset Register Summary")
    print("   0.  Exit")
    print()


def view_compliance_dashboard():
    import db
    print()
    print("  COMPLIANCE DASHBOARD")
    print(f"  {'Asset ID':<10} {'System Name':<35} {'Classification':<15} {'Status':<14} {'Review Status'}")
    print("  " + "-" * 90)
    cols, rows = db.fetch_all("SELECT asset_id, system_name, data_classification, compliance_status, review_status FROM compliance_dashboard")
    for row in rows:
        print(f"  {str(row[0]):<10} {str(row[1]):<35} {str(row[2]):<15} {str(row[3]):<14} {str(row[4])}")

    cols2, summary = db.fetch_all("""
        SELECT COUNT(*),
               SUM(CASE WHEN compliance_status = 'Compliant' THEN 1 ELSE 0 END),
               SUM(CASE WHEN compliance_status = 'Non-Compliant' THEN 1 ELSE 0 END),
               SUM(CASE WHEN review_status = 'Review Overdue' THEN 1 ELSE 0 END)
        FROM compliance_dashboard
    """)
    total, compliant, non_compliant, overdue = summary[0]
    print()
    print(f"  Total Assets: {total}  |  Compliant: {compliant}  |  Non-Compliant: {non_compliant}  |  Review Overdue: {overdue}")


def generate_report():
    from report import generate_report as gen
    print()
    print("  Generating Excel report...")
    path = gen()
    print(f"  Done. File saved: {path}")


def run_reconciliation():
    from reconciliation import run_reconciliation as run_rec
    print()
    csv_path = input("  Enter path to CSV file: ").strip()
    if not os.path.exists(csv_path):
        print(f"  Error: file not found — {csv_path}")
        return
    run_rec(csv_path)


def view_audit_log():
    from audit_log import view_log
    print()
    choice = input("  Filter by Asset ID? (press Enter to skip): ").strip()
    asset_id = choice if choice else None
    view_log(asset_id=asset_id, limit=20)


def add_audit_entry():
    from audit_log import log_change
    print()
    print("  ADD MANUAL AUDIT ENTRY")
    asset_id    = input("  Asset ID (e.g. ESK-001): ").strip()
    action      = input("  Action (INSERT / UPDATE / DELETE): ").strip().upper()
    field       = input("  Field changed (press Enter to skip): ").strip() or None
    old_val     = input("  Old value (press Enter to skip): ").strip() or None
    new_val     = input("  New value (press Enter to skip): ").strip() or None
    changed_by  = input("  Changed by (default: faisal.sanad): ").strip() or "faisal.sanad"
    notes       = input("  Notes (press Enter to skip): ").strip() or None
    print()
    log_change(asset_id, action, field, old_val, new_val, changed_by, notes)


def view_asset_summary():
    import db
    print()
    print("  ASSET REGISTER SUMMARY")
    print(f"  {'Asset ID':<10} {'System Name':<38} {'Category':<25} {'Classification'}")
    print("  " + "-" * 90)
    cols, rows = db.fetch_all("""
        SELECT asset_id, system_name, data_category, data_classification
        FROM assets WHERE is_active = TRUE ORDER BY asset_id
    """)
    for row in rows:
        print(f"  {str(row[0]):<10} {str(row[1]):<38} {str(row[2]):<25} {str(row[3])}")
    print()
    print(f"  Total: {len(rows)} assets")


def main():
    while True:
        clear()
        banner()
        main_menu()

        choice = input("  Select option: ").strip()
        print()

        if choice == "1":
            view_compliance_dashboard()
        elif choice == "2":
            generate_report()
        elif choice == "3":
            run_reconciliation()
        elif choice == "4":
            view_audit_log()
        elif choice == "5":
            add_audit_entry()
        elif choice == "6":
            view_asset_summary()
        elif choice == "0":
            print("  Exiting. Goodbye.")
            sys.exit(0)
        else:
            print("  Invalid option. Please try again.")

        print()
        input("  Press Enter to return to menu...")


if __name__ == "__main__":
    main()
