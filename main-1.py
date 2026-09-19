# =============================================================
#
#  CYBERSECURITY PASSWORD STRENGTH ANALYZER
#  Main Entry Point – Menu-Driven Interface
#
#  Run with:  python main.py
#
# =============================================================

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.password_strength_system import PasswordStrengthSystem
from models.password_analyzer import PasswordAnalyzer
from services.analysis_service import AnalysisService
from services.report_service import ReportService
from services.export_service import ExportService
from utils.helpers import (
    display_banner,
    display_menu,
    display_report_submenu,
    get_valid_input,
    clear_screen,
    validate_email,
    validate_name,
)
from utils.exceptions import (
    EmptyPasswordError,
    InvalidPasswordFormatError,
    WeakPasswordError,
    InvalidUserInputError,
)


# ═══════════════════════════════════════════════════════════
#  GLOBAL SYSTEM INSTANCE
# ═══════════════════════════════════════════════════════════

system = PasswordStrengthSystem()
analysis_service = AnalysisService(system)
report_service = ReportService(system)
export_service = ExportService(system)

# Track currently logged-in user
current_user_id = None


# ═══════════════════════════════════════════════════════════
#  MENU HANDLERS
# ═══════════════════════════════════════════════════════════

def handle_user_registration():
    """Menu option 1: Register a new user."""
    global current_user_id

    print("\n" + "=" * 55)
    print("         USER REGISTRATION")
    print("=" * 55)

    try:
        user_id = get_valid_input(
            "  Enter User ID   : ",
            validator=lambda x: len(x) >= 2,
            error_msg="User ID must be at least 2 characters.",
        )
        name = get_valid_input(
            "  Enter Full Name  : ",
            validator=validate_name,
            error_msg="Name must contain only letters and spaces.",
        )
        email = get_valid_input(
            "  Enter Email      : ",
            validator=validate_email,
            error_msg="Please enter a valid email address.",
        )

        user = system.register_user(user_id, name, email)
        current_user_id = user_id

        print("\n  ✔ Registration successful!")
        print(user.display_details())

    except ValueError as e:
        print(f"\n  ⚠ Registration failed: {e}")
    except InvalidUserInputError as e:
        print(f"\n  ⚠ Invalid input: {e}")


def handle_analyze_password():
    """Menu option 2: Analyze a password."""
    global current_user_id

    print("\n" + "=" * 55)
    print("         PASSWORD ANALYSIS")
    print("=" * 55)

    try:
        password = input("  Enter password to analyze: ")

        if not password:
            raise EmptyPasswordError()

        if len(password) < 1:
            raise InvalidPasswordFormatError("Password must have at least 1 character.")

        # Ask if they want to associate with a user
        if current_user_id:
            associate = input(
                f"  Associate with user '{current_user_id}'? (y/n): "
            ).strip().lower()
            uid = current_user_id if associate == "y" else None
        else:
            uid = None

        result = analysis_service.analyze(password, user_id=uid)

        # Display formatted result
        print(analysis_service.display_analysis(result))

        # Warn if critically weak
        if result.get("score", 0) <= 20:
            print("  ⚠ WARNING: This password is CRITICALLY WEAK!")
            print("  Consider using one of these generated alternatives:\n")
            suggestions = analysis_service.get_suggestions()
            for i, s in enumerate(suggestions, 1):
                print(f"    {i}. {s}")
            print()

    except EmptyPasswordError as e:
        print(f"\n  ⚠ Error: {e}")
    except InvalidPasswordFormatError as e:
        print(f"\n  ⚠ Error: {e}")
    except ValueError as e:
        print(f"\n  ⚠ Error: {e}")


def handle_generate_password():
    """Menu option 3: Generate a strong password."""
    print("\n" + "=" * 55)
    print("         STRONG PASSWORD GENERATOR")
    print("=" * 55)

    print("\n  Generation Options:")
    print("  1. Random Password (custom length)")
    print("  2. Passphrase (word-based)")
    print("  3. Get 5 Suggestions")

    choice = input("\n  Select option (1-3): ").strip()

    if choice == "1":
        try:
            length_str = input("  Enter desired length (8-64, default 16): ").strip()
            length = int(length_str) if length_str else 16
            length = max(8, min(64, length))

            password = analysis_service.generate_password(length=length)
            print(f"\n  Generated Password: {password}")
            print(f"  Length: {len(password)} characters")

            # Auto-analyze the generated password
            print("\n  Analyzing generated password...")
            result = analysis_service.analyze(password)
            print(f"  Score    : {result.get('score', 0)}/100")
            print(f"  Strength : {result.get('strength', 'Unknown')}")

        except ValueError:
            print("\n  ⚠ Invalid length. Using default (16).")
            password = analysis_service.generate_password(length=16)
            print(f"\n  Generated Password: {password}")

    elif choice == "2":
        try:
            words_str = input("  Number of words (3-6, default 4): ").strip()
            word_count = int(words_str) if words_str else 4
            word_count = max(3, min(6, word_count))

            passphrase = analysis_service.generate_passphrase(word_count=word_count)
            print(f"\n  Generated Passphrase: {passphrase}")
            print(f"  Length: {len(passphrase)} characters")

            # Auto-analyze
            print("\n  Analyzing generated passphrase...")
            result = analysis_service.analyze(passphrase)
            print(f"  Score    : {result.get('score', 0)}/100")
            print(f"  Strength : {result.get('strength', 'Unknown')}")

        except ValueError:
            passphrase = analysis_service.generate_passphrase(word_count=4)
            print(f"\n  Generated Passphrase: {passphrase}")

    elif choice == "3":
        suggestions = analysis_service.get_suggestions()
        print("\n  Password Suggestions:")
        print("  " + "-" * 45)
        for i, s in enumerate(suggestions, 1):
            print(f"  {i}. {s}  (length: {len(s)})")
        print("  " + "-" * 45)

    else:
        print("\n  ⚠ Invalid option.")


def handle_view_history():
    """Menu option 4: View password analysis history."""
    global current_user_id

    print("\n" + "=" * 55)
    print("         PASSWORD ANALYSIS HISTORY")
    print("=" * 55)

    print("\n  1. View all analysis records")
    print("  2. View user-specific history")
    print("  3. Search history")
    print("  4. View sorted by score")
    print("  5. View weak passwords only")
    print("  6. View strong passwords only")
    print("  7. View risky passwords only")

    choice = input("\n  Select option (1-7): ").strip()

    if choice == "1":
        records = system.analysis_records
        if not records:
            print("\n  No analysis records found.")
            return
        print(f"\n  Total Records: {len(records)}\n")
        for i, rec in enumerate(records, 1):
            print(
                f"  {i}. {rec.get('password_masked', '***')} | "
                f"Score: {rec.get('score', 0)} | "
                f"Strength: {rec.get('strength', 'N/A')} | "
                f"{rec.get('analyzed_at', '')}"
            )

    elif choice == "2":
        uid = current_user_id
        if not uid:
            uid = input("  Enter User ID: ").strip()
        try:
            user = system.get_user(uid)
            history = user.view_history()
            if not history:
                print(f"\n  No history found for user '{uid}'.")
                return
            print(f"\n  History for {user.name} ({len(history)} records):\n")
            for i, rec in enumerate(history, 1):
                print(
                    f"  {i}. {rec.get('password_masked', '***')} | "
                    f"Score: {rec.get('score', 0)} | "
                    f"Strength: {rec.get('strength', 'N/A')} | "
                    f"{rec.get('analyzed_at', '')}"
                )
        except KeyError as e:
            print(f"\n  ⚠ {e}")

    elif choice == "3":
        keyword = input("  Enter search keyword: ").strip()
        if not keyword:
            print("\n  ⚠ Keyword cannot be empty.")
            return
        results = analysis_service.search_history(keyword)
        if results:
            print(f"\n  Found {len(results)} matching record(s):\n")
            for i, rec in enumerate(results, 1):
                print(
                    f"  {i}. {rec.get('password_masked', '***')} | "
                    f"Score: {rec.get('score', 0)} | "
                    f"Strength: {rec.get('strength', 'N/A')}"
                )
        else:
            print(f"\n  No records matching '{keyword}'.")

    elif choice == "4":
        sorted_records = analysis_service.sort_by_score()
        if not sorted_records:
            print("\n  No records to display.")
            return
        print("\n  Records sorted by score (highest first):\n")
        for i, rec in enumerate(sorted_records, 1):
            print(
                f"  {i}. {rec.get('password_masked', '***')} | "
                f"Score: {rec.get('score', 0)} | "
                f"Strength: {rec.get('strength', 'N/A')}"
            )

    elif choice == "5":
        weak = analysis_service.get_weak_passwords()
        if not weak:
            print("\n  No weak passwords found. Great!")
            return
        print(f"\n  Weak Passwords ({len(weak)}):\n")
        for i, rec in enumerate(weak, 1):
            print(
                f"  {i}. {rec.get('password_masked', '***')} | "
                f"Score: {rec.get('score', 0)}"
            )

    elif choice == "6":
        strong = analysis_service.get_strong_passwords()
        if not strong:
            print("\n  No strong passwords found yet.")
            return
        print(f"\n  Strong Passwords ({len(strong)}):\n")
        for i, rec in enumerate(strong, 1):
            print(
                f"  {i}. {rec.get('password_masked', '***')} | "
                f"Score: {rec.get('score', 0)}"
            )

    elif choice == "7":
        risky = analysis_service.get_risky_passwords()
        if not risky:
            print("\n  No risky passwords found.")
            return
        print(f"\n  Risky Passwords ({len(risky)}):\n")
        for i, rec in enumerate(risky, 1):
            vuln = rec.get("vulnerabilities", {})
            print(
                f"  {i}. {rec.get('password_masked', '***')} | "
                f"Risks: {vuln.get('total_risks', 0)} | "
                f"Level: {vuln.get('risk_level', 'N/A')}"
            )

    else:
        print("\n  ⚠ Invalid option.")


def handle_security_reports():
    """Menu option 5: Security reports sub-menu."""
    global current_user_id

    while True:
        display_report_submenu()
        choice = input("  Select report option (1-7): ").strip()

        if choice == "1":
            # Password Security Report – use generator
            records = system.analysis_records
            if not records:
                print("\n  No analysis records to report on.")
                continue

            print("\n  Generating password security reports (using generator)...\n")
            report_gen = report_service.report_generator(records)
            for i, report_data in enumerate(report_gen, 1):
                print(f"  --- Report {i}: {report_data['report_id']} ---")
                print(report_data["report_text"])
                print()
                if i >= 5:
                    remaining = len(records) - i
                    if remaining > 0:
                        print(f"  ... and {remaining} more report(s).")
                    break

        elif choice == "2":
            # User Security Report
            uid = current_user_id
            if not uid:
                uid = input("  Enter User ID: ").strip()
            try:
                user = system.get_user(uid)
                print(report_service.display_user_security_report(user))
            except KeyError as e:
                print(f"\n  ⚠ {e}")

        elif choice == "3":
            # Risk Assessment Report
            print(report_service.display_risk_assessment_report())

        elif choice == "4":
            # Analysis Summary Report
            print(report_service.display_analysis_summary_report())

        elif choice == "5":
            # Export to CSV
            print("\n  Exporting reports to CSV...")
            path1 = export_service.export_security_reports_csv()
            path2 = export_service.export_password_analysis_csv()
            path3 = export_service.export_user_security_csv()
            print(f"\n  ✔ Security Report CSV   : {path1}")
            print(f"  ✔ Password Analysis CSV : {path2}")
            print(f"  ✔ User Security CSV     : {path3}")

        elif choice == "6":
            # Generate report text files
            print("\n  Generating report files...")
            paths = report_service.generate_all_reports(user_id=current_user_id)
            if paths:
                print(f"\n  ✔ Generated {len(paths)} report file(s):")
                for p in paths:
                    print(f"    → {p}")
            else:
                print("\n  No records available to generate reports from.")

        elif choice == "7":
            break
        else:
            print("\n  ⚠ Invalid option.")


def handle_save_data():
    """Menu option 6: Save all data."""
    print("\n  Saving all data...")
    result = system.save_data()
    print(f"  ✔ {result}")


def handle_load_data():
    """Menu option 7: Load saved data."""
    print("\n  Loading saved data...")
    try:
        result = system.load_data()
        print(f"  ✔ {result}")
        users = system.list_users()
        records = system.analysis_records
        print(f"  Loaded {len(users)} user(s) and {len(records)} analysis record(s).")
    except FileNotFoundError as e:
        print(f"\n  ⚠ File not found: {e}")
    except Exception as e:
        print(f"\n  ⚠ Error loading data: {e}")


# ═══════════════════════════════════════════════════════════
#  MAIN LOOP
# ═══════════════════════════════════════════════════════════

def main():
    """Main entry point – menu-driven interface."""
    global current_user_id

    clear_screen()
    display_banner()

    # Auto-load data if available
    try:
        system.load_data()
        users = system.list_users()
        records = system.analysis_records
        if users or records:
            print(f"  ✔ Auto-loaded {len(users)} user(s) and {len(records)} analysis record(s).\n")
    except Exception:
        pass  # No saved data yet — that's fine

    while True:
        display_menu()

        if current_user_id:
            print(f"  Logged in as: {current_user_id}")

        choice = input("  Enter your choice (1-8): ").strip()

        if choice == "1":
            handle_user_registration()
        elif choice == "2":
            handle_analyze_password()
        elif choice == "3":
            handle_generate_password()
        elif choice == "4":
            handle_view_history()
        elif choice == "5":
            handle_security_reports()
        elif choice == "6":
            handle_save_data()
        elif choice == "7":
            handle_load_data()
        elif choice == "8":
            # Auto-save before exit
            print("\n  Saving data before exit...")
            system.save_data()
            print("\n  ╔══════════════════════════════════════╗")
            print("  ║  Thank you for using the Cyber       ║")
            print("  ║  Password Strength Analyzer!          ║")
            print("  ║  Stay secure! 🔒                     ║")
            print("  ╚══════════════════════════════════════╝\n")
            sys.exit(0)
        else:
            print("\n  ⚠ Invalid choice. Please enter a number between 1 and 8.")

        input("\n  Press Enter to continue...")


# ═══════════════════════════════════════════════════════════
#  POLYMORPHISM DEMONSTRATION (Bonus: runs at startup)
# ═══════════════════════════════════════════════════════════

def demonstrate_polymorphism():
    """Quick demonstration of polymorphism with Person hierarchy."""
    from models.user import User
    from models.admin import Admin

    print("\n" + "=" * 55)
    print("  POLYMORPHISM DEMONSTRATION")
    print("=" * 55)

    persons = [
        User("DEMO-U1", "Demo User", "user@demo.com"),
        Admin("DEMO-A1", "Demo Admin", "admin@demo.com", admin_id="ADM-001"),
    ]

    for person in persons:
        print(person.display_details())   # Polymorphic call
        print()

    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()