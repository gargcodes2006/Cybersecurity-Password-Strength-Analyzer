# =============================================================
# PasswordStrengthSystem - Main System (Composition Root)
# Cybersecurity Password Strength Analyzer
# =============================================================

import os
import json
from datetime import datetime

from models.password import Password
from models.password_analyzer import PasswordAnalyzer
from models.vulnerability_scanner import VulnerabilityScanner
from models.password_generator import PasswordGenerator
from models.security_report import SecurityReport
from models.user import User


class PasswordStrengthSystem:
    """
    Central system that composes all components.
    Demonstrates: Composition – contains Password, PasswordAnalyzer,
                  VulnerabilityScanner, PasswordGenerator, SecurityReport.
    """

    # Paths relative to project root
    DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    EXPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")

    def __init__(self):
        # Composition – system owns these components
        self.__analyzer = PasswordAnalyzer()
        self.__scanner = VulnerabilityScanner()
        self.__generator = PasswordGenerator()

        # Data stores (lists and dicts)
        self.__users = {}              # dict: user_id -> User
        self.__analysis_records = []   # list of analysis result dicts
        self.__reports = []            # list of SecurityReport objects

        # Ensure directories exist
        for d in [self.DATA_DIR, self.REPORTS_DIR, self.EXPORTS_DIR]:
            os.makedirs(d, exist_ok=True)

    # ── Properties ─────────────────────────────────────────

    @property
    def users(self) -> dict:
        return dict(self.__users)

    @property
    def analysis_records(self) -> list:
        return list(self.__analysis_records)

    @property
    def reports(self) -> list:
        return list(self.__reports)

    # ── User management ───────────────────────────────────

    def register_user(self, user_id: str, name: str, email: str) -> User:
        """Register a new user in the system."""
        if user_id in self.__users:
            raise ValueError(f"User ID '{user_id}' already exists.")
        user = User(user_id=user_id, name=name, email=email)
        self.__users[user_id] = user
        return user

    def get_user(self, user_id: str) -> User:
        """Retrieve a user by ID."""
        if user_id not in self.__users:
            raise KeyError(f"User '{user_id}' not found.")
        return self.__users[user_id]

    def list_users(self) -> list:
        """Return list of all users."""
        return list(self.__users.values())

    # ── Core analysis ──────────────────────────────────────

    def analyze_password(self, password_text: str, user_id: str = None) -> dict:
        """
        Full password analysis pipeline:
        1. Create Password object
        2. Run PasswordAnalyzer
        3. Run VulnerabilityScanner
        4. Combine results
        5. Store in history
        """
        # Validate
        if not password_text:
            raise ValueError("Password cannot be empty.")

        # Create Password object
        pwd = Password(password_text)
        basic_analysis = pwd.analyze_password()

        # Deep analysis via PasswordAnalyzer
        analyzer_result = self.__analyzer.full_analysis(password_text)

        # Vulnerability scan
        vuln_result = self.__scanner.scan_password(password_text)

        # Combine results into a single record
        combined = {
            "password_masked": basic_analysis["password_masked"],
            "length": basic_analysis["length"],
            "score": analyzer_result["score"],
            "strength": analyzer_result["strength"],
            "character_analysis": basic_analysis["character_analysis"],
            "rules_passed": basic_analysis["rules_passed"],
            "rules_failed": basic_analysis["rules_failed"],
            "complexity": analyzer_result["complexity"],
            "entropy": analyzer_result["entropy"],
            "patterns": analyzer_result["patterns"],
            "vulnerabilities": vuln_result,
            "crack_time_estimate": self._estimate_crack_time(analyzer_result["entropy"]),
            "recommendations": self._generate_recommendations(
                analyzer_result, vuln_result, basic_analysis
            ),
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_id": analyzer_result["analysis_id"],
        }

        # Store record
        self.__analysis_records.append(combined)

        # Attach to user if logged in
        if user_id and user_id in self.__users:
            self.__users[user_id].analyze_password(password_text, combined)

        return combined

    # ── Report generation ──────────────────────────────────

    def generate_reports(self, user_id: str = None) -> list:
        """Generate reports for all analysis records or a specific user."""
        generated_paths = []

        if user_id and user_id in self.__users:
            user = self.__users[user_id]
            history = user.view_history()
            for record in history:
                report = SecurityReport()
                details = record.get("details", record)
                text = report.generate_report(details, user_name=user.name)
                path = self._save_report_file(report, text)
                self.__reports.append(report)
                generated_paths.append(path)
        else:
            for record in self.__analysis_records:
                report = SecurityReport()
                text = report.generate_report(record)
                path = self._save_report_file(report, text)
                self.__reports.append(report)
                generated_paths.append(path)

        return generated_paths

    # ── Data persistence ───────────────────────────────────

    def save_data(self) -> str:
        """Save all system data to JSON files."""
        # Save users
        users_data = {uid: u.to_dict() for uid, u in self.__users.items()}
        users_path = os.path.join(self.DATA_DIR, "users.json")
        with open(users_path, "w", encoding="utf-8") as f:
            json.dump(users_data, f, indent=4, ensure_ascii=False)

        # Save analysis records
        records_path = os.path.join(self.DATA_DIR, "analysis_records.json")
        with open(records_path, "w", encoding="utf-8") as f:
            json.dump(self.__analysis_records, f, indent=4, ensure_ascii=False)

        # Save reports metadata
        reports_data = [r.export_report() for r in self.__reports]
        reports_path = os.path.join(self.DATA_DIR, "reports.json")
        with open(reports_path, "w", encoding="utf-8") as f:
            json.dump(reports_data, f, indent=4, ensure_ascii=False)

        return f"Data saved to {self.DATA_DIR}"

    def load_data(self) -> str:
        """Load system data from JSON files."""
        # Load users
        users_path = os.path.join(self.DATA_DIR, "users.json")
        if os.path.exists(users_path):
            with open(users_path, "r", encoding="utf-8") as f:
                users_data = json.load(f)
            self.__users = {}
            for uid, udata in users_data.items():
                self.__users[uid] = User.from_dict(udata)

        # Load analysis records
        records_path = os.path.join(self.DATA_DIR, "analysis_records.json")
        if os.path.exists(records_path):
            with open(records_path, "r", encoding="utf-8") as f:
                self.__analysis_records = json.load(f)

        # Load reports metadata
        reports_path = os.path.join(self.DATA_DIR, "reports.json")
        if os.path.exists(reports_path):
            with open(reports_path, "r", encoding="utf-8") as f:
                reports_data = json.load(f)
            self.__reports = []
            for rdata in reports_data:
                rpt = SecurityReport(
                    report_id=rdata["report_id"],
                    security_level=rdata.get("security_level", "Unknown"),
                    report_data=rdata.get("report_data", {}),
                )
                self.__reports.append(rpt)

        return f"Data loaded from {self.DATA_DIR}"

    # ── Password generation (delegated) ───────────────────

    def generate_strong_password(self, length: int = 16) -> str:
        return self.__generator.generate_password(length=length)

    def suggest_passwords(self) -> list:
        return self.__generator.suggest_password()

    def generate_passphrase(self, word_count: int = 4) -> str:
        return self.__generator.generate_passphrase(word_count=word_count)

    # ── History search (recursive) ─────────────────────────

    def search_history(self, keyword: str, records: list = None, index: int = 0) -> list:
        """
        Recursive function to search password analysis history.
        Demonstrates: Recursion.
        """
        if records is None:
            records = self.__analysis_records

        if index >= len(records):
            return []

        results = []
        record = records[index]
        record_str = json.dumps(record).lower()
        if keyword.lower() in record_str:
            results.append(record)

        # Recurse to the next record
        results.extend(self.search_history(keyword, records, index + 1))
        return results

    # ── Private helpers ────────────────────────────────────

    def _estimate_crack_time(self, entropy: dict) -> dict:
        """Estimate time to crack based on entropy bits."""
        total_bits = entropy.get("total_bits", 0)

        # Assume 10 billion guesses per second (modern GPU cluster)
        guesses_per_second = 10_000_000_000
        if total_bits <= 0:
            return {"seconds": 0, "human_readable": "Instant", "difficulty": "Trivial"}

        import math
        total_combinations = 2 ** total_bits
        seconds = total_combinations / guesses_per_second

        if seconds < 1:
            human = "Instant"
            difficulty = "Trivial"
        elif seconds < 60:
            human = f"{seconds:.1f} seconds"
            difficulty = "Very Easy"
        elif seconds < 3600:
            human = f"{seconds / 60:.1f} minutes"
            difficulty = "Easy"
        elif seconds < 86400:
            human = f"{seconds / 3600:.1f} hours"
            difficulty = "Moderate"
        elif seconds < 31536000:
            human = f"{seconds / 86400:.1f} days"
            difficulty = "Hard"
        elif seconds < 31536000 * 100:
            human = f"{seconds / 31536000:.1f} years"
            difficulty = "Very Hard"
        elif seconds < 31536000 * 1_000_000:
            human = f"{seconds / 31536000:.0f} years"
            difficulty = "Extremely Hard"
        else:
            exponent = int(math.log10(seconds / 31536000))
            human = f"~10^{exponent} years"
            difficulty = "Practically Impossible"

        return {
            "seconds": seconds,
            "human_readable": human,
            "difficulty": difficulty,
            "entropy_bits": total_bits,
            "assumed_guesses_per_sec": guesses_per_second,
        }

    def _generate_recommendations(self, analyzer_result: dict,
                                  vuln_result: dict,
                                  basic_analysis: dict) -> list:
        """Generate actionable security recommendations."""
        recommendations = []
        rules_failed = basic_analysis.get("rules_failed", [])
        score = analyzer_result.get("score", 0)

        if "Minimum 8 characters" in rules_failed:
            recommendations.append("Increase password length to at least 8 characters. Aim for 12-16+.")
        if "Contains uppercase letter" in rules_failed:
            recommendations.append("Add uppercase letters (A-Z) to increase complexity.")
        if "Contains lowercase letter" in rules_failed:
            recommendations.append("Add lowercase letters (a-z) to increase complexity.")
        if "Contains digit" in rules_failed:
            recommendations.append("Include at least one numeric digit (0-9).")
        if "Contains special character" in rules_failed:
            recommendations.append("Add special characters (!@#$%^&*) for higher entropy.")

        if vuln_result.get("is_common_password"):
            recommendations.append("CRITICAL: This is a commonly known password. Change it immediately!")
        if vuln_result.get("dictionary_words_found"):
            recommendations.append("Avoid using common dictionary words in your password.")
        if vuln_result.get("keyboard_patterns"):
            recommendations.append("Remove keyboard walk patterns (e.g., qwerty, asdf).")

        patterns = analyzer_result.get("patterns", {})
        if not patterns.get("is_pattern_free", True):
            recommendations.append("Eliminate predictable patterns like sequential or repeated characters.")

        if score < 40:
            recommendations.append("Consider using a randomly generated password for maximum security.")
            recommendations.append("Use a passphrase: combine 4+ random words with numbers and symbols.")
        elif score < 60:
            recommendations.append("Good start! Add more character variety or increase length.")
        elif score < 80:
            recommendations.append("Solid password. Consider adding more length for even better security.")

        if not recommendations:
            recommendations.append("Excellent password! Keep up the good security practices.")

        return recommendations

    def _save_report_file(self, report: SecurityReport, text: str) -> str:
        """Save a report to the reports directory."""
        filename = f"{report.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = os.path.join(self.REPORTS_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        return (
            f"PasswordStrengthSystem(users={len(self.__users)}, "
            f"analyses={len(self.__analysis_records)}, "
            f"reports={len(self.__reports)})"
        )

    def __repr__(self) -> str:
        return "PasswordStrengthSystem()"
