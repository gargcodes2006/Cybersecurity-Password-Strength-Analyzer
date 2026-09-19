# =============================================================
# SecurityReport Model
# Cybersecurity Password Strength Analyzer
# =============================================================

from datetime import datetime


class SecurityReport:
    """
    Represents a security report generated from password analyses.
    """

    _report_counter = 0

    def __init__(self, report_id: str = None, security_level: str = "Unknown",
                 report_data: dict = None):
        SecurityReport._report_counter += 1
        self.__report_id = report_id or f"RPT-{SecurityReport._report_counter:04d}"
        self.__report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__security_level = security_level
        self.__report_data = report_data or {}

    # ── Properties ─────────────────────────────────────────

    @property
    def report_id(self) -> str:
        return self.__report_id

    @property
    def report_date(self) -> str:
        return self.__report_date

    @property
    def security_level(self) -> str:
        return self.__security_level

    @security_level.setter
    def security_level(self, value: str):
        valid_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong", "Unknown"]
        if value in valid_levels:
            self.__security_level = value
        else:
            self.__security_level = "Unknown"

    @property
    def report_data(self) -> dict:
        return dict(self.__report_data)

    # ── Report generation ──────────────────────────────────

    def generate_report(self, analysis_result: dict, user_name: str = "Anonymous") -> str:
        """Generate a formatted text report from analysis results."""
        self.__report_data = analysis_result
        score = analysis_result.get("score", 0)
        strength = analysis_result.get("strength", "Unknown")
        self.__security_level = strength

        complexity = analysis_result.get("complexity", {})
        entropy = analysis_result.get("entropy", {})
        patterns = analysis_result.get("patterns", {})
        vulnerabilities = analysis_result.get("vulnerabilities", {})

        separator = "=" * 55
        thin_sep = "-" * 55

        report_lines = [
            separator,
            "       PASSWORD SECURITY ANALYSIS REPORT",
            separator,
            f"  Report ID   : {self.__report_id}",
            f"  Date        : {self.__report_date}",
            f"  User        : {user_name}",
            separator,
            "",
            "  OVERALL RESULT",
            thin_sep,
            f"  Security Score : {score}/100",
            f"  Strength Level : {strength}",
            f"  Security Level : {self.__security_level}",
            "",
            "  COMPLEXITY ANALYSIS",
            thin_sep,
            f"  Password Length       : {complexity.get('length', 'N/A')}",
            f"  Has Uppercase         : {'Yes' if complexity.get('has_uppercase') else 'No'}",
            f"  Has Lowercase         : {'Yes' if complexity.get('has_lowercase') else 'No'}",
            f"  Has Digits            : {'Yes' if complexity.get('has_digits') else 'No'}",
            f"  Has Special Chars     : {'Yes' if complexity.get('has_special_characters') else 'No'}",
            f"  Character Variety     : {complexity.get('character_variety_score', 'N/A')}/4",
            f"  Unique Characters     : {complexity.get('unique_characters', 'N/A')}",
            f"  Unique Ratio          : {complexity.get('unique_ratio', 'N/A')}",
            f"  Complexity Rating     : {complexity.get('complexity_rating', 'N/A')}",
            "",
            "  ENTROPY ANALYSIS",
            thin_sep,
            f"  Shannon Entropy       : {entropy.get('shannon_entropy', 'N/A')}",
            f"  Charset Entropy       : {entropy.get('charset_entropy', 'N/A')} bits",
            f"  Charset Size          : {entropy.get('charset_size', 'N/A')}",
            f"  Total Bits            : {entropy.get('total_bits', 'N/A')}",
            "",
            "  PATTERN DETECTION",
            thin_sep,
            f"  Patterns Detected     : {patterns.get('patterns_detected', 0)}",
            f"  Pattern Free          : {'Yes' if patterns.get('is_pattern_free') else 'No'}",
        ]

        # List individual patterns
        for p in patterns.get("patterns", []):
            report_lines.append(f"    ► [{p['severity']}] {p['type']}: {p['detail']}")

        report_lines.append("")
        report_lines.append("  VULNERABILITY SCAN")
        report_lines.append(thin_sep)

        if vulnerabilities:
            report_lines.append(f"  Total Risks           : {vulnerabilities.get('total_risks', 0)}")
            report_lines.append(f"  Risk Level            : {vulnerabilities.get('risk_level', 'N/A')}")
            report_lines.append(f"  Common Password       : {'Yes' if vulnerabilities.get('is_common_password') else 'No'}")
            dict_words = vulnerabilities.get("dictionary_words_found", [])
            if dict_words:
                report_lines.append(f"  Dictionary Words      : {', '.join(dict_words)}")
            for risk in vulnerabilities.get("risks", []):
                report_lines.append(f"    ► [{risk['severity']}] {risk['risk']}: {risk['detail']}")
        else:
            report_lines.append("  No vulnerability data available.")

        report_lines.append("")
        report_lines.append(separator)
        report_lines.append("              END OF REPORT")
        report_lines.append(separator)

        return "\n".join(report_lines)

    def export_report(self) -> dict:
        """Export report as a dictionary for JSON/CSV serialization."""
        return {
            "report_id": self.__report_id,
            "report_date": self.__report_date,
            "security_level": self.__security_level,
            "report_data": self.__report_data,
        }

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        return (
            f"SecurityReport(id={self.__report_id}, "
            f"date={self.__report_date}, level={self.__security_level})"
        )

    def __repr__(self) -> str:
        return f"SecurityReport(report_id={self.__report_id!r})"

    def __len__(self) -> int:
        """Number of data points in the report."""
        return len(self.__report_data)
