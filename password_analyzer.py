# =============================================================
# PasswordAnalyzer Model
# Cybersecurity Password Strength Analyzer
# =============================================================

import re
import math
from datetime import datetime


class PasswordAnalyzer:
    """
    Deep analysis engine for password complexity, entropy,
    and pattern detection.
    Demonstrates: Composition target, Static Methods, Class Methods.
    """

    _total_analyses = 0  # Class-level counter for class method demo

    def __init__(self, analysis_id: str = None):
        self.__analysis_id = analysis_id or f"ANA-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.__password_score = 0.0

    # ── Properties ─────────────────────────────────────────

    @property
    def analysis_id(self) -> str:
        return self.__analysis_id

    @property
    def password_score(self) -> float:
        return self.__password_score

    # ── Complexity check ───────────────────────────────────

    def check_complexity(self, password_text: str) -> dict:
        """
        Evaluate password complexity across multiple dimensions.
        """
        length = len(password_text)
        has_upper = bool(re.search(r"[A-Z]", password_text))
        has_lower = bool(re.search(r"[a-z]", password_text))
        has_digit = bool(re.search(r"\d", password_text))
        has_special = bool(re.search(r"[^A-Za-z0-9]", password_text))

        # Consecutive character checks
        consecutive_upper = len(re.findall(r"[A-Z]{2,}", password_text))
        consecutive_lower = len(re.findall(r"[a-z]{2,}", password_text))
        consecutive_digits = len(re.findall(r"\d{2,}", password_text))

        char_variety = sum([has_upper, has_lower, has_digit, has_special])
        unique_chars = len(set(password_text))
        unique_ratio = round(unique_chars / length, 2) if length else 0

        complexity = {
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_special_characters": has_special,
            "character_variety_score": char_variety,
            "unique_characters": unique_chars,
            "unique_ratio": unique_ratio,
            "consecutive_uppercase_groups": consecutive_upper,
            "consecutive_lowercase_groups": consecutive_lower,
            "consecutive_digit_groups": consecutive_digits,
            "meets_minimum_length": length >= 8,
            "complexity_rating": self._rate_complexity(char_variety, length, unique_ratio),
        }
        return complexity

    # ── Entropy calculation ────────────────────────────────

    @staticmethod
    def calculate_entropy(password_text: str) -> dict:
        """
        Static method — Calculate both Shannon and charset-based entropy.
        """
        if not password_text:
            return {"shannon_entropy": 0.0, "charset_entropy": 0.0, "bits_per_char": 0.0}

        # Shannon entropy (per-character information content)
        freq = {}
        for ch in password_text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(password_text)
        shannon = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                shannon -= p * math.log2(p)

        # Charset-based entropy
        charset_size = 0
        if re.search(r"[a-z]", password_text):
            charset_size += 26
        if re.search(r"[A-Z]", password_text):
            charset_size += 26
        if re.search(r"\d", password_text):
            charset_size += 10
        if re.search(r"[^A-Za-z0-9]", password_text):
            charset_size += 32

        charset_entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        return {
            "shannon_entropy": round(shannon, 4),
            "charset_entropy": round(charset_entropy, 2),
            "bits_per_char": round(shannon, 4),
            "charset_size": charset_size,
            "total_bits": round(charset_entropy, 2),
        }

    # ── Pattern detection ──────────────────────────────────

    def detect_patterns(self, password_text: str) -> dict:
        """Detect common insecure patterns in the password."""
        patterns_found = []

        # Repeated characters (e.g., aaa, 111)
        repeated = re.findall(r"(.)\1{2,}", password_text)
        if repeated:
            patterns_found.append({
                "type": "Repeated Characters",
                "detail": f"Characters repeated 3+ times: {''.join(repeated)}",
                "severity": "Medium",
            })

        # Sequential letters (abc, xyz)
        seq_alpha = self._find_sequential_alpha(password_text)
        if seq_alpha:
            patterns_found.append({
                "type": "Sequential Letters",
                "detail": f"Sequential letter sequences: {', '.join(seq_alpha)}",
                "severity": "High",
            })

        # Sequential numbers (123, 456)
        seq_num = self._find_sequential_numbers(password_text)
        if seq_num:
            patterns_found.append({
                "type": "Sequential Numbers",
                "detail": f"Sequential number sequences: {', '.join(seq_num)}",
                "severity": "High",
            })

        # Keyboard patterns (qwerty, asdf)
        kb_patterns = self._find_keyboard_patterns(password_text)
        if kb_patterns:
            patterns_found.append({
                "type": "Keyboard Patterns",
                "detail": f"Keyboard walk patterns: {', '.join(kb_patterns)}",
                "severity": "Critical",
            })

        # Date patterns
        if re.search(r"\b(19|20)\d{2}\b", password_text) or re.search(r"\d{2}/\d{2}/\d{2,4}", password_text):
            patterns_found.append({
                "type": "Date Pattern",
                "detail": "Contains a date-like pattern.",
                "severity": "Medium",
            })

        # Leet-speak substitutions
        leet_map = {"@": "a", "3": "e", "1": "i", "0": "o", "$": "s", "7": "t"}
        leet_count = sum(1 for ch in password_text if ch in leet_map)
        if leet_count >= 2:
            patterns_found.append({
                "type": "Leet Speak Substitution",
                "detail": f"Detected {leet_count} leet-speak character(s).",
                "severity": "Low",
            })

        return {
            "patterns_detected": len(patterns_found),
            "patterns": patterns_found,
            "is_pattern_free": len(patterns_found) == 0,
        }

    # ── Full analysis orchestrator ─────────────────────────

    def full_analysis(self, password_text: str) -> dict:
        """Run all analysis checks and return combined results."""
        PasswordAnalyzer._total_analyses += 1
        complexity = self.check_complexity(password_text)
        entropy = self.calculate_entropy(password_text)
        patterns = self.detect_patterns(password_text)

        # Composite score
        score = self._composite_score(complexity, entropy, patterns)
        self.__password_score = score

        return {
            "analysis_id": self.__analysis_id,
            "complexity": complexity,
            "entropy": entropy,
            "patterns": patterns,
            "score": score,
            "strength": self._strength_label(score),
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ── Class method ───────────────────────────────────────

    @classmethod
    def get_total_analyses(cls) -> int:
        """Class method — return total analyses performed across all instances."""
        return cls._total_analyses

    @classmethod
    def overall_security_statistics(cls) -> dict:
        """Class method – aggregate statistics."""
        return {
            "total_analyses_performed": cls._total_analyses,
        }

    # ── Private helpers ────────────────────────────────────

    def _rate_complexity(self, variety: int, length: int, unique_ratio: float) -> str:
        if variety >= 4 and length >= 12 and unique_ratio >= 0.7:
            return "Excellent"
        elif variety >= 3 and length >= 8:
            return "Good"
        elif variety >= 2 and length >= 6:
            return "Fair"
        else:
            return "Poor"

    def _find_sequential_alpha(self, text: str) -> list:
        sequences = []
        lower = text.lower()
        for i in range(len(lower) - 2):
            if (lower[i].isalpha() and lower[i + 1].isalpha() and lower[i + 2].isalpha()):
                if (ord(lower[i + 1]) == ord(lower[i]) + 1 and
                        ord(lower[i + 2]) == ord(lower[i]) + 2):
                    sequences.append(lower[i:i + 3])
                elif (ord(lower[i + 1]) == ord(lower[i]) - 1 and
                      ord(lower[i + 2]) == ord(lower[i]) - 2):
                    sequences.append(lower[i:i + 3])
        return sequences

    def _find_sequential_numbers(self, text: str) -> list:
        sequences = []
        for i in range(len(text) - 2):
            if text[i].isdigit() and text[i + 1].isdigit() and text[i + 2].isdigit():
                if (int(text[i + 1]) == int(text[i]) + 1 and
                        int(text[i + 2]) == int(text[i]) + 2):
                    sequences.append(text[i:i + 3])
                elif (int(text[i + 1]) == int(text[i]) - 1 and
                      int(text[i + 2]) == int(text[i]) - 2):
                    sequences.append(text[i:i + 3])
        return sequences

    def _find_keyboard_patterns(self, text: str) -> list:
        keyboard_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
        ]
        found = []
        lower = text.lower()
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                segment = row[i:i + 4]
                if segment in lower:
                    found.append(segment)
        return found

    def _composite_score(self, complexity: dict, entropy: dict, patterns: dict) -> float:
        score = 0.0
        # Length contribution (max 25)
        score += min(25, complexity["length"] * 2)
        # Variety contribution (max 25)
        score += complexity["character_variety_score"] * 6.25
        # Entropy contribution (max 25)
        score += min(25, entropy["charset_entropy"] / 5)
        # Pattern penalty
        penalty = patterns["patterns_detected"] * 8
        score -= penalty
        # Unique ratio bonus (max 15)
        score += complexity["unique_ratio"] * 15
        # Minimum length bonus
        if complexity["meets_minimum_length"]:
            score += 10

        return round(min(100, max(0, score)), 1)

    def _strength_label(self, score: float) -> str:
        if score <= 20:
            return "Very Weak"
        elif score <= 40:
            return "Weak"
        elif score <= 60:
            return "Moderate"
        elif score <= 80:
            return "Strong"
        else:
            return "Very Strong"

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        return f"PasswordAnalyzer(id={self.__analysis_id}, score={self.__password_score})"

    def __repr__(self) -> str:
        return f"PasswordAnalyzer(analysis_id={self.__analysis_id!r})"
