# =============================================================
# Password Model
# Cybersecurity Password Strength Analyzer
# =============================================================

import re
import math
import string


class Password:
    """
    Represents a password and provides fundamental analysis.
    Demonstrates: Encapsulation, Static Methods, Magic Methods.
    """

    # ── Password rules stored as tuple (immutable) ─────────
    RULES = (
        ("Minimum 8 characters", lambda p: len(p) >= 8),
        ("Contains uppercase letter", lambda p: bool(re.search(r"[A-Z]", p))),
        ("Contains lowercase letter", lambda p: bool(re.search(r"[a-z]", p))),
        ("Contains digit", lambda p: bool(re.search(r"\d", p))),
        ("Contains special character", lambda p: bool(re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\[\]\\;'/`~]", p))),
    )

    STRENGTH_LEVELS = {
        (0, 20): "Very Weak",
        (21, 40): "Weak",
        (41, 60): "Moderate",
        (61, 80): "Strong",
        (81, 100): "Very Strong",
    }

    def __init__(self, password_text: str):
        if not password_text:
            raise ValueError("Password cannot be empty.")
        self.__password_text = password_text
        self.__length = len(password_text)
        self.__strength = self.calculate_strength()

    # ── Properties ─────────────────────────────────────────

    @property
    def password_text(self) -> str:
        return self.__password_text

    @property
    def length(self) -> int:
        return self.__length

    @property
    def strength(self) -> str:
        return self.__strength

    # ── Core analysis ──────────────────────────────────────

    def analyze_password(self) -> dict:
        """Full analysis of the password against all rules."""
        rules_passed = []
        rules_failed = []
        for description, rule_fn in self.RULES:
            if rule_fn(self.__password_text):
                rules_passed.append(description)
            else:
                rules_failed.append(description)

        score = self.calculate_score()
        strength_label = self._label_from_score(score)

        return {
            "password_masked": self.__password_text[:2] + "*" * max(0, self.__length - 2),
            "length": self.__length,
            "score": score,
            "strength": strength_label,
            "rules_passed": rules_passed,
            "rules_failed": rules_failed,
            "entropy": self.calculate_entropy(),
            "character_analysis": self._character_analysis(),
        }

    def calculate_strength(self) -> str:
        """Return the human-readable strength label."""
        return self._label_from_score(self.calculate_score())

    def calculate_score(self) -> float:
        """
        Calculate a 0-100 score based on multiple factors.
        Demonstrates: Static-like scoring logic applied per instance.
        """
        score = 0.0

        # Length scoring (max 30)
        score += min(30, self.__length * 2.5)

        # Character diversity scoring (max 30)
        has_upper = bool(re.search(r"[A-Z]", self.__password_text))
        has_lower = bool(re.search(r"[a-z]", self.__password_text))
        has_digit = bool(re.search(r"\d", self.__password_text))
        has_special = bool(re.search(r"[^A-Za-z0-9]", self.__password_text))

        diversity = sum([has_upper, has_lower, has_digit, has_special])
        score += diversity * 7.5

        # Entropy bonus (max 20)
        entropy = self.calculate_entropy()
        score += min(20, entropy / 4)

        # Unique character ratio bonus (max 20)
        unique_ratio = len(set(self.__password_text)) / self.__length if self.__length else 0
        score += unique_ratio * 20

        return round(min(100, max(0, score)), 1)

    @staticmethod
    def calculate_entropy_static(password_text: str) -> float:
        """Static method to calculate Shannon entropy of a password."""
        if not password_text:
            return 0.0
        charset_size = 0
        if re.search(r"[a-z]", password_text):
            charset_size += 26
        if re.search(r"[A-Z]", password_text):
            charset_size += 26
        if re.search(r"\d", password_text):
            charset_size += 10
        if re.search(r"[^A-Za-z0-9]", password_text):
            charset_size += 32
        if charset_size == 0:
            return 0.0
        return round(len(password_text) * math.log2(charset_size), 2)

    def calculate_entropy(self) -> float:
        """Instance wrapper around the static entropy calculator."""
        return Password.calculate_entropy_static(self.__password_text)

    # ── Private helpers ────────────────────────────────────

    def _character_analysis(self) -> dict:
        """Break down the password character composition."""
        uppers = sum(1 for c in self.__password_text if c.isupper())
        lowers = sum(1 for c in self.__password_text if c.islower())
        digits = sum(1 for c in self.__password_text if c.isdigit())
        specials = sum(1 for c in self.__password_text if c in string.punctuation)
        spaces = sum(1 for c in self.__password_text if c == " ")
        return {
            "uppercase": uppers,
            "lowercase": lowers,
            "digits": digits,
            "special_characters": specials,
            "spaces": spaces,
            "total": self.__length,
            "unique_characters": len(set(self.__password_text)),
        }

    def _label_from_score(self, score: float) -> str:
        for (lo, hi), label in self.STRENGTH_LEVELS.items():
            if lo <= score <= hi:
                return label
        return "Very Strong" if score > 80 else "Very Weak"

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        masked = self.__password_text[:2] + "*" * max(0, self.__length - 2)
        return f"Password({masked}, strength={self.__strength})"

    def __repr__(self) -> str:
        return f"Password(length={self.__length}, strength={self.__strength!r})"

    def __len__(self) -> int:
        return self.__length

    def __eq__(self, other) -> bool:
        if isinstance(other, Password):
            return self.__password_text == other.__password_text
        return False
