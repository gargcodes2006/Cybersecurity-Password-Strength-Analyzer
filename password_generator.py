# =============================================================
# PasswordGenerator Model
# Cybersecurity Password Strength Analyzer
# =============================================================

import random
import string


class PasswordGenerator:
    """
    Generates strong, random passwords and provides suggestions.
    """

    def __init__(self):
        self.__generated_password = ""

    # ── Properties ─────────────────────────────────────────

    @property
    def generated_password(self) -> str:
        return self.__generated_password

    # ── Password generation ────────────────────────────────

    def generate_password(self, length: int = 16,
                          use_upper: bool = True,
                          use_lower: bool = True,
                          use_digits: bool = True,
                          use_special: bool = True) -> str:
        """
        Generate a cryptographically-inspired random password.
        Guarantees at least one character from each selected category.
        """
        if length < 8:
            length = 8

        charset = ""
        required = []

        if use_upper:
            charset += string.ascii_uppercase
            required.append(random.choice(string.ascii_uppercase))
        if use_lower:
            charset += string.ascii_lowercase
            required.append(random.choice(string.ascii_lowercase))
        if use_digits:
            charset += string.digits
            required.append(random.choice(string.digits))
        if use_special:
            special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            charset += special
            required.append(random.choice(special))

        if not charset:
            charset = string.ascii_letters + string.digits
            required.append(random.choice(string.ascii_letters))

        remaining_length = length - len(required)
        password_chars = required + [random.choice(charset) for _ in range(remaining_length)]
        random.shuffle(password_chars)

        self.__generated_password = "".join(password_chars)
        return self.__generated_password

    def suggest_password(self, base_password: str = "") -> list:
        """
        Generate a list of 5 strong password suggestions.
        If a base_password is given, generate variants inspired by it.
        """
        suggestions = []

        # Generate 5 different random passwords with varying lengths
        for length in [12, 14, 16, 18, 20]:
            pwd = self.generate_password(length=length)
            suggestions.append(pwd)

        return suggestions

    def generate_passphrase(self, word_count: int = 4) -> str:
        """Generate a passphrase-style password using random words and separators."""
        word_bank = [
            "Alpha", "Bravo", "Cyber", "Delta", "Eagle", "Frost",
            "Guard", "Hydra", "Intel", "Joker", "Knife", "Lunar",
            "Nexus", "Omega", "Prism", "Quake", "Raven", "Storm",
            "Titan", "Ultra", "Venom", "Wrath", "Xenon", "Yield",
            "Zephyr", "Blaze", "Crypt", "Drift", "Ember", "Flock",
        ]
        separators = ["!", "@", "#", "$", "-", "_", ".", "&"]

        chosen_words = random.sample(word_bank, min(word_count, len(word_bank)))
        sep = random.choice(separators)
        # Add a random digit suffix to each word
        parts = [w + str(random.randint(0, 99)) for w in chosen_words]
        passphrase = sep.join(parts)
        self.__generated_password = passphrase
        return passphrase

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        masked = self.__generated_password[:3] + "***" if self.__generated_password else "(none)"
        return f"PasswordGenerator(last={masked})"

    def __repr__(self) -> str:
        return "PasswordGenerator()"
