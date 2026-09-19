# =============================================================
# User - Derived from Person
# Cybersecurity Password Strength Analyzer
# =============================================================

from datetime import datetime
from models.person import Person


class User(Person):
    """
    Registered user who can analyse passwords.
    Demonstrates: Inheritance, Polymorphism, Encapsulation.
    """

    def __init__(self, user_id: str, name: str, email: str,
                 password_history: list = None, security_score: float = 0.0):
        super().__init__(user_id, name, email)
        self.__password_history = password_history if password_history else []
        self.__security_score = security_score

    # ── Properties ─────────────────────────────────────────

    @property
    def password_history(self) -> list:
        return list(self.__password_history)   # return copy for safety

    @property
    def security_score(self) -> float:
        return self.__security_score

    @security_score.setter
    def security_score(self, value: float):
        self.__security_score = max(0.0, min(100.0, value))

    # ── Polymorphic implementations ────────────────────────

    def display_details(self) -> str:
        """Polymorphism – User-specific display."""
        return (
            f"╔══════════════════════════════════════╗\n"
            f"║          USER PROFILE                ║\n"
            f"╠══════════════════════════════════════╣\n"
            f"║ ID    : {self.user_id:<28}║\n"
            f"║ Name  : {self.name:<28}║\n"
            f"║ Email : {self.email:<28}║\n"
            f"║ Score : {self.__security_score:<28.1f}║\n"
            f"║ Checks: {len(self.__password_history):<28}║\n"
            f"╚══════════════════════════════════════╝"
        )

    def update_profile(self, **kwargs) -> None:
        """Update user profile fields."""
        if "name" in kwargs:
            self.name = kwargs["name"]
        if "email" in kwargs:
            self.email = kwargs["email"]

    # ── Password analysis helpers ──────────────────────────

    def analyze_password(self, password_text: str, analysis_result: dict) -> None:
        """Store an analysis result in the user's history."""
        record = {
            "password_masked": password_text[:2] + "*" * (len(password_text) - 2),
            "score": analysis_result.get("score", 0),
            "strength": analysis_result.get("strength", "Unknown"),
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": analysis_result,
        }
        self.__password_history.append(record)
        # Update user's overall security score to the latest analysis score
        self.__security_score = analysis_result.get("score", self.__security_score)

    def view_history(self) -> list:
        """Return full password analysis history."""
        return list(self.__password_history)

    # ── Magic Methods ──────────────────────────────────────

    def __len__(self) -> int:
        """Number of passwords analysed by this user."""
        return len(self.__password_history)

    def __str__(self) -> str:
        return (
            f"User({self.name}, score={self.__security_score:.1f}, "
            f"analyses={len(self.__password_history)})"
        )

    # ── Serialization ──────────────────────────────────────

    def to_dict(self) -> dict:
        base = super().to_dict()
        base.update({
            "password_history": self.__password_history,
            "security_score": self.__security_score,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        """Construct a User from a dictionary (JSON deserialization)."""
        user = cls(
            user_id=data["user_id"],
            name=data["name"],
            email=data["email"],
            password_history=data.get("password_history", []),
            security_score=data.get("security_score", 0.0),
        )
        return user
