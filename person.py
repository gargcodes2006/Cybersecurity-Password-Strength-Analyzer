# =============================================================
# Person - Abstract Base Class
# Cybersecurity Password Strength Analyzer
# =============================================================

from abc import ABC, abstractmethod
from datetime import datetime


class Person(ABC):
    """
    Abstract base class for all persons in the system.
    Demonstrates: Abstraction, Encapsulation, Constructor,
                  Magic Methods (__str__, __repr__)
    """

    def __init__(self, user_id: str, name: str, email: str):
        """Constructor (__init__) with encapsulation via name-mangling."""
        self.__user_id = user_id          # Private attribute (encapsulation)
        self.__name = name                # Private attribute
        self.__email = email              # Private attribute
        self._created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Properties (Encapsulation) ─────────────────────────

    @property
    def user_id(self) -> str:
        """Read-only access to user_id."""
        return self.__user_id

    @property
    def name(self) -> str:
        return self.__name

    @name.setter
    def name(self, value: str):
        if not value or not value.strip():
            raise ValueError("Name cannot be empty.")
        self.__name = value.strip()

    @property
    def email(self) -> str:
        return self.__email

    @email.setter
    def email(self, value: str):
        if not value or "@" not in value:
            raise ValueError("Invalid email address.")
        self.__email = value.strip()

    # ── Abstract Methods ───────────────────────────────────

    @abstractmethod
    def display_details(self) -> str:
        """Polymorphic method – implemented differently by each subclass."""
        pass

    @abstractmethod
    def update_profile(self, **kwargs) -> None:
        """Update profile fields."""
        pass

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(id={self.__user_id}, name={self.__name})"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"user_id={self.__user_id!r}, "
            f"name={self.__name!r}, "
            f"email={self.__email!r})"
        )

    # ── Serialization helpers ──────────────────────────────

    def to_dict(self) -> dict:
        """Convert person data to dictionary for JSON storage."""
        return {
            "user_id": self.__user_id,
            "name": self.__name,
            "email": self.__email,
            "created_at": self._created_at,
            "type": self.__class__.__name__,
        }
