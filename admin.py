# =============================================================
# Admin - Derived from Person
# Cybersecurity Password Strength Analyzer
# =============================================================

from models.person import Person


class Admin(Person):
    """
    System administrator with report-generation and user-management rights.
    Demonstrates: Inheritance, Polymorphism.
    """

    def __init__(self, user_id: str, name: str, email: str, admin_id: str = None):
        super().__init__(user_id, name, email)
        self.__admin_id = admin_id or f"ADM-{user_id}"

    # ── Properties ─────────────────────────────────────────

    @property
    def admin_id(self) -> str:
        return self.__admin_id

    # ── Polymorphic implementations ────────────────────────

    def display_details(self) -> str:
        """Polymorphism – Admin-specific display."""
        return (
            f"╔══════════════════════════════════════╗\n"
            f"║          ADMIN PROFILE               ║\n"
            f"╠══════════════════════════════════════╣\n"
            f"║ User ID : {self.user_id:<26}║\n"
            f"║ Admin ID: {self.__admin_id:<26}║\n"
            f"║ Name    : {self.name:<26}║\n"
            f"║ Email   : {self.email:<26}║\n"
            f"╚══════════════════════════════════════╝"
        )

    def update_profile(self, **kwargs) -> None:
        if "name" in kwargs:
            self.name = kwargs["name"]
        if "email" in kwargs:
            self.email = kwargs["email"]

    # ── Admin-specific methods ─────────────────────────────

    def generate_reports(self, system) -> list:
        """
        Generate all available reports through the system.
        Returns a list of generated report file paths.
        """
        return system.generate_reports()

    def manage_users(self, system) -> list:
        """Return the list of registered users for management."""
        return system.users

    # ── Magic Methods ──────────────────────────────────────

    def __str__(self) -> str:
        return f"Admin({self.name}, admin_id={self.__admin_id})"

    def __repr__(self) -> str:
        return (
            f"Admin(user_id={self.user_id!r}, name={self.name!r}, "
            f"email={self.email!r}, admin_id={self.__admin_id!r})"
        )

    # ── Serialization ──────────────────────────────────────

    def to_dict(self) -> dict:
        base = super().to_dict()
        base["admin_id"] = self.__admin_id
        return base

    @classmethod
    def from_dict(cls, data: dict) -> "Admin":
        return cls(
            user_id=data["user_id"],
            name=data["name"],
            email=data["email"],
            admin_id=data.get("admin_id"),
        )
