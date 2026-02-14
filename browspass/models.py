"""Shared data models for browser password extraction."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LoginEntry:
    """Represents a single login credential entry.

    Attributes:
        origin_url: The URL where the login is used (Chrome) or hostname (Firefox)
        username: The username/email address
        password: The decrypted password in plaintext
        date_created: Optional timestamp (Chromium timestamp or Unix timestamp)
        times_used: Optional usage count (Chromium only)
    """

    origin_url: str
    username: str
    password: str
    date_created: int | None = None
    times_used: int | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "origin_url": self.origin_url,
            "username": self.username,
            "password": self.password,
            "date_created": self.date_created,
            "times_used": self.times_used,
        }
