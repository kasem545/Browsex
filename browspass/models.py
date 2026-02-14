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


@dataclass(frozen=True)
class BookmarkEntry:
    """Represents a single bookmark entry.

    Attributes:
        url: The bookmark URL
        title: The bookmark title
        date_added: Timestamp when bookmark was added
        folder: The folder/category where bookmark is stored
    """

    url: str
    title: str
    date_added: int | None = None
    folder: str | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "title": self.title,
            "date_added": self.date_added,
            "folder": self.folder,
        }


@dataclass(frozen=True)
class HistoryEntry:
    """Represents a single history entry.

    Attributes:
        url: The visited URL
        title: The page title
        visit_count: Number of times visited
        last_visit_time: Timestamp of last visit
    """

    url: str
    title: str | None = None
    visit_count: int | None = None
    last_visit_time: int | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "title": self.title,
            "visit_count": self.visit_count,
            "last_visit_time": self.last_visit_time,
        }
