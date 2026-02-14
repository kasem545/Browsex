"""Intelligent file discovery for browser data extraction."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def find_file(
    base_path: Path,
    filename: str,
    max_depth: int = 3,
    case_sensitive: bool = False,
) -> Path | None:
    """Recursively search for a file within a directory tree.

    Args:
        base_path: Directory to search from
        filename: Exact filename to find (e.g., "Login Data", "logins.json")
        max_depth: Maximum directory depth to search (default: 3)
        case_sensitive: Whether filename matching is case-sensitive

    Returns:
        Path to found file, or None if not found
    """
    if not base_path.exists() or not base_path.is_dir():
        return None

    search_name = filename if case_sensitive else filename.lower()

    def search_recursive(current_path: Path, depth: int) -> Path | None:
        if depth > max_depth:
            return None

        try:
            for item in current_path.iterdir():
                item_name = item.name if case_sensitive else item.name.lower()

                if item.is_file() and item_name == search_name:
                    logger.debug("Found %s at %s", filename, item)
                    return item

                if item.is_dir() and not item.name.startswith("."):
                    result = search_recursive(item, depth + 1)
                    if result:
                        return result

        except PermissionError:
            logger.debug("Permission denied: %s", current_path)

        return None

    result = search_recursive(base_path, 0)

    if not result:
        logger.debug(
            "File %s not found in %s (max_depth=%d)", filename, base_path, max_depth
        )

    return result


def find_profile_directory(
    base_path: Path,
    marker_files: list[str],
    max_depth: int = 2,
) -> list[Path]:
    """Find directories containing specific marker files.

    Useful for finding browser profile directories within User Data.

    Args:
        base_path: Directory to search from
        marker_files: Files that must exist for a directory to be considered a profile
        max_depth: Maximum directory depth to search

    Returns:
        List of directories containing all marker files
    """
    if not base_path.exists() or not base_path.is_dir():
        return []

    profiles = []

    def search_recursive(current_path: Path, depth: int) -> None:
        if depth > max_depth:
            return

        try:
            has_all_markers = all(
                (current_path / marker).exists() for marker in marker_files
            )

            if has_all_markers:
                profiles.append(current_path)
                logger.debug("Found profile directory: %s", current_path)
                return

            for item in current_path.iterdir():
                if (
                    item.is_dir()
                    and not item.name.startswith(".")
                    and item.name not in ["extensions_crx_cache", "component_crx_cache"]
                ):
                    search_recursive(item, depth + 1)

        except PermissionError:
            logger.debug("Permission denied: %s", current_path)

    search_recursive(base_path, 0)
    return profiles


def find_chrome_local_state(profile_or_user_data: Path) -> Path | None:
    """Find Local State file for Chromium browsers.

    Searches upward from profile directory and downward from User Data.

    Args:
        profile_or_user_data: Profile directory or User Data directory

    Returns:
        Path to Local State file, or None if not found
    """
    candidates = [
        profile_or_user_data / "Local State",
        profile_or_user_data.parent / "Local State",
        profile_or_user_data.parent.parent / "Local State",
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            logger.debug("Found Local State at %s", candidate)
            return candidate

    result = find_file(profile_or_user_data, "Local State", max_depth=3)
    if result:
        return result

    if profile_or_user_data.parent != profile_or_user_data:
        result = find_file(profile_or_user_data.parent, "Local State", max_depth=2)
        if result:
            return result

    logger.debug("Local State not found near %s", profile_or_user_data)
    return None
