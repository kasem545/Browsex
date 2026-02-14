"""CLI entrypoint for browser password extraction."""

import csv
import logging
import sys
from argparse import ArgumentParser, Namespace
from io import StringIO
from pathlib import Path

import orjson

from browsex.browsers import Brave, Chrome, Edge, FirefoxDecryptor, Opera
from browsex.models import BookmarkEntry, HistoryEntry, LoginEntry

logger = logging.getLogger(__name__)


def detect_browser_from_path(profile_path: Path) -> str | None:
    """Auto-detect browser type from profile path structure."""
    path_str = str(profile_path).lower()

    if "firefox" in path_str or ".mozilla" in path_str:
        return "firefox"
    if "chrome" in path_str and "google" in path_str:
        return "chrome"
    if "brave" in path_str:
        return "brave"
    if "edge" in path_str or "microsoft" in path_str:
        return "edge"
    if "opera" in path_str:
        return "opera"

    if (profile_path / "key4.db").exists() and (profile_path / "logins.json").exists():
        return "firefox"
    if (profile_path / "Login Data").exists():
        if "Default" in [p.name for p in profile_path.parents]:
            return "chrome"
        if (profile_path.parent / "Local State").exists():
            if "brave" in str(profile_path.parent).lower():
                return "brave"
            if "edge" in str(profile_path.parent).lower():
                return "edge"
            if "opera" in str(profile_path.parent).lower():
                return "opera"
            return "chrome"

    if (profile_path / "Local State").exists() and (
        profile_path / "Default" / "Login Data"
    ).exists():
        logger.warning(
            "Detected Chrome User Data directory. Please specify a profile directory:"
        )
        profiles = [
            p.name
            for p in profile_path.iterdir()
            if p.is_dir()
            and (p / "Login Data").exists()
            and p.name not in ["extensions_crx_cache", "component_crx_cache"]
        ]
        if profiles:
            logger.warning("Available profiles: %s", ", ".join(profiles))
            logger.warning(
                "Example: browsex chrome -p '%s/%s'", profile_path, profiles[0]
            )
        return None

    return None


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


def format_json(
    logins: list[LoginEntry] | None = None,
    bookmarks: list[BookmarkEntry] | None = None,
    history: list[HistoryEntry] | None = None,
) -> str:
    data: dict[str, list[dict[str, str | int | None]]] = {}
    if logins:
        data["logins"] = [login.to_dict() for login in logins]
    if bookmarks:
        data["bookmarks"] = [bookmark.to_dict() for bookmark in bookmarks]
    if history:
        data["history"] = [entry.to_dict() for entry in history]
    return orjson.dumps(data, option=orjson.OPT_INDENT_2).decode("utf-8")


def format_csv(
    logins: list[LoginEntry] | None = None,
    bookmarks: list[BookmarkEntry] | None = None,
    history: list[HistoryEntry] | None = None,
) -> str:
    output = StringIO()

    if logins:
        fieldnames = [
            "origin_url",
            "username",
            "password",
            "date_created",
            "times_used",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for login in logins:
            writer.writerow(login.to_dict())
        output.write("\n")

    if bookmarks:
        fieldnames = ["url", "title", "date_added", "folder"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for bookmark in bookmarks:
            writer.writerow(bookmark.to_dict())
        output.write("\n")

    if history:
        fieldnames = ["url", "title", "visit_count", "last_visit_time"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in history:
            writer.writerow(entry.to_dict())

    return output.getvalue()


def format_text(
    logins: list[LoginEntry] | None = None,
    bookmarks: list[BookmarkEntry] | None = None,
    history: list[HistoryEntry] | None = None,
) -> str:
    lines = []

    if logins:
        lines.append("\n=== PASSWORDS ===")
        for login in logins:
            lines.append(f"\nURL: {login.origin_url}")
            lines.append(f"Username: {login.username}")
            lines.append(f"Password: {login.password}")

    if bookmarks:
        lines.append("\n\n=== BOOKMARKS ===")
        for bookmark in bookmarks:
            lines.append(f"\nTitle: {bookmark.title}")
            lines.append(f"URL: {bookmark.url}")
            if bookmark.folder:
                lines.append(f"Folder: {bookmark.folder}")

    if history:
        lines.append("\n\n=== HISTORY ===")
        for entry in history:
            lines.append(f"\nURL: {entry.url}")
            if entry.title:
                lines.append(f"Title: {entry.title}")
            if entry.visit_count:
                lines.append(f"Visits: {entry.visit_count}")

    return "\n".join(lines)


def handle_firefox(args: Namespace) -> int:
    profile_path = Path(args.profile_path)

    try:
        decryptor = FirefoxDecryptor(profile_path, args.master_password or "")

        logins = None
        bookmarks = None
        history = None

        if args.passwords:
            logins = decryptor.extract_logins()
        if args.bookmarks:
            bookmarks = decryptor.extract_bookmarks()
        if args.history:
            history = decryptor.extract_history()

        if not any([logins, bookmarks, history]):
            logger.warning("No data found")
            return 0

        if args.format == "json":
            output = format_json(logins, bookmarks, history)
        elif args.format == "csv":
            output = format_csv(logins, bookmarks, history)
        else:
            output = format_text(logins, bookmarks, history)

        if args.output:
            output_path = Path(args.output)
            output_path.write_text(output, encoding="utf-8")
            logger.info("Results written to: %s", output_path)
        else:
            print(output)

        return 0

    except Exception as e:
        logger.error("Firefox extraction failed: %s", e)
        if args.verbose:
            raise
        return 1


def handle_chromium(args: Namespace, browser_class: type) -> int:
    profile_path = Path(args.profile_path)
    masterkey = getattr(args, "masterkey", None)

    try:
        decryptor = browser_class(profile_path, masterkey)

        logins = None
        bookmarks = None
        history = None

        if args.passwords:
            logins = decryptor.extract_logins()
        if args.bookmarks:
            bookmarks = decryptor.extract_bookmarks()
        if args.history:
            history = decryptor.extract_history()

        if not any([logins, bookmarks, history]):
            logger.warning("No data found")
            return 0

        if args.format == "json":
            output = format_json(logins, bookmarks, history)
        elif args.format == "csv":
            output = format_csv(logins, bookmarks, history)
        else:
            output = format_text(logins, bookmarks, history)

        if args.output:
            output_path = Path(args.output)
            output_path.write_text(output, encoding="utf-8")
            logger.info("Results written to: %s", output_path)
        else:
            print(output)

        return 0

    except Exception as e:
        logger.error("%s extraction failed: %s", browser_class.__name__, e)
        if args.verbose:
            raise
        return 1


def main() -> int:
    parser = ArgumentParser(
        description="Extract and decrypt browser passwords",
        prog="browsex",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="browser", required=False)

    auto_parser = subparsers.add_parser(
        "auto", help="Auto-detect browser and extract data"
    )
    auto_parser.add_argument(
        "-p",
        "--profile-path",
        required=True,
        help="Path to browser profile directory",
    )
    auto_parser.add_argument(
        "-m",
        "--master-password",
        default="",
        help="Master password (if set)",
    )
    auto_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    auto_parser.add_argument(
        "--passwords",
        action="store_true",
        help="Extract passwords",
    )
    auto_parser.add_argument(
        "--bookmarks",
        action="store_true",
        help="Extract bookmarks",
    )
    auto_parser.add_argument(
        "--history",
        action="store_true",
        help="Extract history",
    )
    auto_parser.add_argument(
        "--all",
        action="store_true",
        help="Extract all data types",
    )
    auto_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: print to stdout)",
    )

    firefox_parser = subparsers.add_parser("firefox", help="Extract Firefox data")
    firefox_parser.add_argument(
        "-p",
        "--profile-path",
        required=True,
        help="Path to Firefox profile directory",
    )
    firefox_parser.add_argument(
        "-m",
        "--master-password",
        default="",
        help="Firefox master password (if set)",
    )
    firefox_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    firefox_parser.add_argument(
        "--passwords",
        action="store_true",
        help="Extract passwords",
    )
    firefox_parser.add_argument(
        "--bookmarks",
        action="store_true",
        help="Extract bookmarks",
    )
    firefox_parser.add_argument(
        "--history",
        action="store_true",
        help="Extract history",
    )
    firefox_parser.add_argument(
        "--all",
        action="store_true",
        help="Extract all data types",
    )
    firefox_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: print to stdout)",
    )

    for browser_name, browser_class in [
        ("chrome", Chrome),
        ("brave", Brave),
        ("edge", Edge),
        ("opera", Opera),
    ]:
        browser_parser = subparsers.add_parser(
            browser_name, help=f"Extract {browser_name.capitalize()} data"
        )
        browser_parser.add_argument(
            "-p",
            "--profile-path",
            required=True,
            help=f"Path to {browser_name.capitalize()} profile directory",
        )
        browser_parser.add_argument(
            "-f",
            "--format",
            choices=["text", "json", "csv"],
            default="text",
            help="Output format (default: text)",
        )
        browser_parser.add_argument(
            "--passwords",
            action="store_true",
            help="Extract passwords",
        )
        browser_parser.add_argument(
            "--bookmarks",
            action="store_true",
            help="Extract bookmarks",
        )
        browser_parser.add_argument(
            "--history",
            action="store_true",
            help="Extract history",
        )
        browser_parser.add_argument(
            "--all",
            action="store_true",
            help="Extract all data types",
        )
        browser_parser.add_argument(
            "-k",
            "--masterkey",
            default=None,
            help="DPAPI masterkey (64-byte hex) for cross-platform decryption of Windows profiles",
        )
        browser_parser.add_argument(
            "-o",
            "--output",
            default=None,
            help="Output file path (default: print to stdout)",
        )
        browser_parser.set_defaults(browser_class=browser_class)

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.browser == "auto":
        detected = detect_browser_from_path(Path(args.profile_path))
        if not detected:
            logger.error("Could not auto-detect browser from profile path")
            return 1
        args.browser = detected
        logger.info("Auto-detected browser: %s", detected)

    if not args.browser:
        parser.print_help()
        return 1

    if args.all:
        args.passwords = True
        args.bookmarks = True
        args.history = True
    elif not any([args.passwords, args.bookmarks, args.history]):
        args.passwords = True

    if args.browser == "firefox":
        return handle_firefox(args)
    if args.browser in ("chrome", "brave", "edge", "opera"):
        return handle_chromium(args, args.browser_class)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
