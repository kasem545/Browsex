"""CLI entrypoint for browser password extraction."""

import csv
import logging
import sys
from argparse import ArgumentParser, Namespace
from io import StringIO
from pathlib import Path

import orjson

from browspass.browsers import Brave, Chrome, Edge, FirefoxDecryptor, Opera
from browspass.models import LoginEntry

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
        return "chrome"

    return None


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


def format_json(logins: list[LoginEntry]) -> str:
    return orjson.dumps(
        [login.to_dict() for login in logins], option=orjson.OPT_INDENT_2
    ).decode("utf-8")


def format_csv(logins: list[LoginEntry]) -> str:
    if not logins:
        return ""

    output = StringIO()
    fieldnames = ["origin_url", "username", "password", "date_created", "times_used"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for login in logins:
        writer.writerow(login.to_dict())
    return output.getvalue()


def format_text(logins: list[LoginEntry]) -> str:
    lines = []
    for login in logins:
        lines.append(f"\nURL: {login.origin_url}")
        lines.append(f"Username: {login.username}")
        lines.append(f"Password: {login.password}")
    return "\n".join(lines)


def handle_firefox(args: Namespace) -> int:
    profile_path = Path(args.profile_path)

    try:
        decryptor = FirefoxDecryptor(profile_path, args.master_password or "")
        logins = decryptor.extract_logins()

        if not logins:
            logger.warning("No logins found")
            return 0

        if args.format == "json":
            print(format_json(logins))
        elif args.format == "csv":
            print(format_csv(logins))
        else:
            print(format_text(logins))

        return 0

    except Exception as e:
        logger.error("Firefox decryption failed: %s", e)
        if args.verbose:
            raise
        return 1


def handle_chromium(args: Namespace, browser_class: type) -> int:
    profile_path = Path(args.profile_path)

    try:
        decryptor = browser_class(profile_path)
        logins = decryptor.extract_logins()

        if not logins:
            logger.warning("No logins found")
            return 0

        if args.format == "json":
            print(format_json(logins))
        elif args.format == "csv":
            print(format_csv(logins))
        else:
            print(format_text(logins))

        return 0

    except Exception as e:
        logger.error("%s decryption failed: %s", browser_class.__name__, e)
        if args.verbose:
            raise
        return 1


def main() -> int:
    parser = ArgumentParser(
        description="Extract and decrypt browser passwords",
        prog="browspass",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="browser", required=False)

    auto_parser = subparsers.add_parser(
        "auto", help="Auto-detect browser and extract passwords"
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

    firefox_parser = subparsers.add_parser("firefox", help="Extract Firefox passwords")
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

    for browser_name, browser_class in [
        ("chrome", Chrome),
        ("brave", Brave),
        ("edge", Edge),
        ("opera", Opera),
    ]:
        browser_parser = subparsers.add_parser(
            browser_name, help=f"Extract {browser_name.capitalize()} passwords"
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

    if args.browser == "firefox":
        return handle_firefox(args)
    if args.browser in ("chrome", "brave", "edge", "opera"):
        return handle_chromium(args, args.browser_class)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
