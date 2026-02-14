"""Tests for intelligent file discovery."""

import tempfile
from pathlib import Path

import pytest

from browsex.browsers import Chrome
from browsex.utils import find_chrome_local_state, find_file, find_profile_directory


class TestFindFile:
    def test_find_file_in_same_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)
            target_file = test_path / "Login Data"
            target_file.touch()

            found = find_file(test_path, "Login Data")
            assert found == target_file

    def test_find_file_in_subdirectory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)
            (test_path / "Default").mkdir()
            target_file = test_path / "Default" / "Login Data"
            target_file.touch()

            found = find_file(test_path, "Login Data", max_depth=2)
            assert found == target_file

    def test_find_file_respects_max_depth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)
            (test_path / "a" / "b" / "c" / "d").mkdir(parents=True)
            target_file = test_path / "a" / "b" / "c" / "d" / "Login Data"
            target_file.touch()

            found = find_file(test_path, "Login Data", max_depth=2)
            assert found is None

            found = find_file(test_path, "Login Data", max_depth=5)
            assert found == target_file

    def test_find_file_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)
            target_file = test_path / "login data"
            target_file.touch()

            found = find_file(test_path, "Login Data", case_sensitive=False)
            assert found == target_file

    def test_find_file_returns_none_when_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir)

            found = find_file(test_path, "NonexistentFile")
            assert found is None


class TestFindChromeLocalState:
    def test_find_local_state_in_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)
            profile = user_data / "Default"
            profile.mkdir()
            local_state = user_data / "Local State"
            local_state.touch()

            found = find_chrome_local_state(profile)
            assert found == local_state

    def test_find_local_state_in_grandparent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)
            browser_dir = user_data / "Brave-Browser"
            profile = browser_dir / "Default"
            profile.mkdir(parents=True)
            local_state = user_data / "Local State"
            local_state.touch()

            found = find_chrome_local_state(profile)
            assert found == local_state

    def test_find_local_state_recursive_search(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "nested" / "dirs").mkdir(parents=True)
            local_state = base / "nested" / "Local State"
            local_state.touch()

            found = find_chrome_local_state(base)
            assert found == local_state


class TestFindProfileDirectory:
    def test_find_profiles_with_marker_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)

            default = user_data / "Default"
            default.mkdir()
            (default / "Login Data").touch()
            (default / "Cookies").touch()

            profile1 = user_data / "Profile 1"
            profile1.mkdir()
            (profile1 / "Login Data").touch()
            (profile1 / "Cookies").touch()

            profiles = find_profile_directory(
                user_data, ["Login Data", "Cookies"], max_depth=1
            )

            assert len(profiles) == 2
            assert default in profiles
            assert profile1 in profiles

    def test_find_profiles_excludes_cache_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)

            cache_dir = user_data / "extensions_crx_cache"
            cache_dir.mkdir()
            (cache_dir / "Login Data").touch()

            profiles = find_profile_directory(user_data, ["Login Data"], max_depth=1)

            assert cache_dir not in profiles


class TestChromeWithUserDataDirectory:
    def test_chrome_finds_files_in_user_data_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)
            default = user_data / "Default"
            default.mkdir()

            (default / "Login Data").touch()
            (default / "Bookmarks").touch()
            (default / "History").touch()
            (user_data / "Local State").write_text('{"os_crypt": {}}')

            decryptor = Chrome(default)

            assert decryptor.login_data_path == default / "Login Data"
            assert decryptor.local_state_path == user_data / "Local State"
            assert decryptor.bookmarks_path == default / "Bookmarks"
            assert decryptor.history_path == default / "History"

    def test_chrome_finds_files_when_pointed_at_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data = Path(temp_dir)
            default = user_data / "Default"
            default.mkdir()

            (default / "Login Data").touch()
            (user_data / "Local State").write_text('{"os_crypt": {}}')

            decryptor = Chrome(user_data)

            assert decryptor.login_data_path == default / "Login Data"
            assert decryptor.local_state_path == user_data / "Local State"
