"""Tests for profile path validation in browser decryptors."""

import tempfile
from pathlib import Path

import pytest

from browsex.browsers import Chrome, FirefoxDecryptor


class TestChromiumProfileValidation:
    def test_nonexistent_profile_logs_warning(self) -> None:
        nonexistent_path = Path("/nonexistent/profile/path")
        decryptor = Chrome(nonexistent_path)
        assert decryptor.profile_path == nonexistent_path

    def test_file_instead_of_directory_logs_warning(self) -> None:
        with tempfile.NamedTemporaryFile() as temp_file:
            file_path = Path(temp_file.name)
            decryptor = Chrome(file_path)
            assert decryptor.profile_path == file_path

    def test_directory_without_login_data_fails_on_extract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir)
            decryptor = Chrome(profile_path)
            with pytest.raises(FileNotFoundError, match="Login Data not found"):
                decryptor.extract_logins()

    def test_valid_profile_structure_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir)
            login_data = profile_path / "Login Data"
            login_data.touch()

            parent_dir = profile_path.parent
            local_state = parent_dir / "Local State"
            local_state.write_text('{"os_crypt": {"encrypted_key": ""}}')

            try:
                decryptor = Chrome(profile_path)
                assert decryptor.profile_path == profile_path
                assert decryptor.login_data_path == login_data
            finally:
                local_state.unlink(missing_ok=True)


class TestFirefoxProfileValidation:
    def test_nonexistent_profile_logs_warning(self) -> None:
        nonexistent_path = Path("/nonexistent/profile/path")
        decryptor = FirefoxDecryptor(nonexistent_path)
        assert decryptor.profile_path == nonexistent_path

    def test_file_instead_of_directory_logs_warning(self) -> None:
        with tempfile.NamedTemporaryFile() as temp_file:
            file_path = Path(temp_file.name)
            decryptor = FirefoxDecryptor(file_path)
            assert decryptor.profile_path == file_path

    def test_directory_without_key4_db_logs_error_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir)
            logins_path = profile_path / "logins.json"
            logins_path.write_text(
                '{"logins": [{"hostname": "test.com", "encryptedPassword": "dGVzdA=="}]}'
            )

            decryptor = FirefoxDecryptor(profile_path)
            results = decryptor.extract_logins()
            assert len(results) == 0

    def test_directory_without_logins_json_fails_on_extract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir)
            key_db = profile_path / "key4.db"
            key_db.touch()

            decryptor = FirefoxDecryptor(profile_path)
            with pytest.raises(FileNotFoundError, match="logins.json not found"):
                decryptor.extract_logins()

    def test_valid_profile_structure_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir)
            key_db = profile_path / "key4.db"
            logins = profile_path / "logins.json"
            key_db.touch()
            logins.touch()

            decryptor = FirefoxDecryptor(profile_path)
            assert decryptor.profile_path == profile_path
            assert decryptor.key_db_path == key_db
            assert decryptor.logins_path == logins
