"""Unit tests for NSS cryptographic functions."""

import pytest

from browsex.crypto.nss_crypto import (
    OID_3DES_CBC,
    OID_AES256_CBC,
    OID_PBE_SHA1_3DES,
    OID_PBES2,
    _derive_3des_key_iv,
    decrypt_3des_cbc,
    decrypt_login_field,
    decrypt_pbe,
)


class TestDerive3DesKeyIV:
    def test_key_length(self) -> None:
        global_salt = b"globalsalt"
        password = b"password"
        entry_salt = b"entrysalt"

        key, iv = _derive_3des_key_iv(global_salt, password, entry_salt)

        assert len(key) == 24
        assert len(iv) == 8

    def test_deterministic_output(self) -> None:
        global_salt = b"globalsalt"
        password = b"password"
        entry_salt = b"entrysalt"

        key1, iv1 = _derive_3des_key_iv(global_salt, password, entry_salt)
        key2, iv2 = _derive_3des_key_iv(global_salt, password, entry_salt)

        assert key1 == key2
        assert iv1 == iv2

    def test_different_inputs_produce_different_outputs(self) -> None:
        key1, iv1 = _derive_3des_key_iv(b"salt1", b"pass1", b"entry1")
        key2, iv2 = _derive_3des_key_iv(b"salt2", b"pass2", b"entry2")

        assert key1 != key2
        assert iv1 != iv2


class TestDecrypt3DesCBC:
    def test_basic_decryption(self) -> None:
        from Crypto.Cipher import DES3

        global_salt = b"test_global_salt"
        password = b"test_password"
        entry_salt = b"test_entry_salt"
        plaintext = b"Hello, World!123"

        key, iv = _derive_3des_key_iv(global_salt, password, entry_salt)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)

        decrypted = decrypt_3des_cbc(global_salt, password, entry_salt, ciphertext)

        assert decrypted == plaintext

    def test_wrong_password_produces_garbage(self) -> None:
        from Crypto.Cipher import DES3

        global_salt = b"test_global_salt"
        correct_password = b"correct"
        wrong_password = b"wrong"
        entry_salt = b"test_entry_salt"
        plaintext = b"Hello, World!123"

        key, iv = _derive_3des_key_iv(global_salt, correct_password, entry_salt)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)

        decrypted = decrypt_3des_cbc(
            global_salt, wrong_password, entry_salt, ciphertext
        )

        assert decrypted != plaintext


class TestOIDConstants:
    def test_oid_values(self) -> None:
        assert OID_3DES_CBC == "1.2.840.113549.3.7"
        assert OID_PBE_SHA1_3DES == "1.2.840.113549.1.12.5.1.3"
        assert OID_PBES2 == "1.2.840.113549.1.5.13"
        assert OID_AES256_CBC == "2.16.840.1.101.3.4.1.42"
