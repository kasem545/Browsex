"""NSS (Network Security Services) cryptographic operations for Firefox/Thunderbird."""

import logging
from hashlib import pbkdf2_hmac, sha1
from hmac import new as hmac_new

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import unpad
from pyasn1.codec.der import decoder as der_decoder  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

OID_3DES_CBC = "1.2.840.113549.3.7"
OID_PBE_SHA1_3DES = "1.2.840.113549.1.12.5.1.3"
OID_PBES2 = "1.2.840.113549.1.5.13"
OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"


def _derive_3des_key_iv(
    global_salt: bytes, password: bytes, entry_salt: bytes
) -> tuple[bytes, bytes]:
    hp = sha1(global_salt + password).digest()
    pes = entry_salt.ljust(20, b"\x00")
    chp = sha1(hp + entry_salt).digest()

    k1 = hmac_new(chp, pes + entry_salt, sha1).digest()
    tk = hmac_new(chp, pes, sha1).digest()
    k2 = hmac_new(chp, tk + entry_salt, sha1).digest()

    k = k1 + k2
    return k[:24], k[-8:]


def decrypt_3des_cbc(
    global_salt: bytes, password: bytes, entry_salt: bytes, ciphertext: bytes
) -> bytes:
    key, iv = _derive_3des_key_iv(global_salt, password, entry_salt)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def _try_decrypt_v10_format(
    data: bytes, password: bytes, global_salt: bytes
) -> tuple[bytes, str] | None:
    """Try to decrypt modern Firefox v10/v11 AES-GCM format.

    Format: [v10][12-byte nonce][ciphertext][16-byte tag]
    """
    if len(data) < 29:  # 4 (v10) + 12 (nonce) + 1 (min ciphertext) + 16 (tag)
        return None

    if data[:4] != b"v10\x00":
        return None

    try:
        nonce = data[4:16]
        ciphertext_and_tag = data[16:]

        if len(ciphertext_and_tag) < 16:
            return None

        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        k_intermediate = sha1(global_salt + password).digest()
        key = pbkdf2_hmac("sha256", k_intermediate, b"", 1, 32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        logger.debug("Successfully decrypted v10 format")
        return plaintext, "v10-aes-gcm"
    except Exception as e:
        logger.debug("v10 format decryption failed: %s", e)
        return None


def _try_decrypt_direct_aes_gcm(
    data: bytes, master_key: bytes
) -> tuple[bytes, str] | None:
    """Try to decrypt direct AES-GCM format without ASN.1 wrapping.

    Format: [12-byte nonce][ciphertext][16-byte tag]
    """
    if len(data) < 29:  # 12 (nonce) + 1 (min ciphertext) + 16 (tag)
        return None

    try:
        nonce = data[:12]
        ciphertext_and_tag = data[12:]

        if len(ciphertext_and_tag) < 16:
            return None

        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        key = master_key[:32]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        logger.debug("Successfully decrypted direct AES-GCM format")
        return plaintext, "direct-aes-gcm"
    except Exception as e:
        logger.debug("Direct AES-GCM decryption failed: %s", e)
        return None


def decrypt_pbe(
    asn1_data: bytes, password: bytes, global_salt: bytes
) -> tuple[bytes, str]:
    try:
        decoded = der_decoder.decode(asn1_data)[0]
        oid = str(decoded[0][0][0])
    except Exception as e:
        logger.debug("ASN.1 decoding failed: %s. Trying alternative formats.", e)
        oid = None

    if oid == OID_PBE_SHA1_3DES:
        entry_salt = decoded[0][0][1][0].asOctets()
        ciphertext = decoded[0][1].asOctets()
        plaintext = decrypt_3des_cbc(global_salt, password, entry_salt, ciphertext)
        return plaintext, oid

    if oid == OID_PBES2:
        pbkdf2_params = decoded[0][0][1][0][1]
        entry_salt = pbkdf2_params[0].asOctets()
        iterations = int(pbkdf2_params[1])
        key_length = int(pbkdf2_params[2])

        aes_params = decoded[0][0][1][1]
        iv = b"\x04\x0e" + aes_params[1].asOctets()

        ciphertext = decoded[0][1].asOctets()

        k_intermediate = sha1(global_salt + password).digest()
        key = pbkdf2_hmac("sha256", k_intermediate, entry_salt, iterations, key_length)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext, oid

    if oid and oid not in (OID_PBE_SHA1_3DES, OID_PBES2):
        logger.debug("Unrecognized OID: %s. Trying v10 format.", oid)

    result = _try_decrypt_v10_format(asn1_data, password, global_salt)
    if result:
        return result

    raise ValueError(
        f"Unsupported PBE algorithm: {oid or 'unknown'}. "
        f"Data length: {len(asn1_data)} bytes. "
        f"First 16 bytes: {asn1_data[:16].hex()}"
    )


def decrypt_login_field(encrypted_data: bytes, master_key: bytes) -> str:
    try:
        decoded = der_decoder.decode(encrypted_data)[0]
        oid = str(decoded[0][1][0])
        iv = decoded[0][1][1].asOctets()
        ciphertext = decoded[0][2].asOctets()
    except Exception as e:
        logger.debug("ASN.1 decoding failed: %s. Trying alternative formats.", e)
        oid = None
        iv = None
        ciphertext = None

    if oid == OID_3DES_CBC:
        key = master_key[:24]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        return plaintext.decode("utf-8", errors="replace")

    if oid == OID_AES256_CBC:
        key = master_key[:32]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode("utf-8", errors="replace")

    result = _try_decrypt_direct_aes_gcm(encrypted_data, master_key)
    if result:
        plaintext, _ = result
        return plaintext.decode("utf-8", errors="replace")

    raise ValueError(
        f"Unsupported login encryption algorithm: {oid or 'unknown'}. "
        f"Data length: {len(encrypted_data)} bytes. "
        f"First 16 bytes: {encrypted_data[:16].hex()}"
    )
