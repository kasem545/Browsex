"""NSS (Network Security Services) cryptographic operations for Firefox/Thunderbird."""

from hashlib import pbkdf2_hmac, sha1
from hmac import new as hmac_new

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import unpad
from pyasn1.codec.der import decoder as der_decoder  # type: ignore[import-untyped]

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


def decrypt_pbe(
    asn1_data: bytes, password: bytes, global_salt: bytes
) -> tuple[bytes, str]:
    decoded = der_decoder.decode(asn1_data)[0]
    oid = str(decoded[0][0][0])

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

    raise ValueError(f"Unsupported PBE algorithm: {oid}")


def decrypt_login_field(encrypted_data: bytes, master_key: bytes) -> str:
    decoded = der_decoder.decode(encrypted_data)[0]
    oid = str(decoded[0][1][0])
    iv = decoded[0][1][1].asOctets()
    ciphertext = decoded[0][2].asOctets()

    if oid == OID_3DES_CBC:
        key = master_key[:24]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)

    elif oid == OID_AES256_CBC:
        key = master_key[:32]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    else:
        raise ValueError(f"Unsupported login encryption algorithm: {oid}")

    return plaintext.decode("utf-8", errors="replace")
