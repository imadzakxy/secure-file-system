import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16


def derive_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_LEN,
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def filename_token(key: bytes, name: str) -> str:
    return hmac.new(key, name.encode("utf-8"), hashlib.sha256).hexdigest()


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
