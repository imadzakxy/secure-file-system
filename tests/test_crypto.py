import os

import pytest

from securefs.crypto import decrypt, derive_key, encrypt, filename_token


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    plaintext = b"top secret data"
    blob = encrypt(key, plaintext)
    assert blob != plaintext
    assert decrypt(key, blob) == plaintext


def test_tamper_detected():
    key = os.urandom(32)
    blob = bytearray(encrypt(key, b"secret"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        decrypt(key, bytes(blob))


def test_wrong_key_rejected():
    key = os.urandom(32)
    other = os.urandom(32)
    blob = encrypt(key, b"secret")
    with pytest.raises(Exception):
        decrypt(other, blob)


def test_aad_authenticated():
    key = os.urandom(32)
    blob = encrypt(key, b"payload", b"header")
    with pytest.raises(Exception):
        decrypt(key, blob, b"other")
    assert decrypt(key, blob, b"header") == b"payload"


def test_filename_token_is_deterministic():
    key = os.urandom(32)
    assert filename_token(key, "file.txt") == filename_token(key, "file.txt")
    assert filename_token(key, "file.txt") != filename_token(key, "other.txt")


def test_derive_key_is_stable():
    salt = os.urandom(16)
    assert derive_key("pass", salt) == derive_key("pass", salt)
    assert derive_key("pass", salt) != derive_key("other", salt)
