import pytest

from auth.kerberos.crypto import decrypt, encrypt, generate_key


def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    payload = {"hello": "world", "n": 1}
    token = encrypt(key, payload)
    assert decrypt(key, token) == payload


def test_wrong_key_fails():
    key = generate_key()
    wrong_key = generate_key()
    token = encrypt(key, {"hello": "world"})
    with pytest.raises(Exception):
        decrypt(wrong_key, token)


def test_tampered_payload_fails():
    key = generate_key()
    token = encrypt(key, {"hello": "world"})
    tampered = token[:-2] + "AA"
    with pytest.raises(Exception):
        decrypt(key, tampered)


def test_generate_key_length():
    assert len(generate_key()) == 32
