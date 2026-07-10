from auth.kerberos.kdf import derive_user_key


def test_same_user_same_password_same_key():
    assert derive_user_key("lucas", "senha123") == derive_user_key("lucas", "senha123")


def test_same_password_different_user_different_key():
    assert derive_user_key("lucas", "senha123") != derive_user_key("alice", "senha123")


def test_different_password_different_key():
    assert derive_user_key("lucas", "senha123") != derive_user_key("lucas", "outra")


def test_key_length_is_32_bytes():
    assert len(derive_user_key("lucas", "senha123")) == 32
