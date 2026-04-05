from micropki.crypto_utils import generate_private_key


def test_generate_rsa_key():
    key = generate_private_key("rsa", 4096)
    assert key.key_size == 4096


def test_generate_ecc_key():
    key = generate_private_key("ecc", 384)
    curve_name = key.curve.name.lower()
    assert "secp384r1" in curve_name