from micropki.crypto_utils import (
    generate_private_key,
    serialize_encrypted_private_key,
    load_encrypted_private_key,
)


def test_encrypted_private_key_can_be_loaded():
    passphrase = b"mypassword123"
    private_key = generate_private_key("rsa", 4096)

    pem_data = serialize_encrypted_private_key(private_key, passphrase)
    loaded_key = load_encrypted_private_key(pem_data, passphrase)

    assert loaded_key.private_numbers() == private_key.private_numbers()