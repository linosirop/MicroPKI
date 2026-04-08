from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from micropki.crypto_utils import generate_private_key
from micropki.certificates import build_self_signed_root_ca


def test_private_key_matches_certificate_public_key_rsa():
    private_key = generate_private_key("rsa", 4096)
    cert = build_self_signed_root_ca(
        private_key=private_key,
        subject_dn="CN=Demo Root CA,O=MicroPKI,C=US",
        validity_days=3650,
    )

    message = b"test message for signature verification"
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    cert.public_key().verify(
        signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )