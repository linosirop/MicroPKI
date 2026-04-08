from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec


def verify_certificate_signature(child_cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    issuer_public_key = issuer_cert.public_key()

    if hasattr(issuer_public_key, "verifier") or issuer_public_key.__class__.__name__.lower().startswith("_rsa"):
        issuer_public_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm,
        )
    else:
        issuer_public_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            ec.ECDSA(child_cert.signature_hash_algorithm),
        )