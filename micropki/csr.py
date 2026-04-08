from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

from micropki.certificates import parse_subject_dn


def build_intermediate_csr(private_key, subject_dn: str, pathlen: int):
    subject = parse_subject_dn(subject_dn)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True,
    )

    if hasattr(private_key, "curve"):
        algorithm = hashes.SHA384()
    else:
        algorithm = hashes.SHA256()

    return builder.sign(private_key, algorithm)


def serialize_csr(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    return csr.is_signature_valid


def get_csr_basic_constraints(csr: x509.CertificateSigningRequest):
    try:
        return csr.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return None