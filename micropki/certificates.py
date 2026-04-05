from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


DN_MAP = {
    "CN": NameOID.COMMON_NAME,
    "C": NameOID.COUNTRY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
}


def parse_subject_dn(dn_string: str) -> x509.Name:
    dn_string = dn_string.strip()
    if not dn_string:
        raise ValueError("Subject DN must not be empty")

    attrs = []

    if dn_string.startswith("/"):
        parts = [p for p in dn_string.split("/") if p]
        for part in parts:
            if "=" not in part:
                raise ValueError(f"Invalid DN component: {part}")
            key, value = part.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            if key not in DN_MAP or not value:
                raise ValueError(f"Unsupported or empty DN attribute: {part}")
            attrs.append(x509.NameAttribute(DN_MAP[key], value))
    else:
        parts = re.split(r"(?<!\\),", dn_string)
        for part in parts:
            if "=" not in part:
                raise ValueError(f"Invalid DN component: {part}")
            key, value = part.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            if key not in DN_MAP or not value:
                raise ValueError(f"Unsupported or empty DN attribute: {part}")
            attrs.append(x509.NameAttribute(DN_MAP[key], value))

    if not attrs:
        raise ValueError("No valid DN attributes found")

    return x509.Name(attrs)


def build_self_signed_root_ca(private_key, subject_dn: str, validity_days: int):
    subject = parse_subject_dn(subject_dn)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )

    if private_key.__class__.__name__.lower().startswith("_ec") or "ec" in private_key.__class__.__name__.lower():
        algorithm = hashes.SHA384()
    else:
        algorithm = hashes.SHA256()

    cert = builder.sign(private_key=private_key, algorithm=algorithm)

    return cert


def serialize_certificate(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)