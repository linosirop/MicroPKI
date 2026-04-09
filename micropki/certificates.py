from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from micropki.serial import generate_unique_serial_int


DN_MAP = {
    "CN": NameOID.COMMON_NAME,
    "C": NameOID.COUNTRY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
    "EMAIL": NameOID.EMAIL_ADDRESS,
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


def choose_hash_for_signing(private_key):
    if hasattr(private_key, "curve"):
        if private_key.curve.name == "secp384r1":
            return hashes.SHA384()
        return hashes.SHA256()
    return hashes.SHA256()


def build_self_signed_root_ca(private_key, subject_dn: str, validity_days: int):
    subject = parse_subject_dn(subject_dn)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(generate_unique_serial_int())
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
    )

    return builder.sign(private_key=private_key, algorithm=choose_hash_for_signing(private_key))


def build_intermediate_certificate(root_cert, root_key, csr, validity_days: int, pathlen: int):
    now = datetime.now(timezone.utc)

    root_ski = root_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value.digest

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(generate_unique_serial_int())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
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
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=root_ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    )

    return builder.sign(private_key=root_key, algorithm=choose_hash_for_signing(root_key))


def build_end_entity_certificate(
    issuer_cert,
    issuer_key,
    subject_dn: str,
    subject_public_key,
    validity_days: int,
    template_builder,
):
    now = datetime.now(timezone.utc)

    issuer_ski = issuer_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value.digest

    builder = (
        x509.CertificateBuilder()
        .subject_name(parse_subject_dn(subject_dn))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_public_key)
        .serial_number(generate_unique_serial_int())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=issuer_ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    )

    builder = template_builder(builder)

    return builder.sign(private_key=issuer_key, algorithm=choose_hash_for_signing(issuer_key))


def serialize_certificate(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def certificate_common_name(cert: x509.Certificate) -> str:
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return f"cert-{cert.serial_number:x}"