from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


SUPPORTED_SAN_TYPES = {"dns", "ip", "email", "uri"}


def parse_san_entries(entries: list[str] | None) -> list[x509.GeneralName]:
    if not entries:
        return []

    result = []
    for entry in entries:
        if ":" not in entry:
            raise ValueError(f"Invalid SAN entry: {entry}. Expected type:value")

        san_type, value = entry.split(":", 1)
        san_type = san_type.strip().lower()
        value = value.strip()

        if san_type not in SUPPORTED_SAN_TYPES:
            raise ValueError(f"Unsupported SAN type: {san_type}")

        if not value:
            raise ValueError(f"Empty SAN value in entry: {entry}")

        if san_type == "dns":
            result.append(x509.DNSName(value))
        elif san_type == "ip":
            result.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif san_type == "email":
            result.append(x509.RFC822Name(value))
        elif san_type == "uri":
            parsed = urlparse(value)
            if not parsed.scheme:
                raise ValueError(f"Invalid URI SAN: {value}")
            result.append(x509.UniformResourceIdentifier(value))

    return result


def validate_template_and_sans(template: str, san_objects: list[x509.GeneralName]) -> None:
    if template not in {"server", "client", "code_signing"}:
        raise ValueError("--template must be one of: server, client, code_signing")

    if template == "server":
        if not san_objects:
            raise ValueError("Server certificate requires at least one SAN")
        allowed = (x509.DNSName, x509.IPAddress)
        if not any(isinstance(s, allowed) for s in san_objects):
            raise ValueError("Server certificate requires at least one DNS or IP SAN")
        for s in san_objects:
            if not isinstance(s, allowed):
                raise ValueError("Server template supports only DNS and IP SANs")

    elif template == "client":
        allowed = (x509.DNSName, x509.RFC822Name)
        for s in san_objects:
            if not isinstance(s, allowed):
                raise ValueError("Client template supports only DNS and email SANs")

    elif template == "code_signing":
        allowed = (x509.DNSName, x509.UniformResourceIdentifier)
        for s in san_objects:
            if not isinstance(s, allowed):
                raise ValueError("Code signing template supports only DNS and URI SANs")


def apply_end_entity_template(builder, template: str, private_key, san_objects: list[x509.GeneralName]):
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    if template == "server":
        if hasattr(private_key, "curve"):
            key_usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        else:
            key_usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )

        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )

    elif template == "client":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=hasattr(private_key, "curve"),
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    elif template == "code_signing":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )

    if san_objects:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_objects),
            critical=False,
        )

    return builder