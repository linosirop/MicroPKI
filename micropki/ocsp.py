from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.ocsp import OCSPResponseBuilder, load_der_ocsp_request, OCSPResponseStatus

from micropki.database import get_certificate_by_serial
from micropki.certificates import certificate_common_name


def build_ocsp_responder_certificate(
        issuer_cert,
        issuer_key,
        subject_dn: str,
        subject_public_key,
        validity_days: int,
        san_objects=None,
):
    """Создаёт специальный OCSP Signing сертификат"""
    from micropki.certificates import build_end_entity_certificate
    from micropki.templates import apply_ocsp_template

    def template_builder(builder):
        return apply_ocsp_template(builder, subject_public_key, san_objects)

    return build_end_entity_certificate(
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        subject_dn=subject_dn,
        subject_public_key=subject_public_key,
        validity_days=validity_days,
        template_builder=template_builder,
    )


def get_issuer_hashes(ca_cert: x509.Certificate):
    """Возвращает (name_hash, key_hash) для Issuer"""
    name_hash = hashlib.sha1(ca_cert.subject.public_bytes()).digest()
    key_hash = hashlib.sha1(ca_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).digest()
    return name_hash, key_hash


def get_cert_status(db_path: str, serial_hex: str, issuer_cert: x509.Certificate):
    """Определяет статус сертификата для OCSP"""
    row = get_certificate_by_serial(db_path, serial_hex)

    if row is None:
        return "unknown", None, None

    # Проверяем, что сертификат выдан тем же CA
    if row["issuer"] != issuer_cert.subject.rfc4514_string():
        return "unknown", None, None

    if row["status"] == "revoked":
        return "revoked", row.get("revocation_date"), row.get("revocation_reason")

    return "good", None, None


def build_ocsp_response(
        ocsp_request,
        db_path: str,
        issuer_cert: x509.Certificate,
        responder_cert: x509.Certificate,
        responder_key,
        cache_ttl: int = 60,
) -> bytes:
    """Основная функция построения OCSP ответа"""
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(seconds=cache_ttl)

    builder = OCSPResponseBuilder()

    # Получаем nonce, если есть
    nonce = None
    try:
        nonce_ext = ocsp_request.extensions.get_extension_for_oid(ExtensionOID.OCSP_NONCE)
        nonce = nonce_ext.value
    except x509.ExtensionNotFound:
        pass

    # Обрабатываем все запросы (обычно один)
    for req in ocsp_request:
        serial_hex = f"{req.serial_number:x}".upper()
        status, rev_date, rev_reason = get_cert_status(db_path, serial_hex, issuer_cert)

        single_response = x509.ocsp.OCSPSingleResponse(
            certid=req,
            cert_status=status,
            this_update=now,
            next_update=next_update,
            revocation_time=rev_date,
            revocation_reason=rev_reason,
        )
        builder = builder.add_response(single_response)
        break  # пока поддерживаем один запрос за раз

    if nonce:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    ocsp_response = builder.sign(
        responder_key,
        hashes.SHA256(),
        responder_cert
    )

    return ocsp_response.public_bytes()