from __future__ import annotations

import logging
import requests
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response


def extract_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    """Извлекает URL OCSP responder из AIA расширения"""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_crl_url(cert: x509.Certificate) -> Optional[str]:
    """Извлекает CRL URL из CDP расширения"""
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in cdp.value:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    return name.value
    except x509.ExtensionNotFound:
        pass
    return None


def fetch_crl(url: str, logger: logging.Logger) -> Optional[x509.CertificateRevocationList]:
    """Загружает CRL по URL"""
    try:
        if url.startswith(("http://", "https://")):
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            crl_data = resp.content
        else:
            with open(url, "rb") as f:
                crl_data = f.read()

        # Пробуем загрузить как PEM или DER
        try:
            return x509.load_pem_x509_crl(crl_data)
        except ValueError:
            return x509.load_der_x509_crl(crl_data)
    except Exception as e:
        logger.warning(f"Failed to fetch CRL from {url}: {e}")
        return None


def check_crl(
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
        crl_source: Optional[str],
        logger: logging.Logger,
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Проверяет статус сертификата по CRL.
    Возвращает (status, revocation_date, revocation_reason)
    status: "good", "revoked", "unknown"
    """
    # Определяем источник CRL
    if crl_source:
        crl_urls = [crl_source]
    else:
        crl_url = extract_crl_url(cert)
        if not crl_url:
            return "unknown", None, None
        crl_urls = [crl_url]

    for url in crl_urls:
        crl = fetch_crl(url, logger)
        if crl is None:
            continue

        # Проверяем подпись CRL
        try:
            issuer_public_key = issuer_cert.public_key()
            if hasattr(issuer_public_key, "verify"):
                issuer_public_key.verify(
                    crl.signature,
                    crl.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    crl.signature_hash_algorithm,
                )
            else:
                issuer_public_key.verify(
                    crl.signature,
                    crl.tbs_certificate_bytes,
                    ec.ECDSA(crl.signature_hash_algorithm),
                )
        except Exception as e:
            logger.warning(f"CRL signature verification failed: {e}")
            continue

        # Проверяем свежесть CRL
        now = datetime.now(timezone.utc)
        if crl.next_update and now > crl.next_update:
            logger.warning(f"CRL is expired (next_update={crl.next_update})")

        # Ищем серийный номер
        for revoked in crl:
            if revoked.serial_number == cert.serial_number:
                reason = "unspecified"
                for ext in revoked.extensions:
                    if ext.oid == ExtensionOID.CRL_REASON:
                        reason = ext.value.value
                return "revoked", revoked.revocation_date.isoformat(), reason

        return "good", None, None

    return "unknown", None, None


def check_ocsp(
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
        ocsp_url: Optional[str],
        logger: logging.Logger,
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Проверяет статус сертификата через OCSP.
    Возвращает (status, revocation_date, revocation_reason)
    """
    # Определяем URL OCSP responder
    if not ocsp_url:
        ocsp_url = extract_ocsp_url(cert)
        if not ocsp_url:
            return "unknown", None, None

    try:
        # Строим OCSP запрос
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
        ocsp_req = builder.build()

        # Отправляем запрос
        headers = {"Content-Type": "application/ocsp-request"}
        resp = requests.post(ocsp_url, data=ocsp_req.public_bytes(), headers=headers, timeout=10)
        resp.raise_for_status()

        # Парсим ответ
        ocsp_resp = load_der_ocsp_response(resp.content)

        if ocsp_resp.response_status.value == 0:  # successful
            for single_resp in ocsp_resp.responses:
                status_map = {
                    0: "good",  # certificate is not revoked
                    1: "revoked",  # certificate is revoked
                    2: "unknown",  # responder doesn't know
                }
                status = status_map.get(single_resp.certificate_status.value, "unknown")

                if status == "revoked":
                    rev_time = single_resp.revocation_time.isoformat() if single_resp.revocation_time else None
                    rev_reason = single_resp.revocation_reason.value if single_resp.revocation_reason else "unspecified"
                    return "revoked", rev_time, rev_reason
                elif status == "good":
                    return "good", None, None
                else:
                    return "unknown", None, None
        else:
            logger.warning(f"OCSP response status error: {ocsp_resp.response_status.value}")
            return "unknown", None, None

    except Exception as e:
        logger.warning(f"OCSP check failed: {e}")
        return "unknown", None, None


def check_revocation_status(
        cert_path: str,
        ca_cert_path: str,
        crl_source: Optional[str],
        ocsp_url: Optional[str],
        logger: logging.Logger,
        prefer_ocsp: bool = True,
) -> Tuple[str, Optional[str], Optional[str], str]:
    """
    Проверяет статус отзыва сертификата с fallback логикой.
    Возвращает (status, revocation_date, revocation_reason, method_used)
    """
    # Загружаем сертификаты
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_cert_path, "rb") as f:
        issuer_cert = x509.load_pem_x509_certificate(f.read())

    if prefer_ocsp:
        # Сначала пробуем OCSP
        status, rev_date, rev_reason = check_ocsp(cert, issuer_cert, ocsp_url, logger)
        if status != "unknown":
            return status, rev_date, rev_reason, "OCSP"

        # Fallback на CRL
        logger.info("OCSP returned unknown/failed, falling back to CRL")
        status, rev_date, rev_reason = check_crl(cert, issuer_cert, crl_source, logger)
        return status, rev_date, rev_reason, "CRL (fallback)"
    else:
        # Сначала CRL, потом OCSP
        status, rev_date, rev_reason = check_crl(cert, issuer_cert, crl_source, logger)
        if status != "unknown":
            return status, rev_date, rev_reason, "CRL"

        logger.info("CRL returned unknown/failed, falling back to OCSP")
        status, rev_date, rev_reason = check_ocsp(cert, issuer_cert, ocsp_url, logger)
        return status, rev_date, rev_reason, "OCSP (fallback)"