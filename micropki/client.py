from __future__ import annotations

import os
import requests
import json
from pathlib import Path
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import generate_private_key, save_private_key, serialize_unencrypted_private_key
from micropki.certificates import parse_subject_dn
from micropki.templates import parse_san_entries, apply_end_entity_template
from micropki.validation import validate_certificate_chain, ValidationResult
from micropki.revocation_check import check_revocation_status


def generate_csr(
        subject: str,
        key_type: str,
        key_size: int,
        san_entries: list[str] | None,
        out_key_path: str,
        out_csr_path: str,
        logger,
) -> None:
    """Генерирует приватный ключ и CSR"""

    # Генерация ключа
    logger.info(f"Generating {key_type}-{key_size} private key")
    private_key = generate_private_key(key_type, key_size)

    # Сохранение ключа (незашифрованный)
    key_pem = serialize_unencrypted_private_key(private_key)
    key_file = Path(out_key_path)
    permissions_ok = save_private_key(key_file, key_pem)
    logger.warning("Private key is stored UNENCRYPTED")
    if not permissions_ok:
        logger.warning("Could not enforce 0o600 permissions on this OS")
    logger.info(f"Private key saved to {key_file.resolve()}")

    # Построение CSR
    subject_name = parse_subject_dn(subject)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject_name)

    # Добавляем SAN если есть
    if san_entries:
        san_objects = parse_san_entries(san_entries)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_objects),
            critical=False,
        )

    # Подписываем CSR
    csr = builder.sign(private_key, hashes.SHA256())

    # Сохраняем CSR
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_file = Path(out_csr_path)
    csr_file.write_bytes(csr_pem)

    logger.info(f"CSR saved to {csr_file.resolve()}")


def request_certificate(
        csr_path: str,
        template: str,
        ca_url: str,
        out_cert_path: str,
        api_key: str | None,
        logger,
) -> None:
    """Отправляет CSR в CA и получает подписанный сертификат"""

    # Загружаем CSR
    csr_data = Path(csr_path).read_bytes()

    # Отправляем запрос
    url = f"{ca_url.rstrip('/')}/request-cert?template={template}"
    headers = {"Content-Type": "application/x-pem-file"}
    if api_key:
        headers["X-API-Key"] = api_key

    logger.info(f"Sending CSR to {url}")

    try:
        resp = requests.post(url, data=csr_data, headers=headers, timeout=30)
        resp.raise_for_status()

        # Сохраняем сертификат
        cert_file = Path(out_cert_path)
        cert_file.write_bytes(resp.content)

        logger.info(f"Certificate saved to {cert_file.resolve()}")
        print(f"✅ Certificate issued successfully: {cert_file.resolve()}")

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to request certificate: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Error: {e.response.status_code} - {e.response.text}")
        raise


def validate_certificate(
        cert_path: str,
        untrusted_paths: list[str],
        trusted_paths: list[str],
        validation_time: str | None,
        expected_eku: str | None,
        output_format: str,
        logger,
) -> None:
    """Валидирует цепочку сертификатов"""

    # Парсим время валидации
    if validation_time:
        try:
            val_time = datetime.fromisoformat(validation_time)
        except ValueError:
            val_time = datetime.now()
    else:
        val_time = datetime.now()

    # Запускаем валидацию
    result = validate_certificate_chain(
        leaf_cert_path=cert_path,
        untrusted_paths=untrusted_paths,
        trusted_paths=trusted_paths,
        validation_time=val_time,
        logger=logger,
        expected_eku=expected_eku,
    )

    # Выводим результат
    if output_format == "json":
        output = {
            "overall_passed": result.overall_passed,
            "error_message": result.error_message,
            "steps": [
                {
                    "name": step.name,
                    "passed": step.passed,
                    "message": step.message,
                    "certificate": step.certificate_subject,
                }
                for step in result.steps
            ],
            "chain_length": len(result.chain),
        }
        print(json.dumps(output, indent=2))
    else:
        print("\n" + "=" * 60)
        print("CERTIFICATE VALIDATION RESULT")
        print("=" * 60)

        if result.overall_passed:
            print("✅ OVERALL STATUS: PASSED")
        else:
            print(f"❌ OVERALL STATUS: FAILED")
            print(f"   Error: {result.error_message}")

        print(f"\nChain length: {len(result.chain)} certificates")
        print("\nValidation steps:")
        for step in result.steps:
            status = "✅" if step.passed else "❌"
            print(f"  {status} {step.name}: {step.message}")

    logger.info(f"Validation completed: passed={result.overall_passed}")


def check_status(
        cert_path: str,
        ca_cert_path: str,
        crl_source: str | None,
        ocsp_url: str | None,
        prefer_ocsp: bool,
        logger,
) -> None:
    """Проверяет статус отзыва сертификата"""

    status, rev_date, rev_reason, method = check_revocation_status(
        cert_path=cert_path,
        ca_cert_path=ca_cert_path,
        crl_source=crl_source,
        ocsp_url=ocsp_url,
        logger=logger,
        prefer_ocsp=prefer_ocsp,
    )

    print("\n" + "=" * 60)
    print("REVOCATION STATUS CHECK")
    print("=" * 60)
    print(f"Method used: {method}")

    if status == "good":
        print("✅ Status: GOOD (not revoked)")
    elif status == "revoked":
        print(f"❌ Status: REVOKED")
        if rev_date:
            print(f"   Revocation date: {rev_date}")
        if rev_reason:
            print(f"   Reason: {rev_reason}")
    else:
        print("⚠️ Status: UNKNOWN (could not determine)")

    logger.info(f"Revocation check completed: status={status}, method={method}")