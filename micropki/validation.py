from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID


@dataclass
class ValidationStep:
    name: str
    passed: bool
    message: str
    certificate_subject: str = ""


@dataclass
class ValidationResult:
    overall_passed: bool
    steps: List[ValidationStep] = field(default_factory=list)
    chain: List[x509.Certificate] = field(default_factory=list)
    error_message: str = ""


def verify_signature(child_cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Проверяет подпись сертификата с помощью открытого ключа издателя"""
    issuer_public_key = issuer_cert.public_key()

    try:
        if hasattr(issuer_public_key, "verify"):
            # Для RSA
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child_cert.signature_hash_algorithm,
            )
        else:
            # Для ECC
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                ec.ECDSA(child_cert.signature_hash_algorithm),
            )
        return True
    except Exception:
        return False


def check_validity_period(cert: x509.Certificate, validation_time: datetime) -> Tuple[bool, str]:
    """Проверяет период действия сертификата"""
    if validation_time < cert.not_valid_before_utc:
        return False, f"Certificate not yet valid (valid from {cert.not_valid_before_utc})"
    if validation_time > cert.not_valid_after_utc:
        return False, f"Certificate expired (expired at {cert.not_valid_after_utc})"
    return True, "Certificate is within validity period"


def check_basic_constraints(cert: x509.Certificate, is_ca_expected: bool) -> Tuple[bool, str]:
    """Проверяет Basic Constraints"""
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if is_ca_expected and not bc.ca:
            return False, "Certificate expected to be a CA but BasicConstraints.ca=False"
        if not is_ca_expected and bc.ca:
            return False, "Certificate expected to be an end-entity but BasicConstraints.ca=True"
        return True, "BasicConstraints check passed"
    except x509.ExtensionNotFound:
        if is_ca_expected:
            return False, "CA certificate missing BasicConstraints extension"
        return True, "No BasicConstraints (OK for end-entity)"


def check_path_length(cert: x509.Certificate, remaining_path_length: int) -> Tuple[bool, int, str]:
    """Проверяет ограничение длины пути"""
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if bc.path_length is not None:
            if remaining_path_length > bc.path_length:
                return False, remaining_path_length, f"Path length constraint exceeded: {remaining_path_length} > {bc.path_length}"
            return True, bc.path_length, f"Path length constraint OK (max={bc.path_length})"
        return True, remaining_path_length, "No path length constraint"
    except x509.ExtensionNotFound:
        return True, remaining_path_length, "No BasicConstraints extension"


def check_key_usage(cert: x509.Certificate, required_usage: str = "key_cert_sign") -> Tuple[bool, str]:
    """Проверяет Key Usage"""
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if required_usage == "key_cert_sign" and not ku.key_cert_sign:
            return False, "CA certificate missing keyCertSign in KeyUsage"
        return True, f"KeyUsage check passed (has {required_usage})"
    except x509.ExtensionNotFound:
        if required_usage == "key_cert_sign":
            return False, "CA certificate missing KeyUsage extension"
        return True, "No KeyUsage extension (OK for end-entity)"


def check_extended_key_usage(cert: x509.Certificate, expected_purpose: Optional[str] = None) -> Tuple[bool, str]:
    """Проверяет Extended Key Usage для end-entity сертификата"""
    if expected_purpose is None:
        return True, "No EKU check required"

    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value

        purpose_map = {
            "server": ExtendedKeyUsageOID.SERVER_AUTH,
            "client": ExtendedKeyUsageOID.CLIENT_AUTH,
            "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        }

        if expected_purpose in purpose_map:
            if purpose_map[expected_purpose] not in eku:
                return False, f"Certificate missing expected EKU: {expected_purpose}"

        return True, f"EKU check passed (contains {expected_purpose})"
    except x509.ExtensionNotFound:
        return False, "Certificate missing ExtendedKeyUsage extension"


def build_certificate_chain(
        leaf_cert: x509.Certificate,
        untrusted: List[x509.Certificate],
        trusted: List[x509.Certificate],
        logger: logging.Logger,
) -> Tuple[List[x509.Certificate], str]:
    """
    Строит цепочку сертификатов от leaf до trusted root.
    Возвращает (chain, error_message)
    """
    chain = [leaf_cert]
    current = leaf_cert

    # Максимальная глубина для предотвращения циклов
    max_depth = 10

    for _ in range(max_depth):
        # Ищем издателя текущего сертификата
        issuer_found = False

        # Сначала проверяем trusted roots
        for root in trusted:
            if current.issuer == root.subject:
                try:
                    if verify_signature(current, root):
                        chain.append(root)
                        return chain, ""
                except Exception:
                    pass

        # Затем проверяем untrusted intermediates
        for cert in untrusted:
            if current.issuer == cert.subject:
                try:
                    if verify_signature(current, cert):
                        chain.append(cert)
                        current = cert
                        issuer_found = True
                        break
                except Exception:
                    pass

        if not issuer_found:
            break

    return [], f"Cannot build chain: no issuer found for {current.subject}"


def validate_certificate_chain(
        leaf_cert_path: str,
        untrusted_paths: List[str],
        trusted_paths: List[str],
        validation_time: datetime,
        logger: logging.Logger,
        expected_eku: Optional[str] = None,
) -> ValidationResult:
    """
    Основная функция валидации цепочки сертификатов
    """
    result = ValidationResult(overall_passed=False)

    # Загрузка сертификатов
    try:
        with open(leaf_cert_path, "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        result.error_message = f"Failed to load leaf certificate: {e}"
        return result

    untrusted_certs = []
    for path in untrusted_paths:
        try:
            with open(path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                untrusted_certs.append(cert)
        except Exception as e:
            logger.warning(f"Failed to load untrusted cert from {path}: {e}")

    trusted_certs = []
    for path in trusted_paths:
        try:
            with open(path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                trusted_certs.append(cert)
        except Exception as e:
            logger.warning(f"Failed to load trusted cert from {path}: {e}")

    # Построение цепочки
    chain, error = build_certificate_chain(leaf_cert, untrusted_certs, trusted_certs, logger)
    if not chain:
        result.error_message = error
        return result

    result.chain = chain
    logger.info(f"Built chain with {len(chain)} certificates")

    # Валидация каждого сертификата в цепочке (кроме корневого)
    remaining_path_len = 999  # Большое значение, если нет ограничения

    for idx, cert in enumerate(chain[:-1]):  # Все, кроме корневого
        issuer = chain[idx + 1]
        is_ca = (idx < len(chain) - 2)  # Последний перед корнем - intermediate

        # Шаг 1: Проверка подписи
        step = ValidationStep(name="Signature", passed=False, message="", certificate_subject=str(cert.subject))
        if verify_signature(cert, issuer):
            step.passed = True
            step.message = "Signature verified successfully"
        else:
            step.message = "Signature verification failed"
            result.steps.append(step)
            result.error_message = step.message
            return result
        result.steps.append(step)

        # Шаг 2: Проверка периода действия
        step = ValidationStep(name="Validity Period", passed=False, message="", certificate_subject=str(cert.subject))
        passed, msg = check_validity_period(cert, validation_time)
        step.passed = passed
        step.message = msg
        if not passed:
            result.steps.append(step)
            result.error_message = msg
            return result
        result.steps.append(step)

        # Шаг 3: Проверка Basic Constraints
        step = ValidationStep(name="Basic Constraints", passed=False, message="", certificate_subject=str(cert.subject))
        passed, msg = check_basic_constraints(cert, is_ca)
        step.passed = passed
        step.message = msg
        if not passed:
            result.steps.append(step)
            result.error_message = msg
            return result
        result.steps.append(step)

        # Шаг 4: Проверка Path Length
        step = ValidationStep(name="Path Length", passed=False, message="", certificate_subject=str(cert.subject))
        passed, remaining_path_len, msg = check_path_length(cert, remaining_path_len)
        step.passed = passed
        step.message = msg
        if not passed:
            result.steps.append(step)
            result.error_message = msg
            return result
        result.steps.append(step)

        # Шаг 5: Проверка Key Usage для CA
        if is_ca:
            step = ValidationStep(name="Key Usage (CA)", passed=False, message="",
                                  certificate_subject=str(cert.subject))
            passed, msg = check_key_usage(cert, "key_cert_sign")
            step.passed = passed
            step.message = msg
            if not passed:
                result.steps.append(step)
                result.error_message = msg
                return result
            result.steps.append(step)

    # Шаг 6: Проверка EKU для leaf (end-entity)
    step = ValidationStep(name="Extended Key Usage", passed=False, message="",
                          certificate_subject=str(leaf_cert.subject))
    passed, msg = check_extended_key_usage(leaf_cert, expected_eku)
    step.passed = passed
    step.message = msg
    if not passed and expected_eku:
        result.steps.append(step)
        result.error_message = msg
        return result
    result.steps.append(step)

    result.overall_passed = True
    result.error_message = ""
    return result