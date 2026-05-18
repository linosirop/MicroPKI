from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, List
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID

# Максимальные сроки действия (в днях)
MAX_VALIDITY = {
    "root": 3650,  # 10 лет
    "intermediate": 1825,  # 5 лет
    "end_entity": 365,  # 1 год
}

# Минимальные размеры ключей
MIN_KEY_SIZE = {
    "rsa": {
        "root": 4096,
        "intermediate": 3072,
        "end_entity": 2048,
    },
    "ecc": {
        "root": 384,  # P-384
        "intermediate": 384,
        "end_entity": 256,  # P-256
    }
}

# Разрешённые типы SAN по шаблонам
ALLOWED_SAN_TYPES = {
    "server": {"dns", "ip"},
    "client": {"dns", "email"},
    "code_signing": {"dns", "uri"},
}

# Запрещённые wildcard домены (по умолчанию запрещены)
ALLOW_WILDCARDS = False  # Можно будет сделать конфигурируемым


class PolicyViolation(Exception):
    """Исключение при нарушении политики"""
    pass


def check_key_size(key_type: str, key_size: int, cert_type: str) -> None:
    """
    Проверяет размер ключа в соответствии с типом сертификата
    cert_type: 'root', 'intermediate', 'end_entity'
    """
    if key_type not in MIN_KEY_SIZE:
        raise PolicyViolation(f"Unsupported key type: {key_type}")

    min_size = MIN_KEY_SIZE[key_type].get(cert_type)
    if min_size is None:
        raise PolicyViolation(f"Invalid certificate type: {cert_type}")

    if key_size < min_size:
        raise PolicyViolation(
            f"Key size {key_size} is too small for {cert_type} certificate. "
            f"Minimum required: {min_size} bits"
        )


def check_validity_period(validity_days: int, cert_type: str) -> None:
    """
    Проверяет период действия сертификата
    """
    max_days = MAX_VALIDITY.get(cert_type)
    if max_days is None:
        raise PolicyViolation(f"Invalid certificate type: {cert_type}")

    if validity_days > max_days:
        raise PolicyViolation(
            f"Validity period {validity_days} days exceeds maximum "
            f"of {max_days} days for {cert_type} certificate"
        )


def check_signature_algorithm(cert_or_csr, cert_type: str = "end_entity") -> None:
    """
    Проверяет алгоритм подписи
    """
    try:
        # Для CSR
        if hasattr(cert_or_csr, 'signature_hash_algorithm'):
            algo = cert_or_csr.signature_hash_algorithm
            algo_name = algo.name if algo else "unknown"

            # Запрещаем SHA-1
            if algo_name == "SHA1":
                raise PolicyViolation("SHA-1 signature algorithm is forbidden")

            # Проверяем минимальную стойкость
            if algo_name not in ["SHA256", "SHA384", "SHA512"]:
                raise PolicyViolation(f"Weak signature algorithm: {algo_name}")
    except Exception as e:
        raise PolicyViolation(f"Signature algorithm check failed: {e}")


def check_public_key_from_private(key) -> None:
    """
    Проверяет публичный ключ (из приватного)
    """
    if isinstance(key, rsa.RSAPrivateKey):
        key_size = key.key_size
        if key_size < 2048:
            raise PolicyViolation(f"RSA key size {key_size} is too small (min 2048)")

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        curve_size = key.curve.key_size
        if curve_size < 256:
            raise PolicyViolation(f"ECC key size {curve_size} is too small (min 256)")


def check_san_types(san_objects: List, template: str) -> None:
    """
    Проверяет типы SAN в соответствии с шаблоном
    """
    allowed_types = ALLOWED_SAN_TYPES.get(template)
    if not allowed_types:
        raise PolicyViolation(f"Unknown template: {template}")

    for san in san_objects:
        san_type = None
        san_value = None

        if isinstance(san, x509.DNSName):
            san_type = "dns"
            san_value = san.value

            # Проверка wildcard
            if not ALLOW_WILDCARDS and san_value.startswith("*."):
                raise PolicyViolation(
                    f"Wildcard DNS name '{san_value}' is not allowed for {template} certificates"
                )

        elif isinstance(san, x509.IPAddress):
            san_type = "ip"

        elif isinstance(san, x509.RFC822Name):
            san_type = "email"

        elif isinstance(san, x509.UniformResourceIdentifier):
            san_type = "uri"

        if san_type not in allowed_types:
            raise PolicyViolation(
                f"SAN type '{san_type}' is not allowed for {template} certificates. "
                f"Allowed types: {allowed_types}"
            )


def check_basic_constraints(cert_type: str, pathlen: Optional[int] = None) -> None:
    """
    Проверяет Basic Constraints
    """
    if cert_type == "intermediate":
        # Для Intermediate CA pathlen должен быть 0
        if pathlen is not None and pathlen > 0:
            raise PolicyViolation(
                f"Intermediate CA cannot issue subordinate CAs (pathLenConstraint must be 0)"
            )

    elif cert_type == "end_entity":
        # End-entity не может быть CA
        pass  # Проверяется в validation.py


def validate_csr_policy(csr: x509.CertificateSigningRequest, template: str) -> None:
    """
    Проверяет CSR на соответствие политикам
    """
    # Проверяем подпись CSR
    if not csr.is_signature_valid:
        raise PolicyViolation("CSR signature is invalid")

    # Проверяем алгоритм подписи
    check_signature_algorithm(csr, "end_entity")

    # Проверяем публичный ключ
    public_key = csr.public_key()

    # Определяем тип и размер ключа
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        key_type = "rsa"
        check_key_size(key_type, key_size, "end_entity")

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.curve.key_size
        key_type = "ecc"
        check_key_size(key_type, key_size, "end_entity")
    else:
        raise PolicyViolation(f"Unsupported key type: {type(public_key)}")

    # Проверяем SAN расширения
    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_objects = list(san_ext.value)
        check_san_types(san_objects, template)
    except x509.ExtensionNotFound:
        # SAN отсутствует - разрешено
        pass

    # Проверяем Basic Constraints (не должно быть CA)
    try:
        bc_ext = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if bc_ext.value.ca:
            raise PolicyViolation("CSR requests CA certificate which is not allowed for end-entity")
    except x509.ExtensionNotFound:
        pass


def validate_issuance_request(cert_type: str, key_type: str, key_size: int,
                              validity_days: int, template: Optional[str] = None,
                              san_objects: Optional[List] = None) -> None:
    """
    Проверяет запрос на выпуск сертификата
    """
    # Проверяем размер ключа
    check_key_size(key_type, key_size, cert_type)

    # Проверяем период действия
    check_validity_period(validity_days, cert_type)

    # Проверяем SAN типы (для end-entity)
    if cert_type == "end_entity" and template and san_objects:
        check_san_types(san_objects, template)