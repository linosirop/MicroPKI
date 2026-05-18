from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from micropki.database import get_connection, get_certificate_by_serial, update_certificate_status
from micropki.revocation import normalize_revocation_reason
from micropki.crl import build_crl_for_ca


def get_public_key_hash(cert_path: str) -> str:
    """Вычисляет SHA-256 хэш публичного ключа из сертификата"""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    public_key = cert.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return hashlib.sha256(public_key_der).hexdigest()


def init_compromised_keys_table(db_path: str) -> None:
    """Создаёт таблицу compromised_keys если не существует"""
    with get_connection(db_path) as conn:
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS compromised_keys
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         public_key_hash
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         certificate_serial
                         TEXT
                         NOT
                         NULL,
                         compromise_date
                         TEXT
                         NOT
                         NULL,
                         compromise_reason
                         TEXT
                         NOT
                         NULL,
                         FOREIGN
                         KEY
                     (
                         certificate_serial
                     ) REFERENCES certificates
                     (
                         serial_hex
                     )
                         )
                     """)
        conn.commit()


def mark_key_compromised(db_path: str, cert_path: str, reason: str, logger) -> None:
    """
    Отмечает ключ как скомпрометированный
    """
    # Инициализируем таблицу
    init_compromised_keys_table(db_path)

    # Получаем информацию о сертификате
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    serial_hex = f"{cert.serial_number:x}".upper()
    public_key_hash = get_public_key_hash(cert_path)
    compromise_date = datetime.now(timezone.utc).isoformat()
    normalized_reason = normalize_revocation_reason(reason)

    # Добавляем в таблицу
    with get_connection(db_path) as conn:
        try:
            conn.execute("""
                         INSERT INTO compromised_keys (public_key_hash, certificate_serial, compromise_date,
                                                       compromise_reason)
                         VALUES (?, ?, ?, ?)
                         """, (public_key_hash, serial_hex, compromise_date, normalized_reason))
            conn.commit()
            logger.info(f"Marked key as compromised: serial={serial_hex}")
        except Exception as e:
            logger.warning(f"Key already marked as compromised or error: {e}")


def is_key_compromised(db_path: str, public_key_hash: str) -> bool:
    """
    Проверяет, не скомпрометирован ли ключ
    """
    init_compromised_keys_table(db_path)

    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM compromised_keys WHERE public_key_hash = ?",
            (public_key_hash,)
        ).fetchone()
        return row is not None


def check_csr_public_key(db_path: str, csr_path: str) -> bool:
    """
    Проверяет, не скомпрометирован ли публичный ключ из CSR
    """
    from cryptography.hazmat.primitives import serialization

    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    public_key = csr.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hash = hashlib.sha256(public_key_der).hexdigest()

    return is_key_compromised(db_path, public_key_hash)