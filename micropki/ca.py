from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from micropki.crypto_utils import (
    read_passphrase_file,
    generate_private_key,
    serialize_encrypted_private_key,
    save_private_key,
    save_certificate,
)
from micropki.certificates import build_self_signed_root_ca, serialize_certificate


def ensure_output_directory(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "private").mkdir(parents=True, exist_ok=True)
    (out_dir / "certs").mkdir(parents=True, exist_ok=True)

    try:
        (out_dir / "private").chmod(0o700)
    except Exception:
        pass


def write_policy_file(
    out_dir: Path,
    subject_dn: str,
    cert,
    key_type: str,
    key_size: int,
) -> None:
    policy_path = out_dir / "policy.txt"
    content = f"""MicroPKI Root CA Policy
Policy Version: 1.0
Creation Date: {datetime.now(timezone.utc).isoformat()}

CA Name: {subject_dn}
Certificate Serial Number: {cert.serial_number:x}
Validity NotBefore: {cert.not_valid_before_utc.isoformat()}
Validity NotAfter: {cert.not_valid_after_utc.isoformat()}
Key Algorithm and Size: {key_type.upper()}-{key_size}
Purpose: Root CA for MicroPKI demonstration
"""
    policy_path.write_text(content, encoding="utf-8")


def init_root_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase_file: str,
    out_dir: str,
    validity_days: int,
    logger,
) -> None:
    out_path = Path(out_dir)
    ensure_output_directory(out_path)

    key_path = out_path / "private" / "ca.key.pem"
    cert_path = out_path / "certs" / "ca.cert.pem"

    if key_path.exists() or cert_path.exists():
        raise FileExistsError(
            "Output files already exist. Refusing to overwrite existing CA material."
        )

    passphrase = read_passphrase_file(passphrase_file)

    logger.info("Starting key generation")
    private_key = generate_private_key(key_type, key_size)
    logger.info("Key generation completed successfully")

    logger.info("Starting self-signed certificate generation")
    cert = build_self_signed_root_ca(private_key, subject, validity_days)
    logger.info("Certificate signing completed successfully")

    encrypted_key = serialize_encrypted_private_key(private_key, passphrase)
    cert_pem = serialize_certificate(cert)

    save_private_key(key_path, encrypted_key)
    logger.info(f"Saved private key to {key_path.resolve()}")

    save_certificate(cert_path, cert_pem)
    logger.info(f"Saved certificate to {cert_path.resolve()}")

    write_policy_file(out_path, subject, cert, key_type, key_size)
    logger.info(f"Generated policy file at {(out_path / 'policy.txt').resolve()}")