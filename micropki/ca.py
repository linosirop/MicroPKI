from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from micropki.crypto_utils import (
    read_passphrase_file,
    generate_private_key,
    serialize_encrypted_private_key,
    serialize_unencrypted_private_key,
    save_private_key,
    save_certificate,
    save_csr,
    load_private_key_from_file,
    load_certificate_from_file,
)
from micropki.certificates import (
    build_self_signed_root_ca,
    build_intermediate_certificate,
    build_end_entity_certificate,
    serialize_certificate,
    certificate_common_name,
)
from micropki.csr import build_intermediate_csr, serialize_csr
from micropki.templates import parse_san_entries, validate_template_and_sans, apply_end_entity_template
from micropki.database import (
    insert_certificate_record,
    get_certificate_by_serial,
    list_certificates,
)


def ensure_output_directory(out_dir: Path, logger) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for subdir in ("private", "certs", "csrs"):
        path = out_dir / subdir
        path.mkdir(parents=True, exist_ok=True)
        if subdir == "private":
            try:
                path.chmod(0o700)
            except Exception:
                logger.warning("Could not enforce 0o700 permissions on private directory on this OS.")


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


def append_intermediate_policy(
    out_dir: Path,
    subject_dn: str,
    cert,
    key_type: str,
    key_size: int,
    pathlen: int,
    issuer_dn: str,
) -> None:
    policy_path = out_dir / "policy.txt"
    content = f"""

Intermediate CA Section
Creation Date: {datetime.now(timezone.utc).isoformat()}
Subject DN: {subject_dn}
Serial Number: {cert.serial_number:x}
Validity NotBefore: {cert.not_valid_before_utc.isoformat()}
Validity NotAfter: {cert.not_valid_after_utc.isoformat()}
Key Algorithm and Size: {key_type.upper()}-{key_size}
Path Length Constraint: {pathlen}
Issuer DN: {issuer_dn}
"""
    with policy_path.open("a", encoding="utf-8") as f:
        f.write(content)


def _store_certificate_in_db(cert, cert_pem: str, db_path: str, logger, subject_override: str | None = None) -> None:
    serial_hex = f"{cert.serial_number:x}".upper()
    subject = subject_override or cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    insert_certificate_record(
        db_path=db_path,
        serial_hex=serial_hex,
        subject=subject,
        issuer=issuer,
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        cert_pem=cert_pem,
        status="valid",
    )
    logger.info(f"Inserted certificate into DB: serial={serial_hex}, subject={subject}")


def init_root_ca(subject, key_type, key_size, passphrase_file, out_dir, validity_days, logger, db_path: str | None = None) -> None:
    out_path = Path(out_dir)
    ensure_output_directory(out_path, logger)

    key_path = out_path / "private" / "ca.key.pem"
    cert_path = out_path / "certs" / "ca.cert.pem"

    if key_path.exists() or cert_path.exists():
        raise FileExistsError("Output files already exist. Refusing to overwrite existing CA material.")

    passphrase = read_passphrase_file(passphrase_file)

    logger.info("Starting key generation")
    private_key = generate_private_key(key_type, key_size)
    logger.info("Key generation completed successfully")

    logger.info("Starting self-signed certificate generation")
    cert = build_self_signed_root_ca(private_key, subject, validity_days)
    logger.info("Certificate signing completed successfully")

    cert_pem = serialize_certificate(cert).decode("utf-8")

    permissions_ok = save_private_key(key_path, serialize_encrypted_private_key(private_key, passphrase))
    logger.info(f"Saved private key to {key_path.resolve()}")
    if not permissions_ok:
        logger.warning("Could not enforce 0o600 permissions on private key file on this OS.")

    save_certificate(cert_path, cert_pem.encode("utf-8"))
    logger.info(f"Saved certificate to {cert_path.resolve()}")

    if db_path:
        _store_certificate_in_db(cert, cert_pem, db_path, logger, subject)

    write_policy_file(out_path, subject, cert, key_type, key_size)
    logger.info(f"Generated policy file at {(out_path / 'policy.txt').resolve()}")


def issue_intermediate_ca(
    root_cert_path: str,
    root_key_path: str,
    root_pass_file: str,
    subject: str,
    key_type: str,
    key_size: int,
    passphrase_file: str,
    out_dir: str,
    validity_days: int,
    pathlen: int,
    logger,
    db_path: str | None = None,
) -> None:
    out_path = Path(out_dir)
    ensure_output_directory(out_path, logger)

    intermediate_key_path = out_path / "private" / "intermediate.key.pem"
    intermediate_cert_path = out_path / "certs" / "intermediate.cert.pem"
    intermediate_csr_path = out_path / "csrs" / "intermediate.csr.pem"

    if intermediate_key_path.exists() or intermediate_cert_path.exists():
        raise FileExistsError("Intermediate CA files already exist. Refusing to overwrite.")

    root_cert = load_certificate_from_file(root_cert_path)
    root_passphrase = read_passphrase_file(root_pass_file)
    root_key = load_private_key_from_file(root_key_path, root_passphrase)

    intermediate_passphrase = read_passphrase_file(passphrase_file)

    logger.info("Starting intermediate key generation")
    intermediate_key = generate_private_key(key_type, key_size)
    logger.info("Intermediate key generation completed successfully")

    logger.info("Generation of Intermediate CA CSR")
    csr = build_intermediate_csr(intermediate_key, subject, pathlen)
    save_csr(intermediate_csr_path, serialize_csr(csr))
    logger.info(f"Saved CSR to {intermediate_csr_path.resolve()}")

    logger.info("Signing Intermediate CA certificate by Root CA")
    intermediate_cert = build_intermediate_certificate(
        root_cert=root_cert,
        root_key=root_key,
        csr=csr,
        validity_days=validity_days,
        pathlen=pathlen,
    )

    intermediate_pem = serialize_certificate(intermediate_cert).decode("utf-8")

    if db_path:
        _store_certificate_in_db(intermediate_cert, intermediate_pem, db_path, logger, subject)

    permissions_ok = save_private_key(
        intermediate_key_path,
        serialize_encrypted_private_key(intermediate_key, intermediate_passphrase),
    )
    logger.info(f"Saved private key to {intermediate_key_path.resolve()}")
    if not permissions_ok:
        logger.warning("Could not enforce 0o600 permissions on private key file on this OS.")

    save_certificate(intermediate_cert_path, intermediate_pem.encode("utf-8"))
    logger.info(f"Saved certificate to {intermediate_cert_path.resolve()}")

    append_intermediate_policy(
        out_path,
        subject,
        intermediate_cert,
        key_type,
        key_size,
        pathlen,
        root_cert.subject.rfc4514_string(),
    )
    logger.info(f"Updated policy file at {(out_path / 'policy.txt').resolve()}")


def issue_end_entity_certificate(
    ca_cert_path: str,
    ca_key_path: str,
    ca_pass_file: str,
    template: str,
    subject: str,
    san_entries: list[str] | None,
    out_dir: str,
    validity_days: int,
    logger,
    db_path: str | None = None,
) -> None:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ca_cert = load_certificate_from_file(ca_cert_path)
    ca_passphrase = read_passphrase_file(ca_pass_file)
    ca_key = load_private_key_from_file(ca_key_path, ca_passphrase)

    san_objects = parse_san_entries(san_entries)
    validate_template_and_sans(template, san_objects)

    leaf_key_type = "rsa"
    leaf_key_size = 2048
    leaf_key = generate_private_key(leaf_key_type, leaf_key_size)

    def template_builder(builder):
        return apply_end_entity_template(builder, template, leaf_key, san_objects)

    cert = build_end_entity_certificate(
        issuer_cert=ca_cert,
        issuer_key=ca_key,
        subject_dn=subject,
        subject_public_key=leaf_key.public_key(),
        validity_days=validity_days,
        template_builder=template_builder,
    )

    cert_pem = serialize_certificate(cert).decode("utf-8")

    if db_path:
        _store_certificate_in_db(cert, cert_pem, db_path, logger, subject)

    common_name = certificate_common_name(cert).replace(" ", "_")
    cert_path = out_path / f"{common_name}.cert.pem"
    key_path = out_path / f"{common_name}.key.pem"

    permissions_ok = save_private_key(key_path, serialize_unencrypted_private_key(leaf_key))
    logger.warning("End-entity private key is stored unencrypted.")
    if not permissions_ok:
        logger.warning("Could not enforce 0o600 permissions on end-entity private key file on this OS.")

    save_certificate(cert_path, cert_pem.encode("utf-8"))

    logger.info(
        f"Successful issuance of end-entity certificate: template={template}, "
        f"subject={subject}, sans={san_entries or []}, serial={cert.serial_number:x}"
    )
    logger.info(f"Saved end-entity key to {key_path.resolve()}")
    logger.info(f"Saved end-entity certificate to {cert_path.resolve()}")


def show_certificate_from_db(db_path: str, serial_hex: str, logger) -> str:
    row = get_certificate_by_serial(db_path, serial_hex)
    if row is None:
        raise ValueError(f"Certificate with serial {serial_hex} not found")

    logger.info(f"Retrieved certificate via show-cert: serial={serial_hex}")
    return row["cert_pem"]


def list_certificates_from_db(
    db_path: str,
    logger,
    status: str | None = None,
    output_format: str = "table",
) -> str:
    rows = list_certificates(db_path, status=status)

    if output_format == "json":
        return json.dumps([dict(row) for row in rows], indent=2, ensure_ascii=False)

    if output_format == "csv":
        lines = ["serial_hex,subject,not_after,status"]
        for row in rows:
            lines.append(f'{row["serial_hex"]},"{row["subject"]}",{row["not_after"]},{row["status"]}')
        return "\n".join(lines)

    headers = ("SERIAL", "SUBJECT", "EXPIRES", "STATUS")
    data_rows = [(r["serial_hex"], r["subject"], r["not_after"], r["status"]) for r in rows]

    widths = [len(h) for h in headers]
    for row in data_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(values):
        return " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(values))

    lines = [fmt_row(headers), "-+-".join("-" * w for w in widths)]
    lines.extend(fmt_row(r) for r in data_rows)

    logger.info(f"Listed certificates from DB: count={len(data_rows)}, status_filter={status}")
    return "\n".join(lines)