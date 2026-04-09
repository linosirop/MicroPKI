from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from micropki.certificates import choose_hash_for_signing
from micropki.crypto_utils import load_certificate_from_file, load_private_key_from_file, read_passphrase_file
from micropki.database import get_connection, list_revoked_certificates


REASON_ENUM_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "removeFromCRL": x509.ReasonFlags.remove_from_crl,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aACompromise": x509.ReasonFlags.aa_compromise,
}


def ensure_crl_directory(out_dir: str) -> Path:
    crl_dir = Path(out_dir) / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)
    return crl_dir


def _metadata_table_sql() -> str:
    return """
    CREATE TABLE IF NOT EXISTS crl_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ca_subject TEXT NOT NULL,
        crl_number INTEGER NOT NULL,
        last_generated TEXT NOT NULL,
        next_update TEXT NOT NULL,
        crl_path TEXT NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_ca_subject
    ON crl_metadata(ca_subject);
    """


def ensure_crl_metadata_table(db_path: str) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(_metadata_table_sql())
        conn.commit()


def get_next_crl_number(db_path: str, ca_subject: str) -> int:
    ensure_crl_metadata_table(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,),
        ).fetchone()
        if row is None:
            return 1
        return int(row["crl_number"]) + 1


def save_crl_metadata(
    db_path: str,
    ca_subject: str,
    crl_number: int,
    last_generated: str,
    next_update: str,
    crl_path: str,
) -> None:
    ensure_crl_metadata_table(db_path)
    with get_connection(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,),
        ).fetchone()

        if existing is None:
            conn.execute(
                """
                INSERT INTO crl_metadata (
                    ca_subject, crl_number, last_generated, next_update, crl_path
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (ca_subject, crl_number, last_generated, next_update, crl_path),
            )
        else:
            conn.execute(
                """
                UPDATE crl_metadata
                SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
                WHERE ca_subject = ?
                """,
                (crl_number, last_generated, next_update, crl_path, ca_subject),
            )
        conn.commit()


def determine_ca_material(ca: str, out_dir: str):
    out_path = Path(out_dir)

    if ca == "root":
        return {
            "cert_path": str(out_path / "certs" / "ca.cert.pem"),
            "key_path": str(out_path / "private" / "ca.key.pem"),
            "default_crl_name": "root.crl.pem",
        }

    if ca == "intermediate":
        return {
            "cert_path": str(out_path / "certs" / "intermediate.cert.pem"),
            "key_path": str(out_path / "private" / "intermediate.key.pem"),
            "default_crl_name": "intermediate.crl.pem",
        }

    raise ValueError("--ca must be either 'root' or 'intermediate'")


def _parse_iso_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def build_crl_for_ca(
    db_path: str,
    out_dir: str,
    ca: str,
    passphrase_file: str,
    next_update_days: int,
    logger,
    out_file: str | None = None,
):
    ca_info = determine_ca_material(ca, out_dir)
    ca_cert = load_certificate_from_file(ca_info["cert_path"])
    ca_key = load_private_key_from_file(ca_info["key_path"], read_passphrase_file(passphrase_file))

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=next_update_days)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    try:
        aki = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    except x509.ExtensionNotFound:
        pass

    crl_number = get_next_crl_number(db_path, ca_cert.subject.rfc4514_string())
    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False,
    )

    revoked_rows = list_revoked_certificates(db_path)
    relevant_revoked = [r for r in revoked_rows if r["issuer"] == ca_cert.subject.rfc4514_string()]

    for row in relevant_revoked:
        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(row["serial_hex"], 16))
            .revocation_date(_parse_iso_utc(row["revocation_date"]))
        )

        reason = row["revocation_reason"]
        if reason:
            revoked_builder = revoked_builder.add_extension(
                x509.CRLReason(REASON_ENUM_MAP[reason]),
                critical=False,
            )

        builder = builder.add_revoked_certificate(revoked_builder.build())

    crl = builder.sign(private_key=ca_key, algorithm=choose_hash_for_signing(ca_key))
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    crl_dir = ensure_crl_directory(out_dir)
    output_path = Path(out_file) if out_file else (crl_dir / ca_info["default_crl_name"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(crl_pem)

    save_crl_metadata(
        db_path=db_path,
        ca_subject=ca_cert.subject.rfc4514_string(),
        crl_number=crl_number,
        last_generated=now.isoformat(),
        next_update=next_update.isoformat(),
        crl_path=str(output_path),
    )

    logger.info(
        f"CRL generation completed successfully: ca={ca}, revoked_count={len(relevant_revoked)}, "
        f"thisUpdate={now.isoformat()}, nextUpdate={next_update.isoformat()}, crl_number={crl_number}"
    )

    return {
        "crl": crl,
        "crl_pem": crl_pem,
        "output_path": str(output_path),
        "revoked_count": len(relevant_revoked),
        "crl_number": crl_number,
    }