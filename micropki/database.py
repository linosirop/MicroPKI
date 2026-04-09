from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_serial_hex
ON certificates(serial_hex);

CREATE INDEX IF NOT EXISTS idx_certificates_status
ON certificates(status);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: str) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()


def insert_certificate_record(
    db_path: str,
    serial_hex: str,
    subject: str,
    issuer: str,
    not_before: str,
    not_after: str,
    cert_pem: str,
    status: str = "valid",
    revocation_reason: str | None = None,
    revocation_date: str | None = None,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO certificates (
                serial_hex, subject, issuer, not_before, not_after,
                cert_pem, status, revocation_reason, revocation_date, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                serial_hex.upper(),
                subject,
                issuer,
                not_before,
                not_after,
                cert_pem,
                status,
                revocation_reason,
                revocation_date,
                created_at,
            ),
        )
        conn.commit()


def get_certificate_by_serial(db_path: str, serial_hex: str):
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE UPPER(serial_hex) = UPPER(?)",
            (serial_hex,),
        ).fetchone()
        return row


def list_certificates(
    db_path: str,
    status: str | None = None,
    issuer: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    query = "SELECT * FROM certificates WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if issuer:
        query += " AND issuer = ?"
        params.append(issuer)

    if date_from:
        query += " AND not_before >= ?"
        params.append(date_from)

    if date_to:
        query += " AND not_after <= ?"
        params.append(date_to)

    query += " ORDER BY created_at ASC"

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return rows


def update_certificate_status(
    db_path: str,
    serial_hex: str,
    status: str,
    revocation_reason: str | None = None,
    revocation_date: str | None = None,
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE certificates
            SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE UPPER(serial_hex) = UPPER(?)
            """,
            (status, revocation_reason, revocation_date, serial_hex),
        )
        conn.commit()


def list_revoked_certificates(db_path: str):
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM certificates WHERE status = 'revoked' ORDER BY created_at ASC"
        ).fetchall()
        return rows