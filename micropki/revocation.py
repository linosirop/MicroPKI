from __future__ import annotations

from datetime import datetime, timezone

from micropki.database import get_certificate_by_serial, update_certificate_status


SUPPORTED_REVOCATION_REASONS = {
    "unspecified": "unspecified",
    "keycompromise": "keyCompromise",
    "cacompromise": "cACompromise",
    "affiliationchanged": "affiliationChanged",
    "superseded": "superseded",
    "cessationofoperation": "cessationOfOperation",
    "certificatehold": "certificateHold",
    "removefromcrl": "removeFromCRL",
    "privilegewithdrawn": "privilegeWithdrawn",
    "aacompromise": "aACompromise",
}


def normalize_revocation_reason(reason: str) -> str:
    key = reason.strip().lower()
    if key not in SUPPORTED_REVOCATION_REASONS:
        raise ValueError(f"Unsupported revocation reason: {reason}")
    return SUPPORTED_REVOCATION_REASONS[key]


def revoke_certificate(db_path: str, serial_hex: str, reason: str, logger):
    normalized_reason = normalize_revocation_reason(reason)
    row = get_certificate_by_serial(db_path, serial_hex)

    if row is None:
        logger.error(f"Revocation failed: certificate not found for serial={serial_hex}")
        raise ValueError(f"Certificate with serial {serial_hex} not found")

    if row["status"] == "revoked":
        logger.warning(f"Certificate already revoked: serial={serial_hex}")
        return {
            "already_revoked": True,
            "serial_hex": row["serial_hex"],
            "reason": row["revocation_reason"],
            "revocation_date": row["revocation_date"],
            "issuer": row["issuer"],
        }

    revocation_date = datetime.now(timezone.utc).isoformat()

    update_certificate_status(
        db_path=db_path,
        serial_hex=serial_hex,
        status="revoked",
        revocation_reason=normalized_reason,
        revocation_date=revocation_date,
    )

    logger.info(
        f"Certificate revoked successfully: serial={serial_hex}, "
        f"reason={normalized_reason}, revocation_date={revocation_date}"
    )

    refreshed = get_certificate_by_serial(db_path, serial_hex)
    return {
        "already_revoked": False,
        "serial_hex": refreshed["serial_hex"],
        "reason": refreshed["revocation_reason"],
        "revocation_date": refreshed["revocation_date"],
        "issuer": refreshed["issuer"],
    }