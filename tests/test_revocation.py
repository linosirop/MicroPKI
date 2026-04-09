import pytest

from micropki.database import init_database, insert_certificate_record, get_certificate_by_serial
from micropki.revocation import normalize_revocation_reason, revoke_certificate


class DummyLogger:
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass


def test_reason_normalization():
    assert normalize_revocation_reason("keyCompromise") == "keyCompromise"
    assert normalize_revocation_reason("KEYCOMPROMISE") == "keyCompromise"


def test_invalid_reason():
    with pytest.raises(ValueError):
        normalize_revocation_reason("badReason")


def test_revoke_certificate_updates_database(tmp_path):
    db_path = str(tmp_path / "micropki.db")
    init_database(db_path)

    insert_certificate_record(
        db_path=db_path,
        serial_hex="ABC123",
        subject="CN=Test",
        issuer="CN=Issuer",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        cert_pem="PEM",
        status="valid",
    )

    result = revoke_certificate(db_path, "ABC123", "keyCompromise", DummyLogger())
    assert result["already_revoked"] is False

    row = get_certificate_by_serial(db_path, "ABC123")
    assert row["status"] == "revoked"
    assert row["revocation_reason"] == "keyCompromise"
    assert row["revocation_date"] is not None