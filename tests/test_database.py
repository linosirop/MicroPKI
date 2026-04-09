from micropki.database import init_database, insert_certificate_record, get_certificate_by_serial, list_certificates


def test_database_insert_and_fetch(tmp_path):
    db_path = str(tmp_path / "micropki.db")
    init_database(db_path)

    pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
    insert_certificate_record(
        db_path=db_path,
        serial_hex="ABC123",
        subject="CN=Test",
        issuer="CN=Issuer",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        cert_pem=pem,
        status="valid",
    )

    row = get_certificate_by_serial(db_path, "ABC123")
    assert row is not None
    assert row["subject"] == "CN=Test"
    assert row["cert_pem"] == pem


def test_database_list_certificates(tmp_path):
    db_path = str(tmp_path / "micropki.db")
    init_database(db_path)

    insert_certificate_record(
        db_path=db_path,
        serial_hex="AAA111",
        subject="CN=One",
        issuer="CN=Issuer",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        cert_pem="PEM1",
        status="valid",
    )

    insert_certificate_record(
        db_path=db_path,
        serial_hex="BBB222",
        subject="CN=Two",
        issuer="CN=Issuer",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        cert_pem="PEM2",
        status="revoked",
    )

    valid_rows = list_certificates(db_path, status="valid")
    assert len(valid_rows) == 1
    assert valid_rows[0]["serial_hex"] == "AAA111"