import pytest
from cryptography import x509
from micropki.templates import parse_san_entries, validate_template_and_sans


def test_parse_multiple_sans():
    sans = parse_san_entries([
        "dns:example.com",
        "dns:www.example.com",
        "ip:192.168.1.1",
        "email:alice@example.com",
        "uri:https://example.com/app",
    ])
    assert len(sans) == 5


def test_server_requires_san():
    with pytest.raises(ValueError):
        validate_template_and_sans("server", [])


def test_code_signing_rejects_ip_san():
    san_objects = parse_san_entries(["ip:127.0.0.1"])
    with pytest.raises(ValueError):
        validate_template_and_sans("code_signing", san_objects)