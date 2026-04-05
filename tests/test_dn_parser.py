import pytest
from micropki.certificates import parse_subject_dn


def test_parse_subject_dn_comma_format():
    name = parse_subject_dn("CN=Demo Root CA,O=MicroPKI,C=US")
    attrs = {attr.oid._name: attr.value for attr in name}
    assert attrs["commonName"] == "Demo Root CA"
    assert attrs["organizationName"] == "MicroPKI"
    assert attrs["countryName"] == "US"


def test_parse_subject_dn_invalid():
    with pytest.raises(ValueError):
        parse_subject_dn("INVALID_DN")