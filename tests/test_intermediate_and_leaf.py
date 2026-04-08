from micropki.crypto_utils import generate_private_key
from micropki.certificates import (
    build_self_signed_root_ca,
    build_intermediate_certificate,
    build_end_entity_certificate,
)
from micropki.csr import build_intermediate_csr
from micropki.templates import parse_san_entries, apply_end_entity_template


def test_intermediate_certificate_is_ca():
    root_key = generate_private_key("rsa", 4096)
    root_cert = build_self_signed_root_ca(root_key, "CN=Root CA,O=MicroPKI,C=US", 3650)

    intermediate_key = generate_private_key("rsa", 4096)
    csr = build_intermediate_csr(intermediate_key, "CN=Intermediate CA,O=MicroPKI,C=US", 0)
    intermediate_cert = build_intermediate_certificate(root_cert, root_key, csr, 1825, 0)

    bc = intermediate_cert.extensions.get_extension_for_class(type(__import__("cryptography").x509.BasicConstraints(ca=True, path_length=0))).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_server_certificate_contains_san():
    root_key = generate_private_key("rsa", 4096)
    root_cert = build_self_signed_root_ca(root_key, "CN=Root CA,O=MicroPKI,C=US", 3650)

    intermediate_key = generate_private_key("rsa", 4096)
    csr = build_intermediate_csr(intermediate_key, "CN=Intermediate CA,O=MicroPKI,C=US", 0)
    intermediate_cert = build_intermediate_certificate(root_cert, root_key, csr, 1825, 0)

    leaf_key = generate_private_key("rsa", 2048)
    san_objects = parse_san_entries(["dns:example.com", "ip:192.168.1.10"])

    cert = build_end_entity_certificate(
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
        subject_dn="CN=example.com,O=MicroPKI,C=US",
        subject_public_key=leaf_key.public_key(),
        validity_days=365,
        template_builder=lambda builder: apply_end_entity_template(builder, "server", leaf_key, san_objects),
    )

    san = cert.extensions.get_extension_for_class(type(__import__("cryptography").x509.SubjectAlternativeName(san_objects))).value
    assert len(san) == 2