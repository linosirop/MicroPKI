from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def read_passphrase_file(path: str) -> bytes:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Passphrase file does not exist: {path}")
    if not file_path.is_file():
        raise ValueError(f"Passphrase path is not a file: {path}")

    data = file_path.read_bytes().rstrip(b"\r\n")
    if not data:
        raise ValueError("Passphrase file is empty")

    return data


def generate_private_key(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size not in (2048, 4096):
            raise ValueError("For RSA, --key-size must be 2048 or 4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if key_type == "ecc":
        if key_size == 256:
            return ec.generate_private_key(ec.SECP256R1())
        if key_size == 384:
            return ec.generate_private_key(ec.SECP384R1())
        raise ValueError("For ECC, --key-size must be 256 or 384")

    raise ValueError("Unsupported key type. Must be 'rsa' or 'ecc'")


def serialize_encrypted_private_key(private_key, passphrase: bytes) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_unencrypted_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_encrypted_private_key(pem_data: bytes, passphrase: bytes):
    return serialization.load_pem_private_key(pem_data, password=passphrase)


def load_private_key_from_file(path: str, passphrase: bytes | None = None):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)


def load_certificate_from_file(path: str):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def save_private_key(path: Path, pem_data: bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_data)

    try:
        path.chmod(0o600)
        return True
    except Exception:
        return False


def save_certificate(path: Path, pem_data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_data)


def save_csr(path: Path, pem_data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_data)