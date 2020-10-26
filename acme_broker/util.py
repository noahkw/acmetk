import typing
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID


def generate_nonce():
    return uuid.uuid4().hex


def generate_csr(CN: str, private_key: rsa.RSAPrivateKey, path: Path, names: typing.List[str]):
    csr = x509.CertificateSigningRequestBuilder() \
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)])) \
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False) \
        .sign(private_key, hashes.SHA256())

    with open(path, 'wb') as pem_out:
        pem_out.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def generate_rsa_key(path: Path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key(private_key, path)

    return private_key


def serialize_key(pk):
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_pubkey(pubkey):
    bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return bytes


def deserialize_pubkey(pem):
    return serialization.load_pem_public_key(pem)


def save_key(pk, filename):
    pem = serialize_key(pk)
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)
