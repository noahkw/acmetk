import typing
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import josepy
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID


def generate_nonce():
    return uuid.uuid4().hex


def generate_csr(
    CN: str, private_key: rsa.RSAPrivateKey, path: Path, names: typing.List[str]
):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(path, "wb") as pem_out:
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
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_pubkey(pubkey):
    key = getattr(
        pubkey, "key", pubkey
    )  # this allows JWKRSA objects to be passed directly

    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_pubkey(pem):
    return serialization.load_pem_public_key(pem)


def deserialize_privatekey(pem):
    return serialization.load_pem_private_key(pem, None)


def deserialize_cert(pem):
    return x509.load_pem_x509_certificate(pem)


def save_key(pk, filename):
    pem = serialize_key(pk)
    with open(filename, "wb") as pem_out:
        pem_out.write(pem)


def load_key(filename):
    with open(filename, "rb") as pem:
        return deserialize_privatekey(pem.read())


def load_cert(filename):
    with open(filename, "rb") as pem:
        return deserialize_cert(pem.read())


def sha256_hex_digest(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def build_url(r, app, p, **kwargs):
    return str(r.url.with_path(str(app.router[p].url_for(**kwargs))))


def url_for(r, p, **kwargs):
    try:
        return build_url(r, r.app, p, **kwargs)
    except KeyError:
        # search subapps for route
        for subapp in r.app._subapps:
            return build_url(r, subapp, p, **kwargs)


def serialize_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_cert_from_csr(csr, root_cert, root_key):
    names = list(names_of(csr))

    subject = csr.subject or x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, names[0])]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=29))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(i) for i in names]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return cert


def generate_root_cert(path: Path, country, state, locality, org_name, common_name):
    root_key = generate_rsa_key(path)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, common_name),
        ]
    )

    root_cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365 * 4))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    root_cert = root_cert_builder.sign(root_key, hashes.SHA256())

    pem = serialize_cert(root_cert)
    with open(path.parent / "root.crt", "wb") as pem_out:
        pem_out.write(pem)

    return root_cert, root_key


def decode_csr(b64der):
    decoded = josepy.decode_csr(b64der)
    return decoded.wrapped.to_cryptography()


def names_of(csr):
    return set(
        [
            v.value
            for v in csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        ]
    ) | set(
        csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    )
