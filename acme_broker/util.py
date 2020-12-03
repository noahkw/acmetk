import re
import typing
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID


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

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(path, "wb") as pem_out:
        pem_out.write(pem)

    return private_key


def forwarded_url(request):
    """Looks for the X-Forwarded-Proto header and replaces the request URL's
    protocol scheme if applicable."""
    if forwarded_protocol := request.headers.get("X-Forwarded-Proto"):
        return request.url.with_scheme(forwarded_protocol)
    else:
        return request.url


def url_for(request, path, **kwargs):
    return str(
        forwarded_url(request).with_path(
            str(request.app.router[path].url_for(**kwargs))
        )
    )


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

    pem = root_cert.public_bytes(serialization.Encoding.PEM)
    with open(path.parent / "root.crt", "wb") as pem_out:
        pem_out.write(pem)

    return root_cert, root_key


def names_of(csr, lower=False):
    names = [
        v.value
        for v in csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    ]
    names.extend(
        csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    )

    return set([name.lower() if lower else name for name in names])


def pem_split(pem):
    _PEM_TO_CLASS = {
        b"CERTIFICATE": x509.load_pem_x509_certificate,
        b"CERTIFICATE REQUEST": x509.load_pem_x509_csr,
    }

    _PEM_RE = re.compile(
        b"-----BEGIN (?P<cls>"
        + b"|".join(_PEM_TO_CLASS.keys())
        + b""")-----"""
        + b"""\r?
.+?\r?
-----END \\1-----\r?\n?""",
        re.DOTALL,
    )

    return [
        _PEM_TO_CLASS[match.groupdict()["cls"]](match.group(0))
        for match in _PEM_RE.finditer(pem.encode())
    ]


class ConfigurableMixin:
    subclasses: typing.Optional[list]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "config_name", None):
            cls.subclasses.append(cls)

    @classmethod
    def config_mapping(cls):
        return {
            configurable.config_name: configurable for configurable in cls.subclasses
        }
