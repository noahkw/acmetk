import asyncio
import base64
import cProfile
import contextlib
import inspect
import ipaddress
import logging
import re
import typing
from datetime import datetime, timedelta
from pathlib import Path
from time import perf_counter

import aiohttp.web
import dns.asyncresolver
import yarl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import NameOID

logger = logging.getLogger(__name__)
if typing.TYPE_CHECKING:
    import cryptography

KEY_FILE_MODE = 0o600


class DNS01ChallengeHelper:
    """Baseclass for DNS Challenge Solvers & Validators

    Provides the methods to query the TXT records and wait for the propagation to succeed
    """

    # from acmetk.models.challenge import ChallengeType
    SUPPORTED_CHALLENGES = frozenset(["dns-01"])
    """The types of challenges that the solver supports."""

    POLLING_DELAY = 1.0
    """Time in seconds between consecutive DNS requests."""

    POLLING_TIMEOUT = 60.0 * 5
    """Time in seconds after which placing the TXT record is considered a failure."""

    DEFAULT_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
    """The DNS servers to use if none are specified during initialization."""

    def __init__(self, dns_servers: typing.Optional[list[str]] = None):
        self._loop = asyncio.get_event_loop()
        self._resolvers = []

        for nameserver in dns_servers or self.DEFAULT_DNS_SERVERS:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [nameserver]
            self._resolvers.append(resolver)

    @staticmethod
    async def _query_txt_record(
        resolver: dns.asyncresolver.Resolver, name: str
    ) -> tuple[str, set[str]]:
        """Queries a DNS TXT record.

        :param resolver: The DNS resolver to use.
        :param name: Name of the TXT record to query.
        :return: Set of strings stored in the TXT record.
        """
        txt_records = []

        with contextlib.suppress(
            dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer
        ):
            resp = await resolver.resolve(name, "TXT")

            for records in resp.rrset.items.keys():
                txt_records.extend([record.decode() for record in records.strings])

        return resolver.nameservers[0], set(txt_records)

    async def query_txt_records(self, name: str, text: str) -> tuple[bool, set[str]]:
        result_set: list[tuple[str, set[str]]] = await asyncio.gather(
            *[self._query_txt_record(resolver, name) for resolver in self._resolvers]
        )
        record_sets: dict[str, set[str]] = dict(result_set)

        missing = set()
        for name, records in record_sets.items():
            if text not in records:
                missing.add(name)

        if missing:
            return False, missing

        return True, missing

    async def _query_until_completed(self, name: str, text: str) -> None:
        """For ChallengeSolvers - wait until the change is propagated."""
        while True:
            done, missing = await self.query_txt_records(name, text)
            if done is True:
                return
            logger.debug(
                f"{name} does not have TXT {text} yet. Retrying (name servers missing record: {missing})"
            )
            await asyncio.sleep(1.0)


def generate_csr(CN: str, private_key: rsa.RSAPrivateKey, path: Path, sans: list[str]):
    """Generates a certificate signing request.

    :param CN: The requested common name.
    :param private_key: The private key to sign the CSR with.
    :param path: The path to write the PEM-serialized CSR to.
    :param names: The requested names in the CSR.
    :return: The generated CSR.
    """
    addresses = list()
    names = list()
    for i in sans:
        try:
            addresses.append(ipaddress.ip_address(i))
        except ValueError:
            names.append(i)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in names]
                + [x509.IPAddress(addr) for addr in addresses]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(path, "wb") as pem_out:
        pem_out.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def generate_rsa_key(path: Path, key_size=2048) -> rsa.RSAPrivateKey:
    """Generates an RSA private key and saves it to the given path as PEM.

    :param path: The path to write the PEM-serialized key to.
    :param key_size: The RSA key size.
    :return: The generated private key.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.touch(KEY_FILE_MODE) if not path.exists() else path.chmod(KEY_FILE_MODE)

    with open(path, "wb") as pem_out:
        pem_out.write(pem)

    return private_key


def generate_ec_key(path: Path, key_size=256) -> ec.EllipticCurvePrivateKey:
    """Generates an EC private key and saves it to the given path as PEM.

    :param path: The path to write the PEM-serialized key to.
    :param key_size: The EC key size.
    :return: The generated private key.
    """
    curve = getattr(ec, f"SECP{key_size}R1")
    private_key = ec.generate_private_key(curve())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.touch(KEY_FILE_MODE) if not path.exists() else path.chmod(KEY_FILE_MODE)

    with open(path, "wb") as pem_out:
        pem_out.write(pem)

    return private_key


def forwarded_url(request: aiohttp.web.Request) -> "yarl.URL":
    """Returns the URL with the correct protocol scheme.

    Looks for the X-Forwarded-Proto header and replaces the request URL's
    protocol scheme if applicable.

    :param request: The request needed to build the URL.
    :return: The corrected URL.
    """
    if forwarded_protocol := request.headers.get("X-Forwarded-Proto"):
        return request.url.with_scheme(forwarded_protocol)
    else:
        return request.url


def url_for(request: aiohttp.web.Request, path: str, **kwargs) -> str:
    """Builds a URL for a given path and optional parameters.

    :param request: The request needed to build the URL.
    :param path: The path for which to build a URL.
    :param kwargs: Optional parameters for URL construction, such as an account ID.
    :return: The constructed URL.
    """
    return str(
        forwarded_url(request).with_path(
            str(request.app.router[path].url_for(**kwargs))
        )
    )


def next_url(url: str, current_cursor: int) -> str:
    """Returns the URL's cursor query given its current value

    :param url: The URL whose cursor is to be incremented.
    :type current_cursor: The cursor's current value.
    :return: The URL with its cursor query value incremented.
    """
    return str(yarl.URL(url) % {"cursor": current_cursor + 1})


def generate_cert_from_csr(
    csr: "cryptography.x509.CertificateSigningRequest",
    root_cert: "cryptography.x509.Certificate",
    root_key: rsa.RSAPrivateKey,
) -> "cryptography.x509.Certificate":
    """Generates a signed certificate from a certificate signing request given the certificate authority's
    certificate and private key.

    :param csr: The certificate signing request to generate a certificate from.
    :param root_cert: The signing CA's root certificate.
    :param root_key: The signing CA's root key.
    :return: The generated certificate.
    """
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


def generate_root_cert(
    path: Path, country: str, state: str, locality: str, org_name: str, common_name: str
) -> tuple["cryptography.x509.Certificate", rsa.RSAPrivateKey]:
    """Generates a self-signed CA root certificate (RSA).

    :param path: The path of the generated private key. The resulting certificate will be saved to
        the same directory as :code:`root.crt`.
    :param country: The requested *country name* in the certificate.
    :param state: The requested *state or province name* in the certificate.
    :param locality: The requested *locality name* in the certificate.
    :param org_name: The requested *organization name* in the certificate.
    :param common_name: The requested *common name* in the certificate.
    :return: The resulting root certificate and corresponding private key.
    """
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


def names_of(
    csr: "cryptography.x509.CertificateSigningRequest", lower: bool = False
) -> set[str]:
    """Returns all names contained in the given CSR.

    :param csr: The CRS whose names to extract.
    :param lower: True if the names should be returned in lowercase.
    :return: Set of the contained identifier strings.
    """
    names = [
        v.value
        for v in csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    ]
    names.extend(
        csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    )

    return {name.lower() if lower else name for name in names}


class base64url:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    @staticmethod
    def decode(data: bytes) -> bytes:
        pad = b"=" * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + pad)


def pem_split(
    pem: str,
) -> list[
    typing.Union[
        "cryptography.x509.CertificateSigningRequest", "cryptography.x509.Certificate"
    ]
]:
    """Parses a PEM encoded string and returns all contained CSRs and certificates.

    :param pem: The concatenated PEM encoded CSRs and certificates.
    :return: List of all certificate signing requests and certificates found in the PEM string.
    """
    _PEM_TO_CLASS = {
        b"CERTIFICATE": x509.load_pem_x509_certificate,
        b"CERTIFICATE REQUEST": x509.load_pem_x509_csr,
        b"EC PRIVATE KEY": lambda x: serialization.load_pem_private_key(
            x, password=None
        ),
        b"RSA PRIVATE KEY": lambda x: serialization.load_pem_private_key(
            x, password=None
        ),
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


class PerformanceMeasure:
    def __init__(self, profile_, init=True):
        if init:
            callerframerecord = inspect.stack()[2]
            frame = callerframerecord[0]
            info = inspect.getframeinfo(frame)
            # cProfile is full path anyway …
            # p = Path(info.filename).resolve()
            # for i in sorted(sys.path, key=lambda x: len(x), reverse=True):
            #     if not p.is_relative_to((parent := Path(i)).resolve()):
            #         continue
            #     p = p.relative_to(parent)
            #     break
            self.mnemonic = f"{info.filename}:{info.lineno} {info.function}"

    #        self.profile = cProfile.Profile()

    async def __aenter__(self):
        self.begin = perf_counter()
        #        self.profile.enable()
        return self

    async def __aexit__(self, type, value, traceback):
        self.end = perf_counter()

    #        self.profile.disable()

    @property
    def duration(self):
        return self.end - self.begin


class PerformanceMeasurementSystem:
    def __init__(self, enable=False):
        self.enable = enable
        self.begin = perf_counter()
        self.end = None
        self.measuring_points = []
        if self.enable:
            self.profile = cProfile.Profile()
            self.profile.enable()
        else:
            self.profile = None

    def measure(self):
        if self.enable:
            self.measuring_points.append(r := PerformanceMeasure(self.profile))
            return r
        return PerformanceMeasure(self.profile, False)

    @property
    def sum(self):
        return sum(map(lambda x: x.duration, self.measuring_points))

    @property
    def duration(self):
        if self.end is None:
            self.end = perf_counter()
        return self.end - self.begin
