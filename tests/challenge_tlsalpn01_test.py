import asyncio
import datetime
import hashlib
import logging
import ssl
import time

from yarl import URL
import acme.messages
import josepy
import pytest
import pytest_asyncio
import trustme
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509 import NameOID

import acmetk.util
from acmetk.client.challenge_solver import ChallengeSolver, ChallengeType
from acmetk.server.challenge_validator import TLSALPN01ChallengeValidator
from acmetk.server import AcmeCA

from .services import CAService
from .clients import acmetkClient


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class Service:
    def __init__(self, ca: trustme.CA, name, port):
        self.name = name
        self.port = port
        self.ca = ca
        self.app = web.Application()
        self.app.add_routes(
            [
                web.get("/", self._handler),
            ]
        )
        self.sessions: dict[str, bytes] = dict()

    def _dehydrated_alpn_cert(self, name: str, data: bytes) -> trustme.LeafCert:
        from pathlib import Path

        p = Path("/tmp/dehydrated/alpn-certs/")
        assert p.exists()
        while not (p / f"{name}.crt.pem").exists():
            time.sleep(1)
        cert = (p / f"{name}.crt.pem").read_bytes()
        key = (p / f"{name}.key.pem").read_bytes()
        return trustme.LeafCert(key, cert, chain_to_ca=[])

    def __create_alpn_cert(self, name: str, data: bytes) -> trustme.LeafCert:
        assert isinstance(name, str)
        assert isinstance(data, bytes)

        key = trustme.KeyType.RSA._generate_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, name),
            ]
        )

        cb = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now := datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier(TLSALPN01ChallengeValidator.PE_ACMEIDENTIFIER),
                    value=b"\x04\20" + data,
                ),
                critical=True,
            )
        )
        cert = cb.sign(private_key=key, algorithm=hashes.SHA256())

        return trustme.LeafCert(
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            ),
            cert.public_bytes(Encoding.PEM),
            [],
        )

    async def _handler(self, req):
        return web.Response(text="OK")

    def sni_cb(self, client: ssl.SSLObject, name: str, ctx_: ssl.SSLContext):
        try:
            token = self.sessions.get(name, b"secret")
            cert = self.__create_alpn_cert(name, token)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.set_alpn_protocols(["acme-tls/1"])
            cert.configure_cert(ctx)
            client.context = ctx
        except Exception as e:
            log.exception(e)
        return

    async def run(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["acme-tls/1"])
        crt = self.ca.issue_cert("localhost", "127.0.0.1", "::1")
        crt.configure_cert(ctx)
        ctx.sni_callback = self.sni_cb
        self.crt = crt
        self.ca.configure_trust(ctx)

        site = web.TCPSite(self.runner, "0.0.0.0", self.port, ssl_context=ctx)
        await site.start()
        self.site = site
        await asyncio.sleep(1)

    async def stop(self):
        await self.site.stop()
        await self.runner.cleanup()


@pytest.fixture
def ca():
    return trustme.CA()


@pytest_asyncio.fixture
async def alpn(ca, unused_tcp_port):
    s = Service(ca, "127.0.0.1", unused_tcp_port)
    await s.run()
    yield s
    await s.stop()


@pytest.mark.asyncio(loop_scope="session")
async def test_ourclient_tlsalpn01(tmp_path_factory, unused_tcp_port_factory, alpn, db):
    cipher, length = "RSA", 4096

    name = "acmetk"

    tmpdir = tmp_path_factory.mktemp("CA")
    service = CAService(tmpdir)
    await service.run(unused_tcp_port_factory(), db, AcmeCA.Config())

    service.ca.register_challenge_validator(TLSALPN01ChallengeValidator(alpn.port))

    directory: str = URL(next(iter(service.runner.sites)).name).with_path("directory")
    tmpdir = tmp_path_factory.mktemp(name)
    client = acmetkClient((cipher, length), service, directory, tmpdir)

    class TLSALPN01Solver(ChallengeSolver):
        SUPPORTED_CHALLENGES = frozenset([ChallengeType.TLS_ALPN_01])

        async def complete_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ) -> None:
            kA = challenge.chall.key_authorization(key).encode("ascii")
            alpn.sessions[identifier.value] = hashlib.sha256(kA).digest()

        async def cleanup_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ):
            del alpn.sessions[identifier.value]

    client.client._challenge_solvers = dict()
    client.client.register_challenge_solver(TLSALPN01Solver())

    await client.register()
    cert_key = client._make_key(client.tmpdir / "cert_key.pem", ("RSA", 4096))
    names = ["localhost"]
    csr = acmetk.util.generate_csr(names[0], cert_key, client.tmpdir / "csr.pem", names)

    await client.order(csr)

    class BadTLSALPN01Solver(ChallengeSolver):
        SUPPORTED_CHALLENGES = frozenset([ChallengeType.TLS_ALPN_01])

        async def complete_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ) -> None:
            alpn.sessions[identifier.value] = b"x"  # == 78

        async def cleanup_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ):
            del alpn.sessions[identifier.value]

    client.client._challenge_solvers = dict()
    client.client.register_challenge_solver(BadTLSALPN01Solver())

    with pytest.raises(acmetk.client.exceptions.CouldNotCompleteChallenge):
        await client.order(csr)
