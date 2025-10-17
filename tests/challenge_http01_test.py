import logging

import acme.messages
import josepy
import pytest
import pytest_asyncio
from aiohttp import web
from yarl import URL

import acmetk.util
from acmetk.client.challenge_solver import ChallengeSolver, ChallengeType
from acmetk.server.challenge_validator import Http01ChallengeValidator
from acmetk.server import AcmeCA

from .services import CAService
from .clients import acmetkClient


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class HTTP01Service:
    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.app = web.Application()
        self.app.add_routes(
            [
                web.get("/.well-known/acme-challenge/{token}", self.handle_acme_challenge),
            ]
        )
        self.sessions: dict[str, bytes] = dict()

    async def handle_acme_challenge(self, request):
        token = request.match_info["token"]
        value = self.sessions.get(token, "secret")
        return web.Response(text=value)

    async def run(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "localhost", self.port)
        await site.start()
        self.site = site

    async def stop(self):
        await self.site.stop()
        await self.runner.cleanup()


@pytest_asyncio.fixture
async def http01(unused_tcp_port_factory):
    s = HTTP01Service("localhost", unused_tcp_port_factory())
    await s.run()
    log.info(f"http01 validator at {s.runner.addresses}")
    yield s
    await s.stop()


@pytest.mark.asyncio(loop_scope="session")
async def test_ourclient_http01(tmp_path_factory, unused_tcp_port_factory, http01, db):

    cipher, length = "RSA", 4096

    name = "acmetk"

    tmpdir = tmp_path_factory.mktemp("CA")
    service = CAService(tmpdir)
    await service.run(
        unused_tcp_port_factory(),
        db,
        AcmeCA.Config(
            rsa_min_keysize=2048,
            ec_min_keysize=256,
            use_forwarded_header=False,
            require_eab=False,
            allow_wildcard=False,
        ),
    )

    await service.ca._db._recreate()

    service.ca.register_challenge_validator(Http01ChallengeValidator(http01.port))
    directory: str = URL(next(iter(service.runner.sites)).name).with_path("directory")
    tmpdir = tmp_path_factory.mktemp(name)
    client = acmetkClient((cipher, length), service, directory, tmpdir)

    class HTTP01Solver(ChallengeSolver):
        SUPPORTED_CHALLENGES = frozenset([ChallengeType.HTTP_01])

        async def complete_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ) -> None:
            kA = challenge.chall.key_authorization(key)
            token = challenge.chall.encode("token")
            http01.sessions[token] = kA

        async def cleanup_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ):
            token = challenge.chall.encode("token")
            del http01.sessions[token]

    client.client._challenge_solvers = dict()
    client.client.register_challenge_solver(HTTP01Solver())

    await client.register()
    cert_key = client._make_key(client.tmpdir / "cert_key.pem", ("RSA", 4096))
    names = ["localhost"]
    csr = acmetk.util.generate_csr(names[0], cert_key, client.tmpdir / "csr.pem", names)

    await client.order(csr)

    class BadHTTP01Solver(ChallengeSolver):
        SUPPORTED_CHALLENGES = frozenset([ChallengeType.HTTP_01])

        async def complete_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ) -> None:
            token = challenge.chall.encode("token")
            http01.sessions[token] = "x"

        async def cleanup_challenge(
            self,
            key: josepy.jwk.JWK,
            identifier: acme.messages.Identifier,
            challenge: acme.messages.ChallengeBody,
        ):
            token = challenge.chall.encode("token")
            del http01.sessions[token]

    client.client._challenge_solvers = dict()
    client.client.register_challenge_solver(BadHTTP01Solver())

    with pytest.raises(acmetk.client.exceptions.CouldNotCompleteChallenge):
        await client.order(csr)
