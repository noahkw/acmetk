from yarl import URL
import pytest
import pytest_asyncio

from acmetk.server import DummyValidator, AcmeCA
from .services import CAService
from .clients import acmetkClient


@pytest_asyncio.fixture
async def service(tmp_path_factory, unused_tcp_port_factory, db):

    tmpdir = tmp_path_factory.mktemp("acmetk")
    service = CAService(tmpdir)
    await service.run(
        unused_tcp_port_factory(),
        db,
        AcmeCA.Config(
            rsa_min_keysize=2048,
            ec_min_keysize=256,
            tos_url=None,
            mail_suffixes=None,
            subnets=None,
            use_forwarded_header=False,
            require_eab=False,
            allow_wildcard=False,
        ),
    )
    return service


@pytest.mark.asyncio(loop_scope="session")
async def test_ourclient_profile(tmp_path_factory, service):

    cipher, length = "RSA", 4096
    name = "acmetk"

    service.ca.register_challenge_validator(DummyValidator())

    directory: str = URL(next(iter(service.runner.sites)).name).with_path("directory")
    tmpdir = tmp_path_factory.mktemp(name)
    client = acmetkClient((cipher, length), service, directory, tmpdir)

    cert_key = client._make_key(client.tmpdir / "cert_key.pem", ("RSA", 4096))
    names = ["localhost"]
    import acmetk.util

    csr = acmetk.util.generate_csr(names[0], cert_key, client.tmpdir / "csr.pem", names)

    await client.register()
    await client.order(csr, profile="classic")
