import secrets

import pytest

from .clients import acmetkClient


@pytest.mark.asyncio(loop_scope="session")
async def test_ourclient_stale_nonces(tmp_path_factory, service):
    cipher, length = "RSA", 4096
    name = "acmetk"

    directory: str = str(service.directory)
    tmpdir = tmp_path_factory.mktemp(name)
    client = acmetkClient((cipher, length), service, directory, tmpdir)

    await client.register()

    # nonces collected during earlier (concurrent) requests, which the server no longer accepts
    client.client._nonces.update(secrets.token_hex(16) for _ in range(32))

    identifiers = client.identifiers_from_names(["localhost"])
    order = await client.client.order_create(identifiers)
    assert order.status.name == "pending"
