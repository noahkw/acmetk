import pytest

from .clients import acmetkClient


@pytest.mark.asyncio(loop_scope="session")
async def test_ourclient_retryafter(tmp_path_factory, service):
    cipher, length = "RSA", 4096
    name = "acmetk"

    directory: str = str(service.directory)
    tmpdir = tmp_path_factory.mktemp(name)
    client = acmetkClient((cipher, length), service, directory, tmpdir)

    cert_key = client._make_key(client.tmpdir / "cert_key.pem", ("RSA", 4096))
    names = ["localhost"]
    import acmetk.util

    csr = acmetk.util.generate_csr(names[0], cert_key, client.tmpdir / "csr.pem", names)

    await client.register()

    assert isinstance(client.client._directory["renewalInfo"], str)

    domains = client.domains_of_csr(csr)
    identifiers = client.identifiers_from_names(domains)
    ord_ = await client.client.order_create(identifiers)

    for authorization_url in ord_.authorizations:
        resp, authorization = await client.client._signed_request(None, authorization_url)
        assert int(resp.headers["Retry-After"]) == 3

    await client.client.authorizations_complete(ord_)

    from acme import messages

    cert_req = messages.CertificateRequest(csr=csr)

    resp, order_obj = await client.client._signed_request(cert_req, ord_.finalize)

    order_url = resp.headers["Location"]
    resp, order = await client.client._signed_request(None, order_url)
    assert int(resp.headers["Retry-After"]) == 7
