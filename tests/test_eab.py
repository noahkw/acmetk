import urllib.parse
import unittest
from unittest.mock import Mock

import yarl
from cryptography.hazmat.primitives.asymmetric import rsa
from acme_broker.server.external_account_binding import ExternalAccountBindingStore
from tests.test_ca import TestCertBotCA


def load_test_cert():
    with open("../eab_test_cert.pem") as f:
        data = f.read()

    return urllib.parse.quote(data)


class TestEAB(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.eab_store = ExternalAccountBindingStore()

    def test_create(self):
        URL = yarl.URL("http://localhost/eab")
        request = Mock(
            headers={"X-SSL-CERT": load_test_cert()},
            url=URL,
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = key.public_key()

        kid, hmac_key = self.eab_store.create(request)

        signature = list(self.eab_store._pending.values())[0].signature(pub_key)
        self.assertTrue(self.eab_store.verify(pub_key, kid, signature))
        self.assertFalse(self.eab_store.verify(pub_key, kid + "x", hmac_key))
        self.assertFalse(self.eab_store.verify(pub_key, kid, "x" + hmac_key))


class TestCertbotCA_EAB(TestCertBotCA):
    @property
    def config_sec(self):
        return self._config["tests"]["LocalCA_EAB"]

    def setUp(self) -> None:
        super().setUp()

    async def test_register(self):
        URL = yarl.URL("http://localhost:8000/eab")
        request = Mock(
            headers={"X-SSL-CERT": load_test_cert()},
            url=URL,
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        kid, hmac_key = self.ca._eab_store.create(request)

        self.log.debug("kid: %s, hmac_key: %s", kid, hmac_key)
        await self._run(
            f"register --agree-tos  -m {kid} --eab-kid {kid} --eab-hmac-key {hmac_key}"
        )

    async def test_run(self):
        pass

    async def test_subdomain_revocation(self):
        pass

    async def test_skey_revocation(self):
        pass

    async def test_renewal(self):
        pass

    async def test_unregister(self):
        pass
