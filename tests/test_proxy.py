import logging
import unittest
import acme.messages

from acme_broker import AcmeProxy
from tests.test_broker import TestBrokerLocalCA, TestBrokerLE
from tests.test_ca import TestAcmetiny, TestOurClient, TestOurClientStress, TestCertBot

log = logging.getLogger("acme_broker.test_proxy")


class TestProxy:
    """Tests for the AcmeProxy class.

    Inherits from TestBroker in order to reduce code duplication.
    This means that some variables and endpoints still contain 'broker', but
    the class AxmeProxy is being tested regardless.
    """

    _cls = AcmeProxy

    DIRECTORY = "http://localhost:8000/broker/directory"


class TestProxyLocalCA(TestProxy, TestBrokerLocalCA):
    @property
    def config_sec(self):
        return self._config["tests"]["ProxyLocalCA"]


class TestAcmetinyProxyLocalCA(
    TestAcmetiny, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    pass


class TestCertBotProxyLocalCA(
    TestCertBot, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    pass


class TestOurClientProxyLocalCA(
    TestOurClientStress, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    pass


class TestOurClientEC384EC384ProxyLocalCA(
    TestOurClientStress, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = CERT_KEY_ALG_BITS = ("EC", 384)


class TestOurClientEC521EC521ProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 521)
    CERT_KEY_ALG_BITS = ("EC", 521)

    async def test_run(self):
        with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
            await super().test_run()
        self.assertBadKey(e, "_EllipticCurvePublicKey", "csr", "521")


class TestOurClientRSA1024EC384ProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 1024)
    CERT_KEY_ALG_BITS = ("EC", 521)

    async def test_run(self):
        with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
            await super().test_run()
        self.assertBadKey(e, "_RSAPublicKey", "account", "1024")


class TestOurClientRSA2048RSA1024ProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 2048)
    CERT_KEY_ALG_BITS = ("RSA", 1024)

    async def test_run(self):
        with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
            await super().test_run()
        self.assertBadKey(e, "_RSAPublicKey", "csr", "1024")


class TestProxyLE(TestProxy, TestBrokerLE):
    @property
    def config_sec(self):
        return self._config["tests"]["ProxyLE"]


class TestAcmetinyProxyLE(TestAcmetiny, TestProxyLE, unittest.IsolatedAsyncioTestCase):
    pass


class TestCertBotProxyLE(TestCertBot, TestProxyLE, unittest.IsolatedAsyncioTestCase):
    pass


class TestOurClientProxyLE(
    TestOurClientStress, TestProxyLE, unittest.IsolatedAsyncioTestCase
):
    async def test_run_stress(self):
        # rate limits!
        pass
