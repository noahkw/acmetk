import logging
import unittest

from acme_broker import AcmeProxy
from tests.test_broker import TestBrokerLocalCA
from tests.test_ca import TestAcmetiny, TestOurClient, TestCertBot

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
    async def test_run(self):
        await super().test_run()


class TestCertBotProxyLocalCA(
    TestCertBot, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()

    async def test_skey_revocation(self):
        await super().test_skey_revocation()

    async def test_renewal(self):
        await super().test_renewal()

    async def test_register(self):
        await super().test_register()

    async def test_unregister(self):
        await super().test_renewal()


class TestOurClientProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()

    async def test_run_stress(self):
        await super().test_run_stress()

    async def test_revoke(self):
        await super().test_revoke()

    async def test_account_update(self):
        await super().test_account_update()

    async def test_unregister(self):
        await super().test_unregister()
