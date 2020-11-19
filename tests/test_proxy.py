import logging
import unittest

from acme_broker import AcmeProxy
from tests.test_broker import TestBrokerLocalCA
from tests.test_ca import TestAcmetiny

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
