import logging
import unittest
import importlib
from unittest import mock
import acme.messages

from acmetk import AcmeProxy
from tests.test_broker import TestBrokerLocalCA, TestBrokerLE
from tests.test_ca import TestAcmetiny, TestOurClient, TestOurClientStress, TestCertBot

log = logging.getLogger("acmetk.test_proxy")


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


class TestCertBotWCProxyLocalCA(
    TestCertBot, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    @property
    def names(self):
        return ["*.test.de"]

    async def test_subdomain_revocation(self):
        "avoid Requesting a certificate for dns.*.test.de"
        pass

    async def test_bad_identifier(self):
        await super().test_bad_identifier()

    async def test_no_wc_run(self):
        self.relay._allow_wildcard = False
        with self.assertRaisesRegex(
            acme.messages.Error, "The ACME server can not issue a wildcard certificate"
        ):
            await super().test_run()


class TestOurClientProxyLocalCA(
    TestOurClientStress, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    pass


class TestOurClientProxyLocalCALexicon(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    from lexicon.providers.base import Provider as BaseProvider

    class FakeProvider(BaseProvider):
        """
        Fake provider to simulate the provider resolution from configuration,
        and to have execution traces when lexicon client is invoked
        """

        CONTENTS = set()

        def _authenticate(self):
            print(f"Authenticate action {self.domain}")
            self.__authenticate()

        def __authenticate(self):
            # require .test.de
            if len(self.domain.split(".")) != 2:
                raise ValueError(f"No domain found {self.domain}")
            if (
                self._get_provider_option("auth_user") != "user"
                or self._get_provider_option("auth_psw") != "password"
            ):
                raise ValueError("Invalid login")

        def _create_record(self, rtype, name, content):
            self.__authenticate()
            self.CONTENTS.add(content)
            return {
                "action": "create",
                "domain": self.domain,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def _list_records(self, rtype=None, name=None, content=None):
            return {
                "action": "list",
                "domain": self.domain,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def _update_record(self, identifier, rtype=None, name=None, content=None):
            return {
                "action": "update",
                "domain": self.domain,
                "identifier": identifier,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def _delete_record(self, identifier=None, rtype=None, name=None, content=None):
            self.__authenticate()
            self.CONTENTS.remove(content)
            return {
                "action": "delete",
                "domain": self.domain,
                "identifier": identifier,
                "type": rtype,
                "name": name,
                "content": content,
            }

        def _request(self, action="GET", url="/", data=None, query_params=None):
            # Not use for tests
            pass

    def setUp(self) -> None:
        original_import = importlib.import_module
        self.mocks = []

        def return_import(module_name):
            """
            This will return a adhoc fakeprovider module if necessary,
            or fallback to the normal return of importlib.import_module.
            """
            if module_name == "lexicon.providers.fakeprovider":
                from types import ModuleType

                module = ModuleType("lexicon.providers.fakeprovider")
                setattr(
                    module, "Provider", TestOurClientProxyLocalCALexicon.FakeProvider
                )
                return module
            return original_import(module_name)

        m = mock.patch(
            "acmetk.plugins.lexicon_solver.importlib.import_module",
            **{"side_effect": return_import},
        )
        self.mocks.append(m)
        m.start()

        m = mock.patch(
            "acmetk.plugins.lexicon_solver.LexiconChallengeSolver.query_txt_record",
            **{"return_value": TestOurClientProxyLocalCALexicon.FakeProvider.CONTENTS},
        )
        self.mocks.append(m)
        m.start()

        super().setUp()

    def tearDown(self) -> None:
        for m in self.mocks:
            m.stop()
        super().tearDown()

    @property
    def config_sec(self):
        return self._config["tests"]["ProxyLocalCALexicon"]

    async def test_run(self):
        await super().test_run()


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
        self.assertBadKey(e, "csr")


class TestOurClientRSA1024EC384ProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 1024)
    CERT_KEY_ALG_BITS = ("EC", 521)


class TestOurClientRSA2048RSA1024ProxyLocalCA(
    TestOurClient, TestProxyLocalCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 2048)
    CERT_KEY_ALG_BITS = ("RSA", 1024)


class TestProxyLE(TestProxy, TestBrokerLE):
    @property
    def config_sec(self):
        return self._config["tests"]["ProxyLE"]


class TestAcmetinyProxyLE(TestAcmetiny, TestProxyLE, unittest.IsolatedAsyncioTestCase):
    pass


class TestCertBotProxyLE(TestCertBot, TestProxyLE, unittest.IsolatedAsyncioTestCase):
    async def test_bad_identifier(self):
        # Order is passed through to LE which returns different errors
        pass


class TestOurClientProxyLE(
    TestOurClientStress, TestProxyLE, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()

    async def test_run_stress(self):
        # rate limits!
        pass
