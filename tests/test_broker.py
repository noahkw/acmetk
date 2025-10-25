import asyncio
import logging
import unittest

from aiohttp import web

import acmetk.util
from acmetk import AcmeCA, AcmeBroker
from acmetk.server import DummyValidator
from tests.test_ca import (
    TestCA,
    TestAcmetiny,
    TestCertBot,
    TestOurClientStress,
    TestDehydrated,
)

log = logging.getLogger("acmetk.test_broker")


class TestBroker(TestCA):
    """Tests for the AcmeBroker class."""

    _cls = AcmeBroker
    DIRECTORY = "http://localhost:8000/broker/directory"

    def setUp(self) -> None:
        super().setUp()

        self.brokerclient_account_key_path = self.path / self.config_sec["services"]["broker"]["client"]["private_key"]

        if not self.brokerclient_account_key_path.exists():
            acmetk.util.generate_rsa_key(self.brokerclient_account_key_path)

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()

        broker = await self._cls.create_app(acmetk.AcmeBroker.Config(**self.config_sec["broker"]))

        await broker._db._recreate()

        main_app = web.Application()
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            self.config_sec["broker"]["hostname"],
            self.config_sec["broker"]["port"],
        )
        await site.start()

        self.runner = runner
        self.relay = broker

    @property
    def ca(self):
        return self.relay

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()


class TestBrokerLocalCA(TestBroker):
    @property
    def config_sec(self):
        return self._config["tests"]["BrokerLocalCA"]

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        ca = await AcmeCA.create_app(AcmeCA.Config(**self.config_sec["services"]["ca"]))
        ca.register_challenge_validator(DummyValidator())

        await ca._db._recreate()

        self.config_sec["services"]["broker"]["client"].update(
            dict(private_key=str(self.brokerclient_account_key_path), challenge_solver={"type": "dummy"})
        )

        broker = await self._cls.create_app(self._cls.Config(**self.config_sec["services"]["broker"]))
        broker.register_challenge_validator(DummyValidator())

        await broker._db._recreate()

        main_app = web.Application()
        main_app.add_subapp("/ca", ca.app)
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            self.config_sec["services"]["broker"]["hostname"],
            self.config_sec["services"]["broker"]["port"],
        )
        await site.start()
        await broker.on_run(broker.app)
        await ca.on_run(ca.app)

        self.runner = runner
        self.relay = self._broker = broker
        self._ca = ca


class TestAcmetinyBrokerLocalCA(TestAcmetiny, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()


class TestCertBotBrokerLocalCA(TestCertBot, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()

    async def test_subdomain_revocation(self):
        await super().test_subdomain_revocation()

    async def test_skey_revocation(self):
        await super().test_skey_revocation()

    async def test_renewal(self):
        await super().test_renewal()

    async def test_register(self):
        await super().test_register()

    async def test_unregister(self):
        await super().test_renewal()


class TestOurClientBrokerLocalCA(TestOurClientStress, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase):
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

    async def test_certificate_content_type(self):
        await super().test_certificate_content_type()


class TestDehydratedCA(TestDehydrated, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase):
    @property
    def key_algo(self):
        return "secp384r1"

    async def test_run(self):
        # Should fail!
        await super().test_run()


class TestBrokerLE(TestBroker):
    @property
    def config_sec(self):
        return self._config["tests"]["BrokerLE"]

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()

        with open("../infoblox") as f:
            self._config["infoblox"]["password"] = f.read().strip()


class TestAcmetinyBrokerLE(TestAcmetiny, TestBrokerLE, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()


class TestCertBotBrokerLE(TestCertBot, TestBrokerLE, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()

    async def test_subdomain_revocation(self):
        await super().test_subdomain_revocation()

    async def test_skey_revocation(self):
        await super().test_skey_revocation()

    async def test_renewal(self):
        await super().test_renewal()

    async def test_register(self):
        await super().test_register()

    async def test_unregister(self):
        await super().test_renewal()


class TestOurClientBrokerLE(TestOurClientStress, TestBrokerLE, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()

    async def test_run_stress(self):
        # rate limits!
        pass

    async def test_revoke(self):
        await super().test_revoke()

    async def test_account_update(self):
        await super().test_account_update()

    async def test_unregister(self):
        await super().test_unregister()
