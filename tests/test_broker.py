import asyncio
import logging
import unittest

from aiohttp import web

import acme_broker.util
from acme_broker import AcmeCA, AcmeBroker
from acme_broker.client import AcmeClient
from tests.test_ca import TestAcme, TestAcmetiny, TestCertBot, TestOurClient

log = logging.getLogger("acme_broker.test_broker")


class TestBroker(TestAcme):
    DIRECTORY = "http://localhost:8000/broker/directory"

    def setUp(self) -> None:
        super().setUp()

        self.brokerclient_account_key_path = (
            self.path / self.config_sec["broker"]["client"]["private_key"]
        )

        if not self.brokerclient_account_key_path.exists():
            acme_broker.util.generate_rsa_key(self.brokerclient_account_key_path)

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()

        broker_client = AcmeClient(
            directory_url=self.config_sec["broker"]["client"]["directory"],
            private_key=self.brokerclient_account_key_path,
            contact=self.config_sec["broker"]["client"]["contact"],
        )

        broker = await AcmeBroker.create_app(
            self.config_sec["broker"], client=broker_client
        )

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

        await broker_client.start()

        self.runner = runner
        self.broker_client = broker_client

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        await self.broker_client.close()


class TestBrokerLocalCA(TestBroker):
    DIRECTORY = "http://localhost:8000/broker/directory"

    @property
    def config_sec(self):
        return self._config["tests"]["BrokerLocalCA"]

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        ca = await AcmeCA.create_app(self.config_sec["ca"])

        broker_client = AcmeClient(
            directory_url=self.config_sec["broker"]["client"]["directory"],
            private_key=self.brokerclient_account_key_path,
            contact=self.config_sec["broker"]["client"]["contact"],
        )

        broker_client.register_challenge_solver(
            (acme_broker.client.client.ChallengeSolverType.DNS_01,),
            acme_broker.client.client.DummySolver(),
        )

        broker = await AcmeBroker.create_app(
            self.config_sec["broker"], client=broker_client
        )

        main_app = web.Application()
        main_app.add_subapp("/ca", ca.app)
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            self.config_sec["broker"]["hostname"],
            self.config_sec["broker"]["port"],
        )
        await site.start()

        await broker_client.start()

        self.runner = runner
        self.broker_client = broker_client


class TestAcmetinyBroker(
    TestAcmetiny, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()


class TestCertBotBroker(
    TestCertBot, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase
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


class TestOurClientBroker(
    TestOurClient, TestBrokerLocalCA, unittest.IsolatedAsyncioTestCase
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


# class TestOurClientBrokerLE(TestOurClient, TestBrokerLE, unittest.IsolatedAsyncioTestCase):
#     def setup(self):
#         super().setUp()
#
#         with open("../infoblox", "r") as f:
#             self.config["infoblox"]["password"] = f.read().strip()
#
#     async def asyncSetUp(self) -> None:
#         await super().asyncSetUp()
#
#         self.infoblox_client = InfobloxClient(**self.config["infoblox"])
#         await self.infoblox_client.connect()
