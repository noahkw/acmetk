import asyncio
import collections
import logging

from aiohttp import web

import acme_broker.util
from acme_broker import AcmeCA, AcmeBroker
from acme_broker.client import AcmeClient
from tests.test_ca import TestAcme, TestAcmetiny, TestCertBot, TestOurClient

log = logging.getLogger("acme_broker.test_broker")


BrokerData = collections.namedtuple("broker_data", "key_path")


class TestBroker(TestAcme):
    DIRECTORY = "http://localhost:8000/broker/directory"

    def setUp(self) -> None:
        super().setUp()

        brokerclient_account_key_path = self.path / "client_account.key"
        acme_broker.util.generate_rsa_key(brokerclient_account_key_path)

        self.broker_data = BrokerData(brokerclient_account_key_path)

        self.config["broker"]["client"].update(
            {"private_key": brokerclient_account_key_path}
        )

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        ca = await AcmeCA.create_app(self.config["ca"])

        broker_client = AcmeClient(
            directory_url=self.config["broker"]["client"]["directory"],
            private_key=self.config["broker"]["client"]["private_key"],
            contact=self.config["broker"]["client"]["contact"],
        )

        broker_client.register_challenge_solver(
            (acme_broker.client.client.ChallengeSolverType.DNS_01,),
            acme_broker.client.client.DummySolver(),
        )

        broker = await AcmeBroker.create_app(
            self.config["broker"], client=broker_client
        )

        main_app = web.Application()
        main_app.add_subapp("/ca", ca.app)
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner, self.config["ca"]["hostname"], self.config["ca"]["port"]
        )
        await site.start()

        await broker_client.start()

        self.runner = runner
        self.broker_client = broker_client

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()
        await self.broker_client.close()


class TestAcmetinyBroker(TestAcmetiny, TestBroker):
    pass


class TestCertBotBroker(TestCertBot, TestBroker):
    pass


class TestOurClientBroker(TestOurClient, TestBroker):
    async def test_run(self):
        await super().test_run()