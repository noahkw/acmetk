import logging

import aiohttp.web_runner
from yarl import URL

import acmetk.util
from acmetk import AcmeCA, AcmeBroker, AcmeProxy
from acmetk.server import AcmeRelayBase, AcmeServerBase


class TestService:
    runner: aiohttp.web_runner.AppRunner

    def __init__(self, tmpdir):
        self.tmpdir = tmpdir
        self.log = logging.getLogger(f"acmetk.tests.{self.__class__.__name__}")

        ca_key_path = self.tmpdir / "root.key"

        acmetk.util.generate_root_cert(
            ca_key_path,
            "DE",
            "Lower Saxony",
            "Hanover",
            "Acme Toolkit",
            self.__class__.__name__,
        )

    async def run(self, port, db, config: AcmeCA.Config):
        raise NotImplementedError()

    async def shutdown(self):
        await self.runner.shutdown()

    async def cleanup(self):
        await self.runner.cleanup()

    @property
    def directory(self) -> URL:
        return URL(next(iter(self.runner.sites)).name).with_path("directory")


class CAService(TestService):
    ca: AcmeServerBase

    async def run(self, port, db, config: AcmeCA.Config):
        config.port = port
        config.hostname = "localhost"
        config.db = db.format(database="acme-ca")
        config.cert = self.tmpdir / "root.crt"
        config.private_key = self.tmpdir / "root.key"
        runner, ca = await AcmeCA.runner(config)

        self.runner = runner
        self.ca = ca


class RelayService(TestService):
    _cls: type[AcmeServerBase] = None
    broker_client: acmetk.AcmeClient
    relay: AcmeRelayBase
    ca: AcmeCA

    @property
    def directory(self):
        return super().directory.with_path("broker/directory")

    async def run(self, port, db, config: "AcmeRelayBase.Config"):
        from aiohttp import web

        config.port = port
        config.hostname = "localhost"
        config.db = db.format(database="acme-ca")
        config.cert = self.tmpdir / "root.crt"
        config.private_key = self.tmpdir / "root.key"

        ca = await AcmeCA.create_app(config)
        #       await ca._db._recreate()

        config = AcmeBroker.Config(
            hostname="localhost",
            port=port,
            client=acmetk.AcmeClient.Config(
                private_key=str(config.private_key),
                directory=f"http://{config.hostname}:{config.port}/ca/directory",
                challenge_solver={"type": "dummy"},
                contact={"email": "acmetk@example.org"},
            ),
            challenge_validators=["dummy"],
            db=db.format(database="acme-broker"),
        )
        broker = await self._cls.create_app(config)
        #        await broker._db._recreate()

        main_app = web.Application()
        main_app.add_subapp("/ca", ca.app)
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            config.hostname,
            config.port,
        )
        await site.start()

        await ca.on_run(ca.app)
        await broker.on_run(broker.app)
        self.runner = runner
        self.broker_client = broker._client
        self.relay: AcmeRelayBase
        self.relay = broker
        self.ca = ca


class ProxyService(RelayService):
    _cls = AcmeProxy


class BrokerService(RelayService):
    _cls = AcmeBroker
