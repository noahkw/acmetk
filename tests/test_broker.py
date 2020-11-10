import asyncio
import collections
import logging
import shlex
import shutil
import unittest
from pathlib import Path

from aiohttp import web

import acme_broker.util
from acme_broker import AcmeCA, AcmeBroker
from acme_broker.client import AcmeClient
from acme_broker.main import load_config

log = logging.getLogger("acme_broker.test_broker")

DEFAULT_NETWORK_TIMEOUT = 45

ClientData = collections.namedtuple("data", ["key", "csr", "path"])


class TestBroker:
    DIRECTORY_BROKER = "http://localhost:8000/broker/directory"
    DIRECTORY_CA = "http://localhost:8000/ca/directory"

    @property
    def name(self):
        return self.__class__.__name__[4:]

    def setUp(self) -> None:
        self.log = logging.getLogger(f"acme_broker.tests.{self.name}")
        self.contact = f"woehler+{self.name}@luis.uni-hannover.de"
        dir_ = Path("./tmp") / self.name
        if not dir_.exists():
            dir_.mkdir(parents=True)

        key = acme_broker.util.generate_rsa_key(dir_ / "account.key")
        acme_broker.util.generate_rsa_key(dir_ / "acme_client.key")
        thekey = acme_broker.util.generate_rsa_key(dir_ / "the.key")
        csr = acme_broker.util.generate_csr(
            f"{self.name}.test.de",
            thekey,
            dir_ / "the.csr",
            names=[f"{self.name}.test.de", f"{self.name}2.test.de"],
        )

        self.data = ClientData(key, csr, dir_)

        _, _ = acme_broker.util.generate_root_cert(
            Path("./root.key"), "DE", "Lower Saxony", "Hanover", "Acme Broker", "AB CA"
        )

        self._rmtree = ["the.csr"]

    def tearDown(self):
        for i in self._rmtree:
            if Path(i).is_absolute():
                log.error(f"{i} is not relative")
                continue

            if (path := self.data.path / i).is_dir():
                log.info(f"rmtree {path}")
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                log.info(f"unlink {path}")
                path.unlink()

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        self.config = load_config("../debug.yml")
        ca = await AcmeCA.create_app(self.config["ca"])

        client = AcmeClient(
            directory_url=self.config["broker"]["client"]["directory"],
            private_key=self.data.path / self.config["broker"]["client"]["private_key"],
            contact=self.config["broker"]["client"]["contact"],
        )

        client.register_challenge_solver(
            (acme_broker.client.client.ChallengeSolverType.DNS_01,),
            acme_broker.client.client.DummySolver(),
        )

        broker = await AcmeBroker.create_app(self.config["broker"], client=client)

        main_app = web.Application()
        main_app.add_subapp("/ca", ca.app)
        main_app.add_subapp("/broker", broker.app)

        runner = web.AppRunner(main_app)
        await runner.setup()

        site = web.TCPSite(
            runner, self.config["ca"]["hostname"], self.config["ca"]["port"]
        )
        await site.start()

        await client.start()

        self.runner = runner
        self.ca = ca
        self.broker = broker
        self.client = client

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()
        await self.client.close()


class TestAcmetiny(TestBroker, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestBroker.setUp(self)
        path = self.data.path
        for n in ["challenge"]:
            if not (r := (path / n)).exists():
                r.mkdir()

    async def _run_acmetiny(self, cmd):
        import acme_tiny as at

        argv = shlex.split(cmd)
        log.info(shlex.join(argv))
        r = await self.loop.run_in_executor(None, at.main, argv)
        return r

    async def test_run(self):
        key, csr, path = self.data
        account_key_path = path / "account.key"
        csr_path = path / "the.csr"

        self.assertTrue(account_key_path.exists())
        self.assertTrue(csr_path.exists())

        await self._run_acmetiny(
            f"--directory-url {self.DIRECTORY_BROKER} --disable-check --contact {self.contact} --account-key "
            f"{account_key_path} --csr {csr_path} --acme-dir {self.data.path}/challenge "
        )
