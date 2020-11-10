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
            names=[f"{self.name}.test.de".lower(), f"{self.name}2.test.de".lower()],
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


class TestCertBot(TestBroker, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestBroker.setUp(self)
        with open(self.data.path / "certbot.ini", "wt") as f:
            f.write(
                f"""server = {self.DIRECTORY_BROKER}
config-dir = ./{self.data.path}/etc/letsencrypt
work-dir = /home/noah/workspace/acme-broker/certbot/
logs-dir = /home/noah/workspace/acme-broker/certbot/logs
"""
            )
        self._rmtree.extend(["archive", "renewal", "live"])
        self._rmtree.extend(["etc"])

    async def _run(self, cmd):
        argv = shlex.split(f"--non-interactive -c {self.data.path}/certbot.ini " + cmd)
        import certbot._internal.main as cbm
        import certbot.util
        import certbot._internal.log
        import certbot._internal.error_handler

        certbot.util.atexit_register = lambda func, *argv, **kwargs: log.info(
            f"patched certbot.util.atexit_register for {func}"
        )
        certbot._internal.error_handler.ErrorHandler._set_signal_handlers = lambda x: log.info(
            "patched certbot._internal.error_handler.ErrorHandler._set_signal_handlers"
        )
        certbot._internal.log.pre_arg_parse_setup = lambda: log.info(
            "patched certbot._internal.log.pre_arg_parse_setup"
        )
        certbot._internal.log.post_arg_parse_setup = lambda x: log.info(
            "patched certbot._internal.log.post_arg_parse_setup"
        )

        logging.config.dictConfig(self.config["logging"])

        r = await self.loop.run_in_executor(None, cbm.main, argv)
        return r

    async def test_run(self):
        await self._run("certificates")

        await self._run(f"register --agree-tos  -m {self.contact}")
        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.data.csr)),
            key=lambda s: s[::-1],
        )
        arg = " --domain ".join(domains)
        await self._run(
            f"certonly --webroot --webroot-path {self.data.path} --domain {arg}"
        )
        arg = " --domain ".join(map(lambda s: f"dns.{s}", domains))
        await self._run(
            f"certonly --manual --manual-public-ip-logging-ok --preferred-challenges=dns --manual-auth-hook "
            f'"echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg} --expand'
        )
        arg = " --domain ".join(map(lambda s: f"http.{s}", domains))
        await self._run(
            f"certonly --manual --manual-public-ip-logging-ok --preferred-challenges=http --manual-auth-hook "
            f'"echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg} --expand'
        )
        for j in ["", "dns.", "http."]:
            try:
                await self._run(
                    f"revoke --cert-path {self.data.path}/etc/letsencrypt/live/{j}{domains[0]}/cert.pem"
                )
            except Exception as e:
                log.exception(e)
        # await self._run(f"renew --webroot --webroot-path {self.data.path}")

    async def test_skey_revocation(self):
        await self._run(f"register --agree-tos  -m {self.contact}")
        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.data.csr)),
            key=lambda s: s[::-1],
        )
        arg = " --domain ".join(domains)
        await self._run(
            f"certonly --webroot --webroot-path {self.data.path} --domain {arg}"
        )

        await self._run(
            f"revoke --cert-path {self.data.path}/etc/letsencrypt/live/{domains[0]}/cert.pem "
            f"--key-path {self.data.path}/etc/letsencrypt/live/{domains[0]}/privkey.pem"
        )

    async def test_renewal(self):
        await self._run(f"register --agree-tos  -m {self.contact}")
        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.data.csr)),
            key=lambda s: s[::-1],
        )
        arg = " --domain ".join(domains)
        await self._run(
            f"certonly --webroot --webroot-path {self.data.path} --domain {arg}"
        )

        await self._run(
            f"renew --no-random-sleep-on-renew --webroot --webroot-path {self.data.path}"
        )

    async def test_register(self):
        await self._run(f"register --agree-tos  -m {self.contact}")

    async def test_unregister(self):
        try:
            await self._run("unregister --agree-tos")
        except Exception:
            pass
        await self.test_register()
        await self._run("unregister --agree-tos")
