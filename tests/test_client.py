import asyncio
import collections
import logging
import shlex
import shutil
import unittest
from pathlib import Path

import acme_broker.util
from acme_broker import AcmeCA
from acme_broker.main import load_config

log = logging.getLogger("acme_broker.test_client")

DEFAULT_NETWORK_TIMEOUT = 45

ClientData = collections.namedtuple("data", ["key", "csr", "path"])


class TestClient:
    DIRECTORY = "http://localhost:8000/directory"

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
        thekey = acme_broker.util.generate_rsa_key(dir_ / "the.key")
        csr = acme_broker.util.generate_csr(
            f"{self.name}.test.de",
            thekey,
            dir_ / "the.csr",
            names=[f"{self.name}.test.de"],
        )

        self.data = ClientData(key, csr, dir_)

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
        runner, ca = await AcmeCA.runner(*self.config["ca"].values())
        self.runner = runner
        self.ca = ca

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()


class TestRunClient(TestClient, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        # await asyncio.sleep(600)
        pass


class TestAcmetiny(TestClient, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestClient.setUp(self)
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
            f"--directory-url {self.DIRECTORY} --disable-check --contact {self.contact} --account-key "
            f"{account_key_path} --csr {csr_path} --acme-dir {self.data.path}/challenge "
        )


class TestCertBot(TestClient, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestClient.setUp(self)
        with open(self.data.path / "certbot.ini", "wt") as f:
            f.write(
                f"""server = {self.DIRECTORY}
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

        r = await self.loop.run_in_executor(None, cbm.main, argv)
        return r

    async def test_run(self):
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
        await self._run("renew")

    async def test_Register(self):
        await self._run(f"register --agree-tos  -m {self.contact}")

    async def test_Unregister(self):
        try:
            await self._run("unregister --agree-tos")
        except Exception:
            pass
        await self.test_Register()
        await self._run("unregister --agree-tos")
