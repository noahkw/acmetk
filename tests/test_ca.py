import asyncio
import collections
import logging
import logging.config
import shlex
import shutil
import unittest
from pathlib import Path

import acme.messages

import acme_broker.util
from acme_broker import AcmeCA
from acme_broker.client import AcmeClient
from acme_broker.main import load_config

log = logging.getLogger("acme_broker.test_client")

ClientData = collections.namedtuple("ClientData", "key_path csr csr_path")
CAData = collections.namedtuple("CADAta", "key_path cert_path")


class TestAcme:
    DIRECTORY = "http://localhost:8000/directory"

    @property
    def name(self):
        return type(self).__name__[4:]

    def setUp(self) -> None:
        self.log = logging.getLogger(f"acme_broker.tests.{self.name}")
        self.contact = f"woehler+{self.name}@luis.uni-hannover.de"

        dir_ = Path("./tmp") / self.name
        if not dir_.exists():
            dir_.mkdir(parents=True)

        self.path = dir_

        client_account_key_path = dir_ / "client_account.key"
        client_cert_key_path = dir_ / "client_cert.key"
        csr_path = dir_ / "client.csr"

        acme_broker.util.generate_rsa_key(client_account_key_path)
        client_cert_key = acme_broker.util.generate_rsa_key(client_cert_key_path)
        csr = acme_broker.util.generate_csr(
            f"{self.name}.test.de",
            client_cert_key,
            csr_path,
            names=[f"{self.name}.test.de", f"{self.name}2.test.de"],
        )

        self.client_data = ClientData(client_account_key_path, csr, csr_path)

        ca_key_path = dir_ / "root.key"
        ca_cert_path = dir_ / "root.crt"

        self.config = load_config("../debug.yml")

        self.config["ca"].update(
            {
                "cert": ca_cert_path,
                "private_key": ca_key_path,
            }
        )

        self.ca_data = CAData(ca_key_path, ca_cert_path)

        acme_broker.util.generate_root_cert(
            ca_key_path, "DE", "Lower Saxony", "Hanover", "Acme Broker", "AB CA"
        )

        self._rmtree = ["client.csr"]

    def tearDown(self):
        for i in self._rmtree:
            if Path(i).is_absolute():
                log.error(f"{i} is not relative")
                continue

            if (self.path / i).is_dir():
                log.info(f"rmtree {self.path}")
                shutil.rmtree(self.path, ignore_errors=True)
            elif self.path.is_file():
                log.info(f"unlink {self.path}")
                self.path.unlink()

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        runner, ca = await AcmeCA.runner(self.config["ca"])
        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()


class TestRunClient(TestAcme, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        # await asyncio.sleep(600)
        pass


class TestAcmetiny(TestAcme, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        super().setUp()
        for n in ["challenge"]:
            if not (r := (self.path / n)).exists():
                r.mkdir()

    async def _run_acmetiny(self, cmd):
        import acme_tiny as at

        argv = shlex.split(cmd)
        log.info(shlex.join(argv))
        r = await self.loop.run_in_executor(None, at.main, argv)
        return r

    async def test_run(self):
        await self._run_acmetiny(
            f"--directory-url {self.DIRECTORY} --disable-check --contact {self.contact} --account-key "
            f"{self.client_data.key_path} --csr {self.client_data.csr_path} "
            f"--acme-dir {self.path}/challenge"
        )


class TestCertBot(TestAcme, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        super().setUp()

        with open(self.path / "certbot.ini", "wt") as f:
            f.write(
                f"""server = {self.DIRECTORY}
config-dir = ./{self.path}/etc/letsencrypt
work-dir = {self.config["certbot"]["workdir"]}/
logs-dir = {self.config["certbot"]["workdir"]}/logs
"""
            )

        self._rmtree.extend(["archive", "renewal", "live"])
        self._rmtree.extend(["etc"])

        self.domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.client_data.csr)),
            key=lambda s: s[::-1],
        )

    async def _run(self, cmd):
        argv = shlex.split(f"--non-interactive -c {self.path}/certbot.ini " + cmd)
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

        arg = " --domain ".join(self.domains)
        await self._run(f"certonly --webroot --webroot-path {self.path} --domain {arg}")
        arg = " --domain ".join(map(lambda s: f"dns.{s}", self.domains))
        await self._run(
            f"certonly --manual --manual-public-ip-logging-ok --preferred-challenges=dns --manual-auth-hook "
            f'"echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg} --expand'
        )
        arg = " --domain ".join(map(lambda s: f"http.{s}", self.domains))
        await self._run(
            f"certonly --manual --manual-public-ip-logging-ok --preferred-challenges=http --manual-auth-hook "
            f'"echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg} --expand'
        )
        for j in ["", "dns.", "http."]:
            try:
                await self._run(
                    f"revoke --cert-path {self.path}/etc/letsencrypt/live/{j}{self.domains[0]}/cert.pem"
                )
            except Exception as e:
                log.exception(e)

    async def test_skey_revocation(self):
        await self._run(f"register --agree-tos  -m {self.contact}")

        arg = " --domain ".join(self.domains)
        await self._run(f"certonly --webroot --webroot-path {self.path} --domain {arg}")

        await self._run(
            f"revoke --cert-path {self.path}/etc/letsencrypt/live/{self.domains[0]}/cert.pem "
            f"--key-path {self.path}/etc/letsencrypt/live/{self.domains[0]}/privkey.pem"
        )

    async def test_renewal(self):
        await self._run(f"register --agree-tos  -m {self.contact}")
        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.client_data.csr)),
            key=lambda s: s[::-1],
        )
        arg = " --domain ".join(domains)
        await self._run(f"certonly --webroot --webroot-path {self.path} --domain {arg}")

        await self._run(
            f"renew --no-random-sleep-on-renew --webroot --webroot-path {self.path}"
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


class TestOurClient(TestAcme, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.domains = sorted(
            acme_broker.util.names_of(self.client_data.csr),
            key=lambda s: s[::-1],
        )

    def _make_client(self):
        client = AcmeClient(
            directory_url=self.DIRECTORY,
            private_key=self.client_data.key_path,
            contact={"email": self.contact},
        )

        client.register_challenge_solver(
            (acme_broker.client.client.ChallengeSolverType.DNS_01,),
            acme_broker.client.client.DummySolver(),
        )

        return client

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.client = self._make_client()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        await self.client.close()

    async def _run_one(self, client):
        await client.start()
        ord = await client.create_order(self.domains)
        await client.complete_authorizations(ord)
        finalized = await client.finalize_order(ord, self.client_data.csr)
        return await client.get_certificate(finalized)

    async def test_run(self):
        await self._run_one(self.client)

    async def test_run_stress(self):
        clients = [self._make_client() for _ in range(10)]

        await asyncio.gather(*[self._run_one(client) for client in clients])
        await asyncio.gather(*[client.close() for client in clients])

    async def test_revoke(self):
        full_chain = await self._run_one(self.client)
        certs = acme_broker.util.certs_from_fullchain(full_chain)
        await self.client.revoke_certificate(certs[0])

    async def test_unregister(self):
        await self.client.start()
        await self.client.deactivate_account()
        try:
            await self.client.start()
        except acme.messages.Error as e:
            if e.code == "unauthorized":
                pass
