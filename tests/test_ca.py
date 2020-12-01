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
from acme_broker.client import (
    AcmeClient,
    DummySolver,
)
from acme_broker.main import load_config
from acme_broker.models.messages import RevocationReason
from acme_broker.server import DummyValidator

log = logging.getLogger("acme_broker.test_ca")

ClientData = collections.namedtuple("ClientData", "key_path csr csr_path")
CAData = collections.namedtuple("CADAta", "key_path cert_path")


class TestAcme:
    DIRECTORY = "http://localhost:8000/directory"
    _config: dict
    log: logging.Logger
    contact: str
    path: Path
    client_data: ClientData

    @property
    def name(self):
        return type(self).__name__[4:]

    @property
    def config_sec(self):
        return NotImplementedError

    def setUp(self) -> None:
        """Sets up our test object with the necessary properties for testing using a client"""
        self._config = load_config("../debug.yml")
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
            self.config_sec["names"][0],
            client_cert_key,
            csr_path,
            names=self.config_sec["names"],
        )

        self.client_data = ClientData(client_account_key_path, csr, csr_path)

        self._rmtree = ["client.csr"]

    def tearDown(self):
        for i in self._rmtree:
            if Path(i).is_absolute():
                log.error(f"{i} is not relative")
                continue

            if (path := self.path / i).is_dir():
                log.info(f"rmtree {path}")
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                log.info(f"unlink {path}")
                path.unlink()

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()


class TestCA(TestAcme):
    @property
    def config_sec(self):
        return self._config["tests"]["LocalCA"]

    def setUp(self) -> None:
        super().setUp()

        ca_key_path = self.path / "root.key"
        ca_cert_path = self.path / "root.crt"

        self.config_sec["ca"].update(
            {
                "cert": ca_cert_path,
                "private_key": ca_key_path,
            }
        )

        self.ca_data = CAData(ca_key_path, ca_cert_path)

        acme_broker.util.generate_root_cert(
            ca_key_path, "DE", "Lower Saxony", "Hanover", "Acme Broker", "AB CA"
        )

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()

        runner, ca = await AcmeCA.runner(self.config_sec["ca"])
        ca.register_challenge_validator(DummyValidator())

        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()


class TestAcmetiny:
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


class TestCertBot:
    def setUp(self) -> None:
        super().setUp()

        with open(self.path / "certbot.ini", "wt") as f:
            f.write(
                f"""server = {self.DIRECTORY}
config-dir = ./{self.path}/etc/letsencrypt
work-dir = {self._config["certbot"]["workdir"]}/
logs-dir = {self._config["certbot"]["workdir"]}/logs
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

        logging.config.dictConfig(self._config["logging"])

        r = await self.loop.run_in_executor(None, cbm.main, argv)
        return r

    async def test_run(self):
        await self._run("certificates")

        await self._run(f"register --agree-tos  -m {self.contact}")

        arg = " --domain ".join(self.domains)
        await self._run(f"certonly --webroot --webroot-path {self.path} --domain {arg}")

    async def test_subdomain_revocation(self):
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

        arg = " --domain ".join(self.domains)
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


class TestOurClient:
    def setUp(self) -> None:
        super().setUp()

        self.domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(self.client_data.csr)),
            key=lambda s: s[::-1],
        )

    def _make_client(self, key_path, email):
        client = AcmeClient(
            directory_url=self.DIRECTORY,
            private_key=key_path,
            contact={"email": email},
            server_cert=self.config_sec.get("client", {}).get("server_cert", None),
        )

        client.register_challenge_solver(DummySolver())

        return client

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.client = self._make_client(self.client_data.key_path, self.contact)

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        await self.client.close()

    async def _run_one(self, client, csr):
        await client.start()

        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(csr)),
            key=lambda s: s[::-1],
        )

        ord = await client.order_create(domains)
        await client.authorizations_complete(ord)
        finalized = await client.order_finalize(ord, csr)
        return await client.certificate_get(finalized)

    async def test_run(self):
        await self._run_one(self.client, self.client_data.csr)

    async def test_run_stress(self):
        clients_csr = []  # (client, csr) tuples
        for i in range(10):
            client_account_key_path = self.path / f"client_{i}_account.key"

            acme_broker.util.generate_rsa_key(client_account_key_path)
            client_cert_key = acme_broker.util.generate_rsa_key(
                self.path / f"client_{i}_cert.key"
            )
            csr = acme_broker.util.generate_csr(
                f"{self.name}.test.de",
                client_cert_key,
                self.path / f"client_{i}.csr",
                names=[f"{self.name}.{i}.test.de", f"{self.name}2.{i}.test.de"],
            )

            clients_csr.append(
                (
                    self._make_client(
                        client_account_key_path, f"client_{i}_{self.contact}"
                    ),
                    csr,
                )
            )

        await asyncio.gather(
            *[self._run_one(client, csr) for client, csr in clients_csr]
        )
        await asyncio.gather(*[client.close() for client, _ in clients_csr])

    async def test_revoke(self):
        full_chain = await self._run_one(self.client, self.client_data.csr)
        certs = acme_broker.util.pem_split(full_chain)
        await self.client.certificate_revoke(
            certs[0], reason=RevocationReason.keyCompromise
        )

    async def test_account_update(self):
        await self.client.start()

        new_contact = (
            "mailto:newmail@tib.eu",
            "woehler@luis.uni-hannover.de",
            "tel:555-1234",
        )
        await self.client.account_update(contact=new_contact)
        await self.client.account_lookup()
        self.assertEqual(self.client._account.contact, new_contact)

    async def test_email_validation(self):
        await self.client.start()

        new_contact = (
            "mailto:newmail@tib.de",
            "woehler@test.de",
            "tel:555-1234",
        )

        with self.assertRaises(acme.messages.Error):
            await self.client.account_update(contact=new_contact)

    async def test_unregister(self):
        await self.client.start()

        kid = self.client._account.kid
        self.client._account = None

        await self.client.account_lookup()

        self.assertEqual(self.client._account.kid, kid)

        await self.client.account_update(status=acme.messages.STATUS_DEACTIVATED)

        with self.assertRaises(acme.messages.Error):
            await self.client.order_create(self.domains)


class TestAcmetinyCA(TestAcmetiny, TestCA, unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        await super().test_run()


class TestCertBotCA(TestCertBot, TestCA, unittest.IsolatedAsyncioTestCase):
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
        await super().test_unregister()


class TestOurClientCA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
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

    async def test_email_validation(self):
        await super().test_email_validation()
