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
    ACCOUNT_KEY_ALG_BITS = ("RSA", 2048)
    CERT_KEY_ALG_BITS = ("RSA", 2048)

    @property
    def name(self):
        return type(self).__name__[4:]

    @property
    def config_sec(self):
        return NotImplementedError

    def _make_key(self, path, alg_and_bits):
        if alg_and_bits[0] == "RSA":
            return acme_broker.util.generate_rsa_key(path, alg_and_bits[1])
        elif alg_and_bits[0] == "EC":
            return acme_broker.util.generate_ec_key(path, alg_and_bits[1])


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

        self._make_key(client_account_key_path, self.ACCOUNT_KEY_ALG_BITS)
        client_cert_key = self._make_key(client_cert_key_path, self.CERT_KEY_ALG_BITS)

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

        await ca._db._recreate()

        self.runner = runner
        self.ca = ca

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
        import tests.acme_tiny.acme_tiny as at

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

class TestAcmetinyEC(TestAcmetiny):
    ACCOUNT_KEY_ALG_BITS = ("EC",256)
    CERT_KEY_ALG_BITS = ("EC",256)
    async def _run_acmetiny(self, cmd):
        import tests.acme_tiny_ec.acme_tiny as at

        argv = shlex.split(cmd)
        log.info(shlex.join(argv))
        r = await self.loop.run_in_executor(None, at.main, argv)
        return r

    async def test_run(self):
        import yarl
        ca = str(yarl.URL(self.DIRECTORY).with_path(''))
        await self._run_acmetiny(
            f"--directory-url {self.DIRECTORY} --disable-check --contact {self.contact} --account-key "
            f"{self.client_data.key_path} --csr {self.client_data.csr_path} "
            f"--acme-dir {self.path}/challenge"
        )



class TestDehydrated:
    @property
    def key_algo(self):
        return "rsa"

    def setUp(self) -> None:
        super().setUp()

        datadirs = ["domains_d", "accounts", "alpn-certs", "certs", "wellknown"]
        self._rmtree.extend(datadirs)
        for n in datadirs:
            if not (r := (self.path / n)).exists():
                r.mkdir()

        with open(str(self.path / "config"), "wt") as f:
            f.write(
                f"""
KEY_ALGO={self.key_algo}
CA={self.DIRECTORY}
CONTACT_EMAIL={self.contact}
IP_VERSION=4
CHALLENGETYPE="http-01"
#DOMAINS_D={str(self.path / 'domains_d')}
#BASEDIR=$SCRIPTDIR
#DOMAINS_TXT="${{BASEDIR}}/domains.txt"
#CERTDIR="${{BASEDIR}}/certs"
#ALPNCERTDIR="${{BASEDIR}}/alpn-certs"
#ACCOUNTDIR="${{BASEDIR}}/accounts"
WELLKNOWN="{str(self.path / 'wellknown')}"
"""
            )

    async def _run_dehydrated(self, _cmd):
        cmd = f"/tmp/dehydrated/dehydrated --config {self.path}/config {_cmd}"
        log.info(cmd)
        p = await asyncio.create_subprocess_exec(
            *shlex.split(cmd), stdout=asyncio.subprocess.PIPE
        )

        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip()
            logger(args)

        while r := await p.stdout.readline():
            llog(r, log.info)

    async def test_run(self):
        await self._run_dehydrated("--register --accept-terms")
        await self._run_dehydrated("--cron --force --domain test.de")


class Testacmesh:
    def setUp(self) -> None:
        super().setUp()
        path = self.path
        for n in ["run", "config", "www", "certs"]:
            if not (r := (path / n)).exists():
                r.mkdir()
        self._rmtree.extend(["www", "certs"])

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        if not (self.path / "run/acme.sh").exists():
            import os
            cwd = os.getcwd()
            os.chdir("/tmp/acme.sh")
            await self._run(
                f"./acme.sh  --no-color --log /dev/null --log-level 0 --home {cwd}/{self.path}/run --install --nocron --noprofile --accountkey {self.client_data.key_path}",
                prefix=False,
            )
            os.chdir(cwd)

    async def _run(self, _cmd, prefix=True):
        if prefix:
            cmd = (
                f"{self.path}/run/acme.sh --no-color --log /dev/null --log-level 0 --config-home {self.path}/config/ --cert-home {self.path}/certs --server {self.DIRECTORY} "
                + _cmd
            )
        else:
            cmd = _cmd
        log.info(cmd)
        p = await asyncio.create_subprocess_exec(
            *shlex.split(cmd), stdout=asyncio.subprocess.PIPE
        )

        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip().split("]", maxsplit=2)
            if len(args) == 2:
                logger(args[1])
            else:
                logger(_line)

        while r := await p.stdout.readline():
            llog(r, log.info)

    async def test_run(self):
        key, csr, path = self.client_data
        await self._run(f"""--register-account --accountemail {self.contact}""")
        domains = " ".join([f"--domain {d}" for d in acme_broker.util.names_of(csr)])
        await self._run(f"""--issue {domains} --webroot {self.path}/www/ --force""")


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

class TestOurClientStress(TestOurClient):
    async def test_run_stress(self):
        clients_csr = []  # (client, csr) tuples
        for i in range(10):
            self._make_key(client_account_key_path := self.path / f"client_{i}_account.key", self.ACCOUNT_KEY_ALG_BITS)
            client_cert_key = self._make_key(self.path / f"client_{i}_cert.key", self.CERT_KEY_ALG_BITS)

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
    pass


class TestAcmetinyECCA(TestAcmetinyEC, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestCertBotCA(TestCertBot, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestOurClientCA(TestOurClientStress, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestOurClientEC256EC256CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC384EC256CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 384)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC384EC256CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 384)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC521EC256CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 521)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC256EC384CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 384)


BAD_KEY_RE = r'urn:ietf:params:acme:error:badPublicKey :: The JWS was signed by a public key the server does not support :: \S+ Keysize for \w+ has to be \d+ <= public_key.key_size=\d+ <= \d+'


class TestOurClientEC256EC521CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 521)

    async def test_run(self):
        """"Let's Encrypt does not allow EC 521 Key Certificates due to lack of browser support"""
        with self.assertRaisesRegex(acme.messages.Error, BAD_KEY_RE):
            await super().test_run()


class TestOurClientRSA1024RSA2048CA(TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 1024)
    CERT_KEY_ALG_BITS = ("RSA", 2048)

    async def test_run(self):
        with self.assertRaisesRegex(acme.messages.Error, BAD_KEY_RE):
            await super().test_run()


class TestDehydratedCA(TestDehydrated, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestDehydratedECCA(TestDehydrated, TestCA, unittest.IsolatedAsyncioTestCase):
    CERT_KEY_ALG_BITS = ("EC", 384)

    @property
    def key_algo(self):
        return "secp384r1"


class TestacmeshCA(Testacmesh, TestCA, unittest.IsolatedAsyncioTestCase):
    pass
