import asyncio
import collections
import logging
import logging.config
import shlex
import shutil
import unittest
from pathlib import Path

import acme.messages

import acmetk.util
from acmetk import AcmeCA
from acmetk.client import (
    AcmeClient,
    DummySolver,
)
from acmetk.main import load_config
from acmetk.models.messages import RevocationReason
from acmetk.server import DummyValidator

log = logging.getLogger("acmetk.test_ca")

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
            return acmetk.util.generate_rsa_key(path, alg_and_bits[1])
        elif alg_and_bits[0] == "EC":
            return acmetk.util.generate_ec_key(path, alg_and_bits[1])

    @property
    def names(self):
        return self.config_sec["names"]

    def setUp(self) -> None:
        """Sets up our test object with the necessary properties for testing using a client"""
        self._config = load_config("../debug.yml")
        self.log = logging.getLogger(f"acmetk.tests.{self.name}")
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

        csr = acmetk.util.generate_csr(
            self.names[0],
            client_cert_key,
            csr_path,
            names=self.names,
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

        acmetk.util.generate_root_cert(
            ca_key_path, "DE", "Lower Saxony", "Hanover", "Acme Toolkit", "ACMETK CA"
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


# disabled - ES signature format is asn1 not r || s
# class TestAcmetinyEC(TestAcmetiny):
#     ACCOUNT_KEY_ALG_BITS = ("EC", 256)
#     CERT_KEY_ALG_BITS = ("EC", 256)
#
#     async def _run_acmetiny(self, cmd):
#         import tests.acme_tiny.acme_tiny_ec as at
#
#         argv = shlex.split(cmd)
#         log.info(shlex.join(argv))
#         r = await self.loop.run_in_executor(None, at.main, argv)
#         return r


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
                f"./acme.sh  --no-color --log /dev/null --log-level 0 "
                f"--home {cwd}/{self.path}/run "
                f"--install --nocron --noprofile --accountkey {self.client_data.key_path}",
                prefix=False,
            )
            os.chdir(cwd)

    async def _run(self, _cmd, prefix=True):
        if prefix:
            cmd = (
                f"{self.path}/run/acme.sh --no-color --log /dev/null --log-level 0 "
                f"--config-home {self.path}/config/ "
                f"--cert-home {self.path}/certs --server {self.DIRECTORY} " + _cmd
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
        domains = " ".join([f"--domain {d}" for d in acmetk.util.names_of(csr)])
        await self._run(f"""--issue {domains} --webroot {self.path}/www/ --force""")


class TestCertBot:
    def setUp(self) -> None:
        super().setUp()

        self._rmtree.extend(["archive", "renewal", "live"])
        self._rmtree.extend(["etc"])

        self.domains = sorted(
            map(lambda x: x.lower(), acmetk.util.names_of(self.client_data.csr)),
            key=lambda s: s[::-1],
        )

    @property
    def key_args(self):
        if self.CERT_KEY_ALG_BITS[0] == "RSA":
            return "--key-type rsa"
        elif self.CERT_KEY_ALG_BITS[0] == "EC":
            return (
                f"--key-type ecdsa --elliptic-curve secp{self.CERT_KEY_ALG_BITS[1]}r1"
            )

    async def _register(self):
        await self._run(f"register --no-eff-email --agree-tos  -m {self.contact}")

    async def _certonly(self, *argv, names=None, preferred_challenges="dns"):
        authhook = "\t" + "\n\t".join(
            map(
                lambda s: f"CERTBOT_{s}=$CERTBOT_{s}",
                [
                    "DOMAIN",
                    "VALIDATION",
                    "TOKEN",
                    "REMAINING_CHALLENGES",
                    "ALL_DOMAINS",
                ],
            )
        )

        domains = " --domain ".join(names or self.domains)
        extra = " ".join(argv) if argv else ""
        await self._run(
            f"certonly {self.key_args} --manual "
            f'--manual-auth-hook "echo \\"{authhook}\\"" '
            f"--manual-cleanup-hook /bin/true --preferred-challenges {preferred_challenges} --domain {domains} {extra}"
        )

    async def _run(self, cmd):
        argv = shlex.split(
            f"--non-interactive "
            f"--work-dir {self._config['certbot']['workdir']} "
            f"--logs-dir {self._config['certbot']['workdir']}/logs "
            f"--config-dir ./{self.path}/etc/letsencrypt "
            f"--server {self.DIRECTORY} " + cmd
        )
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

        log.info("certbot %s" % (" ".join(argv),))
        r = await self.loop.run_in_executor(None, cbm.main, argv)
        return r

    async def test_run(self):
        await self._run("certificates")
        await self._register()
        await self._certonly()

    async def test_subdomain_revocation(self):
        await self._register()

        await self._certonly()

        await self._certonly(
            "--expand", names=list(map(lambda s: f"dns.{s}", self.domains))
        )
        await self._certonly(
            "--expand", names=list(map(lambda s: f"http.{s}", self.domains))
        )

        for j in ["", "dns.", "http."]:
            try:
                await self._run(
                    f"revoke --cert-path {self.path}/etc/letsencrypt/live/{j}{self.domains[0]}/cert.pem"
                )
            except Exception as e:
                log.exception(e)

    async def test_skey_revocation(self):
        await self._register()

        await self._certonly()

        domain = self.domains[0].lstrip("*.")
        await self._run(
            f"revoke --cert-path {self.path}/etc/letsencrypt/live/{domain}/cert.pem "
            f"--key-path {self.path}/etc/letsencrypt/live/{domain}/privkey.pem"
        )

    async def test_renewal(self):
        await self._register()
        await self._certonly()

        await self._run(
            f"renew --no-random-sleep-on-renew --webroot --webroot-path {self.path}"
        )

    async def test_register(self):
        await self._register()

    async def test_unregister(self):
        try:
            await self._run("unregister --agree-tos")
        except Exception:
            pass
        await self.test_register()
        await self._run("unregister --agree-tos")

    async def test_bad_identifier(self):
        await self._register()
        for err, names in {
            r"Domain name contains an invalid character": [
                "the_test.de",
                "{invalid}",
                "test.-de",
            ],
            r"Domain name contains malformed punycode": ["xn--test.de"],
            r"Domain name does not end with a valid public suffix \(TLD\)": ["test.11"],
        }.items():
            for i in names:
                with self.assertRaisesRegex(
                    acme.messages.Error,
                    r"urn:ietf:params:acme:error:rejectedIdentifier :: "
                    r"The server will not issue certificates for the identifier :: "
                    + err,
                ):
                    await self._certonly(names=[i])


class TestOurClient:
    BAD_KEY_RE = (
        r"urn:ietf:params:acme:error:badPublicKey :: "
        r"The JWS was signed by a public key the server does not support :: "
        r"(?P<alg>\S+) Keysize for (?P<action>\w+) has to be \d+ <= public_key.key_size=(?P<bits>\d+) <= \d+"
    )

    def assertBadKey(self, e, action, key_params=None):
        if key_params:
            alg, bits = key_params
        else:
            if action == "account":
                alg, bits = self.ACCOUNT_KEY_ALG_BITS
            else:
                alg, bits = self.CERT_KEY_ALG_BITS

        alg = {"RSA": "_RSAPublicKey", "EC": "_EllipticCurvePublicKey"}[alg]
        bits = str(bits)

        m = e.expected_regex.match(str(e.exception)).groupdict()
        for k, v in {"alg": alg, "action": action, "bits": bits}.items():
            self.assertEqual(v, m[k])

    def setUp(self) -> None:
        super().setUp()

        self.domains = sorted(
            map(lambda x: x.lower(), acmetk.util.names_of(self.client_data.csr)),
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
        try:
            self.ca._match_keysize(
                client._private_key.key._wrapped.public_key(), "account"
            )
        except ValueError:
            with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
                await client.start()
            self.assertBadKey(e, "account")
            return
        else:
            await client.start()

        domains = sorted(
            map(lambda x: x.lower(), acmetk.util.names_of(csr)),
            key=lambda s: s[::-1],
        )

        ord = await client.order_create(domains)
        await client.authorizations_complete(ord)

        try:
            self.ca._match_keysize(csr.public_key(), "csr")
        except ValueError:
            with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
                await client.order_finalize(ord, csr)
            self.assertBadKey(e, "csr")
            return
        else:
            finalized = await client.order_finalize(ord, csr)
            return await client.certificate_get(finalized)

    async def test_run(self):
        await self._run_one(self.client, self.client_data.csr)

    async def test_keychange(self):
        try:
            self.ca._match_keysize(
                self.client._private_key.key._wrapped.public_key(), "account"
            )
        except ValueError:
            with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
                await self.client.start()
            self.assertBadKey(e, "account")
            return
        else:
            await self.client.start()

        with self.assertRaisesRegex(
            acme.messages.Error, "The KeyChange object key already in use"
        ):
            await self.client.key_change(self.client_data.key_path)

        kp = self.client_data.key_path.parent / "keychange.key"
        self._make_key(kp, self.ACCOUNT_KEY_ALG_BITS)

        await self.client.key_change(kp)
        await self._run_one(self.client, self.client_data.csr)

        await self.client.key_change(self.client_data.key_path)
        await self._run_one(self.client, self.client_data.csr)

        sk = self.client_data.key_path.parent / "keychange.key"
        KEY_PARAMS = ("RSA", 1024)
        self._make_key(sk, KEY_PARAMS)
        with self.assertRaisesRegex(acme.messages.Error, self.BAD_KEY_RE) as e:
            await self.client.key_change(sk)
        self.assertBadKey(e, "account", KEY_PARAMS)

        self._make_key(sk, ("EC", 256))
        await self.client.key_change(sk)

        self._make_key(sk, ("EC", 384))
        await self.client.key_change(sk)

        self._make_key(sk, ("EC", 521))
        await self.client.key_change(sk)

        await self.client.key_change(self.client_data.key_path)


class TestOurClientStress(TestOurClient):
    async def test_run_stress(self):
        clients_csr = []  # (client, csr) tuples
        for i in range(10):
            self._make_key(
                client_account_key_path := self.path / f"client_{i}_account.key",
                self.ACCOUNT_KEY_ALG_BITS,
            )
            client_cert_key = self._make_key(
                self.path / f"client_{i}_cert.key", self.CERT_KEY_ALG_BITS
            )

            csr = acmetk.util.generate_csr(
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
        certs = acmetk.util.pem_split(full_chain)
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
        self.assertEqual(new_contact, self.client._account.contact)

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


# class TestAcmetinyECCA(TestAcmetinyEC, TestCA, unittest.IsolatedAsyncioTestCase):
#    pass


class TestCertBotCA(TestCertBot, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestCertBotWCCA(TestCertBot, TestCA, unittest.IsolatedAsyncioTestCase):
    @property
    def names(self):
        return ["*.test.de"]

    async def test_subdomain_revocation(self):
        "avoid Requesting a certificate for dns.*.test.de"
        pass

    async def test_run(self):
        await super().test_run()

    async def test_no_wc_run(self):
        self.ca._allow_wildcard = False
        with self.assertRaisesRegex(
            acme.messages.Error, "The ACME server can not issue a wildcard certificate"
        ):
            await super().test_run()


class TestCertBotRSA2048EC256CA(TestCertBot, TestCA, unittest.IsolatedAsyncioTestCase):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 2048)
    CERT_KEY_ALG_BITS = ("EC", 256)

    async def test_skey_revocation(self):
        # certbot 1.10.1 can do ec certificates but can not skey revoke them
        with self.assertRaises(AssertionError):
            await super().test_skey_revocation()


class TestOurClientCA(TestOurClientStress, TestCA, unittest.IsolatedAsyncioTestCase):
    async def test_revoke(self):
        await super().test_revoke()

    async def test_keychange(self):
        await super().test_keychange()


class TestOurClientEC256EC256CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC384EC256CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 384)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC521EC256CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 521)
    CERT_KEY_ALG_BITS = ("EC", 256)


class TestOurClientEC256EC384CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 384)


class TestOurClientEC256EC521CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("EC", 256)
    CERT_KEY_ALG_BITS = ("EC", 521)

    """"Let's Encrypt does not allow EC 521 Key Certificates due to lack of browser support"""

    def test_validate_key(self):
        self.ca._match_keysize(
            self.client._private_key.key._wrapped.public_key(), "account"
        )

        with self.assertRaises(ValueError):
            self.ca._match_keysize(self.client_data.csr.public_key(), "csr")


class TestOurClientRSA1024RSA2048CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 1024)
    CERT_KEY_ALG_BITS = ("RSA", 2048)

    def test_validate_key(self):
        with self.assertRaises(ValueError):
            self.ca._match_keysize(
                self.client._private_key.key._wrapped.public_key(), "account"
            )

        self.ca._match_keysize(self.client_data.csr.public_key(), "csr")


class TestOurClientRSA2048RSA1024CA(
    TestOurClient, TestCA, unittest.IsolatedAsyncioTestCase
):
    ACCOUNT_KEY_ALG_BITS = ("RSA", 2048)
    CERT_KEY_ALG_BITS = ("RSA", 1024)

    def test_validate_key(self):
        self.ca._match_keysize(
            self.client._private_key.key._wrapped.public_key(), "account"
        )

        with self.assertRaises(ValueError):
            self.ca._match_keysize(self.client_data.csr.public_key(), "csr")


class TestDehydratedCA(TestDehydrated, TestCA, unittest.IsolatedAsyncioTestCase):
    pass


class TestDehydratedECCA(TestDehydrated, TestCA, unittest.IsolatedAsyncioTestCase):
    CERT_KEY_ALG_BITS = ("EC", 384)

    @property
    def key_algo(self):
        return "secp384r1"


class TestacmeshCA(Testacmesh, TestCA, unittest.IsolatedAsyncioTestCase):
    pass
