import asyncio
import ipaddress
import logging.config
import shlex
import re
from pathlib import Path
import typing

import cryptography.hazmat.primitives.serialization
import pytest

import acme.messages
import acmetk.util

BAD_KEY_RE = (
    r"urn:ietf:params:acme:error:badPublicKey :: "
    r"The JWS was signed by a public key the server does not support :: "
    r"(?P<alg>\S+) Keysize for (?P<action>\w+) has to be \d+ <= public_key.key_size=(?P<bits>\d+) <= \d+"
)


def assertBadKey(exc, action, key):
    alg = key.__class__.__name__
    bits = str(key.key_size)

    m = re.match(BAD_KEY_RE, str(exc.value)).groupdict()
    for k, v in {"alg": alg, "action": action, "bits": bits}.items():
        assert v == m[k]


class TestClient:
    DIRECTORY: str
    path: str

    def __init__(self, account_key, service, directory, tmpdir):
        self.ACCOUNT_KEY = account_key
        self.service = service
        self.DIRECTORY = directory
        self.tmpdir = tmpdir
        self.log = logging.getLogger(self.__class__.__qualname__)
        self.contact = f"{self.__class__.__name__}@acmetk.example.org"

        client_account_key_path = self.tmpdir / "account-key.pem"
        self._make_key(client_account_key_path, self.ACCOUNT_KEY)
        assert client_account_key_path.exists()

    @property
    def key(self):
        return cryptography.hazmat.primitives.serialization.load_pem_private_key(
            (self.tmpdir / "account-key.pem").read_bytes(), password=None
        )

    def domains_of_csr(self, csr) -> list[str]:
        domains = sorted(
            map(lambda x: x.lower(), acmetk.util.names_of(csr)),
            key=lambda s: s[::-1],
        )
        return domains

    def identifiers_from_names(self, names):
        identifiers = list()
        for name in names:
            try:
                ipaddress.ip_address(name)
                identifiers.append({"type": "ip", "value": name})
            except ValueError:
                identifiers.append({"type": "dns", "value": name})
        return identifiers

    def _make_key(self, path, alg_and_bits):
        if alg_and_bits[0] == "RSA":
            return acmetk.util.generate_rsa_key(path, alg_and_bits[1])
        elif alg_and_bits[0] == "EC":
            return acmetk.util.generate_ec_key(path, alg_and_bits[1])

    async def close(self):
        pass

    async def register(self):
        try:
            self.service.ca._match_keysize(self.key.public_key(), "account")
        except ValueError:
            with pytest.raises(Exception):
                await self._register()
            return False
        return await self._register()

    async def _register(self):
        raise NotImplementedError()

    async def order(self, csr, profile: typing.Union[str, None] = None):
        try:
            self.service.ca._match_keysize(csr.public_key(), "csr")
        except ValueError:
            with pytest.raises(acme.messages.Error, match=BAD_KEY_RE) as e:
                await self._order(csr)
            assertBadKey(e, "csr", csr.public_key())
            return False

        await self._order(csr, profile)
        return True

    async def _order(self, csr, profile: typing.Union[str, None] = None):
        raise NotImplementedError()


class certbotClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)

        import warnings

        warnings.simplefilter("ignore", category=DeprecationWarning)
        self.loop = asyncio.get_running_loop()

    def _csr_key_args(self, csr):
        import cryptography.hazmat.primitives.asymmetric.rsa
        import cryptography.hazmat.primitives.asymmetric.ec

        if isinstance(
            (p := csr.public_key()),
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
        ):
            return "--key-type rsa"
        elif isinstance(
            p,
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization,
        ):
            return f"--key-type ecdsa --elliptic-curve secp{p.key_size}r1"

    async def _register(self):
        await self._run(f"register --no-eff-email --agree-tos  -m {self.contact}")
        return True

    async def _order(self, csr):
        await self._certonly(csr)
        return True

    async def _certonly(self, csr, *argv, preferred_challenges="dns"):
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

        domains = " --domain ".join(self.domains_of_csr(csr))
        extra = " ".join(argv) if argv else ""
        await self._run(
            f"certonly {self._csr_key_args(csr)} --manual "
            f'--manual-auth-hook "echo \\"{authhook}\\"" '
            f"--manual-cleanup-hook /bin/true --preferred-challenges {preferred_challenges} --domain {domains} {extra}"
        )

    async def _run(self, cmd):
        argv = shlex.split(
            f"--non-interactive "
            f"--work-dir {self.tmpdir / 'var' / 'run'} "
            f"--logs-dir {self.tmpdir / 'var' / 'logs'} "
            f"--config-dir {self.tmpdir / 'etc' / 'letsencrypt'} "
            f"--server {self.DIRECTORY} " + cmd
        )
        import certbot._internal.main as cbm
        import certbot.util
        import certbot._internal.log
        import certbot._internal.error_handler

        certbot.util.atexit_register = lambda func, *argv, **kwargs: self.log.info(
            f"patched certbot.util.atexit_register for {func}"
        )
        certbot._internal.error_handler.ErrorHandler._set_signal_handlers = lambda x: self.log.info(
            "patched certbot._internal.error_handler.ErrorHandler._set_signal_handlers"
        )
        certbot._internal.log.pre_arg_parse_setup = lambda: self.log.info(
            "patched certbot._internal.log.pre_arg_parse_setup"
        )
        certbot._internal.log.post_arg_parse_setup = lambda x: self.log.info(
            "patched certbot._internal.log.post_arg_parse_setup"
        )

        self.log.info("certbot {}".format(" ".join(argv)))
        r = await self.loop.run_in_executor(None, cbm.main, argv)
        self.log.info(f"result {r}")
        return r

    async def test_run(self):
        await self._run("certificates")
        await self._register()
        await self._certonly()

    async def test_subdomain_revocation(self):
        await self._register()

        await self._certonly()

        await self._certonly("--expand", names=list(map(lambda s: f"dns.{s}", self.domains)))
        await self._certonly("--expand", names=list(map(lambda s: f"http.{s}", self.domains)))

        for j in ["", "dns.", "http."]:
            try:
                await self._run(f"revoke --cert-path {self.path}/etc/letsencrypt/live/{j}{self.domains[0]}/cert.pem")
            except Exception as e:
                print(e)

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

        await self._run(f"renew --no-random-sleep-on-renew --webroot --webroot-path {self.path}")

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
                    r"The server will not issue certificates for the identifier :: " + err,
                ):
                    await self._certonly(names=[i])


class acmetkClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)
        self.client = self._make_client(self.tmpdir / "account-key.pem", "acmetk@acmetk.example.org")

    def _make_client(self, key_path, email):
        from acmetk import AcmeClient
        from acmetk.client import DummySolver

        client = AcmeClient(
            directory_url=self.DIRECTORY,
            private_key=key_path,
            contact={"email": email},
            server_cert=None,
        )

        client.register_challenge_solver(DummySolver())

        return client

    async def _register(self):
        await self.client.start()
        return True

    async def _order(self, csr, profile: typing.Union[str, None] = None):
        domains = self.domains_of_csr(csr)
        identifiers = self.identifiers_from_names(domains)
        ord_ = await self.client.order_create(identifiers, profile=profile)
        await self.client.authorizations_complete(ord_)
        await self.client.order_finalize(ord_, csr)
        return True


class acmezClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)
        self.bin = str(Path("/tmp/acmez/examples/porcelain/porcelain"))

    async def _run(self):
        cmd = self.bin
        self.log.info(cmd)
        p = await asyncio.create_subprocess_exec(*shlex.split(cmd), stdout=asyncio.subprocess.PIPE)

        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip().split("]", maxsplit=2)
            if len(args) == 2:
                logger(args[1])
            else:
                logger(_line)

        while r := await p.stdout.readline():
            llog(r, self.log.info)

    async def register(self):
        return True

    async def order(self, csr):
        self._run()


class acmetinyClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)
        for i in ["challenge"]:
            (self.tmpdir / i).mkdir()

    async def _run_acmetiny(self, cmd):
        import tests.acme_tiny.acme_tiny as at

        argv = shlex.split(cmd)
        self.log.info(shlex.join(argv))
        r = await asyncio.get_running_loop().run_in_executor(None, at.main, argv)
        return r

    async def register(self):
        return True

    async def order(self, csr):
        try:
            self.service.ca._match_keysize(csr.public_key(), "csr")
        except ValueError:
            with pytest.raises(ValueError):
                await self._order(csr)
            #            assertBadKey(e, "csr", csr.public_key())
            return False

        await self._order(csr)
        return True

    async def _order(self, csr):
        await self._run_acmetiny(
            f"--directory-url {self.DIRECTORY} --disable-check --contact {self.contact} --account-key "
            f"{self.tmpdir / 'account-key.pem'} --csr {self.tmpdir / 'csr.pem'} "
            f"--acme-dir {self.tmpdir}/challenge"
        )
        return True


class dehydratedClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)
        (self.tmpdir / "wellknown").mkdir()

        (self.tmpdir / "config").write_text(
            f"""
KEY_ALGO=rsa
CA={self.DIRECTORY}
CONTACT_EMAIL={self.contact}
IP_VERSION=4
CHALLENGETYPE="http-01"
#DOMAINS_D={str(self.tmpdir / 'domains_d')}
#BASEDIR=$SCRIPTDIR
#DOMAINS_TXT="${{BASEDIR}}/domains.txt"
#CERTDIR="${{BASEDIR}}/certs"
#ALPNCERTDIR="${{BASEDIR}}/alpn-certs"
#ACCOUNTDIR="${{BASEDIR}}/accounts"
WELLKNOWN="{str(self.tmpdir / 'wellknown')}"
"""
        )

    async def _run_dehydrated(self, _cmd):
        cmd = f"/tmp/dehydrated/dehydrated --config {self.tmpdir}/config {_cmd}"
        self.log.info(cmd)
        p = await asyncio.create_subprocess_exec(*shlex.split(cmd), stdout=asyncio.subprocess.PIPE)

        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip()
            logger(args)

        while r := await p.stdout.readline():
            llog(r, self.log.info)

    async def register(self):
        await self._run_dehydrated("--register --accept-terms")

    async def order(self, csr):
        names = acmetk.util.names_of(csr)
        (domains := self.tmpdir / "domains.txt").write_text("\n".join(names))
        await self._run_dehydrated(f"--cron --force  --domains-txt {domains}")


class acmeshClient(TestClient):
    def __init__(self, account_key, service, directory, tmpdir):
        super().__init__(account_key, service, directory, tmpdir)
        for i in ["config", "certs", "run", "www"]:
            (self.tmpdir / i).mkdir()

    async def _bootstrap(self):
        if not (self.tmpdir / "run/acme.sh").exists():
            import os

            cwd = os.getcwd()
            os.chdir("/tmp/acme.sh")
            await self._run_exec(
                f"./acme.sh  --no-color --log /dev/null --log-level 0 "
                f"--home {self.tmpdir}/run "
                f"--install --nocron --noprofile --accountkey {self.tmpdir / 'client_key.pem'}",
            )
            os.chdir(cwd)

    async def _run(self, _cmd):
        cmd = (
            f"{self.tmpdir}/run/acme.sh --no-color --log /dev/null --log-level 0 "
            f"--config-home {self.tmpdir}/config "
            f"--cert-home {self.tmpdir}/certs --server {self.DIRECTORY} " + _cmd
        )
        self.log.info(cmd)
        await self._bootstrap()
        await self._run_exec(cmd)

    async def _run_exec(self, cmd):
        p = await asyncio.create_subprocess_exec(*shlex.split(cmd), stdout=asyncio.subprocess.PIPE)

        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip().split("]", maxsplit=2)
            if len(args) == 2:
                logger(args[1])
            else:
                logger(_line)

        while r := await p.stdout.readline():
            llog(r, self.log.info)

    async def register(self):
        await self._run(f"""--register-account --accountemail {self.contact}""")
        return True

    async def order(self, csr):
        await self.register()
        domains = " ".join([f"--domain {d}" for d in acmetk.util.names_of(csr)])
        await self._run(f"""--issue {domains} --webroot {self.tmpdir}/www/ --force""")
        return True
