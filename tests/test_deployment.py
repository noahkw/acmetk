import asyncio
import unittest
from pathlib import Path

import trustme

from acme_broker import AcmeCA
from acme_broker.server import RequestIPDNSChallengeValidator
from tests.test_ca import TestAcmetiny, TestAcme, TestOurClient, TestCertBot


class TestDeployment(TestAcme):
    """Tests for integrating with our CA over HTTPS.

    These tests need to be executed within the supplied docker image
    to make use of Nginx' reverse proxy functionality.
    This is probably easiest to set up using PyCharm's built-in
    'docker-compose' remote interpreter."""

    DIRECTORY = "https://localhost/directory"

    @property
    def config_sec(self):
        return self._config["tests"]["LocalCADeployment"]

    def setUp(self) -> None:
        super().setUp()

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()

        # Create and place the self-signed certificate for openresty to use.
        fake_ca = trustme.CA()
        server_cert = fake_ca.issue_cert("127.0.0.1", "localhost")

        cert_path = Path(self.config_sec["client"]["server_cert"])

        first_in_chain = True
        for pem in server_cert.cert_chain_pems:
            pem.write_to_path(cert_path, append=not first_in_chain)
            first_in_chain = False

        fake_ca.cert_pem.write_to_path(cert_path, append=True)

        key_path = cert_path.parent / "resty-auto-ssl-fallback.key"
        server_cert.private_key_pem.write_to_path(key_path)

        # The environment variable is set to the server cert so that the requests module uses it (certbot).
        import os

        os.environ["REQUESTS_CA_BUNDLE"] = self.config_sec["client"]["server_cert"]

        # Disable SSL verification for urllib3 (acmetiny).
        import ssl

        ssl._create_default_https_context = ssl._create_unverified_context

        # Disable resty-auto-ssl
        with open("/usr/local/bin/resty-auto-ssl/dehydrated", "w") as f:
            f.write("echo 1;")

        self.nginx_proc = await asyncio.create_subprocess_shell(
            '/usr/local/openresty/nginx/sbin/nginx -g "daemon off; master_process on;"',
            None,
            None,
        )

        runner, ca = await AcmeCA.runner(self.config_sec["ca"])
        ca.register_challenge_validator(RequestIPDNSChallengeValidator())

        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()
        self.nginx_proc.kill()


class TestAcmetinyCADeployment(
    TestAcmetiny, TestDeployment, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()


class TestCertBotCADeployment(
    TestCertBot, TestDeployment, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()

    async def test_subdomain_revocation(self):
        # localhost can't have subdomains.
        pass

    async def test_skey_revocation(self):
        await super().test_skey_revocation()

    async def test_renewal(self):
        await super().test_renewal()

    async def test_register(self):
        await super().test_register()

    async def test_unregister(self):
        await super().test_unregister()


class TestOurClientCADeployment(
    TestOurClient, TestDeployment, unittest.IsolatedAsyncioTestCase
):
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
