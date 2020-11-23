import functools
import subprocess
import unittest

from acme_broker import AcmeCA
from acme_broker.server import RequestIPDNSChallengeValidator
from tests.test_ca import TestAcmetiny, TestAcme, TestOurClient


class TestDeployment(TestAcme):
    """Tests for integrating with our CA over HTTPS.

    These tests need to be executed within the supplied docker image
    to make use of Nginx' reverse proxy functionality.
    This is probably easiest to set up using PyCharm's built-in
    'docker-compose' remote interpreter."""

    DIRECTORY = "https://127.0.0.1:443/directory"

    @property
    def config_sec(self):
        return self._config["tests"]["LocalCADeployment"]

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()

        self.loop.run_in_executor(
            None,
            functools.partial(
                subprocess.call, '/usr/sbin/nginx -g "daemon off;"', shell=True
            ),
        )
        runner, ca = await AcmeCA.unix_socket(self.config_sec["ca"], "/tmp/app_1.sock")
        ca.register_challenge_validator(RequestIPDNSChallengeValidator())

        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()


class TestAcmetinyCADeployment(
    TestAcmetiny, TestDeployment, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()


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
