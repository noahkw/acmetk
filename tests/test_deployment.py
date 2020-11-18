import unittest

from tests.test_ca import TestAcmetiny, TestAcme


class TestDeployment(TestAcme):
    """Tests for integrating with our CA over HTTPS"""

    DIRECTORY = "https://acmenoah.luis.uni-hannover.de/directory"

    @property
    def name(self):
        return type(self).__name__[4:]

    @property
    def config_sec(self):
        return self._config["tests"]["LocalCADeployment"]


class TestAcmetinyCADeployment(
    TestAcmetiny, TestDeployment, unittest.IsolatedAsyncioTestCase
):
    async def test_run(self):
        await super().test_run()
