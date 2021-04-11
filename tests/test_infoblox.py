import asyncio
import logging.config
import unittest
import uuid


from acmetk.plugins.infoblox_solver import InfobloxClient
from acmetk.main import load_config

log = logging.getLogger("acmetk.test_infoblox")


class TestInfobloxClient(unittest.IsolatedAsyncioTestCase):
    @property
    def name(self):
        return type(self).__name__[4:]

    def setUp(self) -> None:
        self.config = load_config("tests/conf/debug.yml")
        with open("tests/conf/infoblox", "r") as f:
            self.config["infoblox"]["password"] = f.read().strip()

    async def asyncSetUp(self) -> None:
        self.infoblox_client = InfobloxClient(**self.config["infoblox"])

    async def test_set_txt_record(self):
        test_name = self.config["infoblox_test"]["name"]
        text_value = uuid.uuid4().hex
        await self.infoblox_client.set_txt_record(test_name, text_value)

        # Poll the DNS until the correct record is available
        try:
            await asyncio.wait_for(
                self.infoblox_client._query_until_completed(test_name, text_value),
                60.0 * 5,
            )
        except asyncio.TimeoutError:
            self.fail("Could not verify that the TXT record was set")

    async def test_delete_txt_record(self):
        test_name = self.config["infoblox_test"]["name"]
        text_value = uuid.uuid4().hex
        await self.infoblox_client.set_txt_record(
            test_name, text_value, views=["Intern", "Extern"]
        )

        # Poll the DNS until the correct record is available
        try:
            await asyncio.wait_for(
                self.infoblox_client._query_until_completed(test_name, text_value),
                60.0 * 5,
            )
        except asyncio.TimeoutError:
            self.fail("Could not verify that the TXT record was set")

        await self.infoblox_client.delete_txt_record(test_name, text_value)
