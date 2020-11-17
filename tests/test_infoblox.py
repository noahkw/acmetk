import asyncio
import logging.config
import unittest
import uuid

import dns.resolver

from acme_broker.client import InfobloxClient
from acme_broker.main import load_config

log = logging.getLogger("acme_broker.test_infoblox")


class TestInfobloxClient(unittest.IsolatedAsyncioTestCase):
    @property
    def name(self):
        return type(self).__name__[4:]

    def setUp(self) -> None:
        self.config = load_config("../debug.yml")
        with open("../infoblox", "r") as f:
            self.config["infoblox"]["password"] = f.read().strip()

    async def asyncSetUp(self) -> None:
        self.infoblox_client = InfobloxClient(**self.config["infoblox"])
        await self.infoblox_client.connect()

    async def _query_txt_record(self, name):
        resp = await asyncio.get_event_loop().run_in_executor(
            None, dns.resolver.resolve, name, "TXT"
        )
        log.info(resp.response.answer)
        txt_record = list(resp.rrset.items.items())[0][0]
        return txt_record.strings[0].decode()

    async def test_set_txt_record(self):
        test_name = self.config["infoblox_test"]["name"]
        text_value = uuid.uuid4().hex
        await self.infoblox_client.set_txt_record(test_name, text_value)

        # with contextlib.suppress(dns.resolver.NXDOMAIN):

        tries = 10
        while tries > 0:
            if await self._query_txt_record(test_name) == text_value:
                break

            tries -= 1
            await asyncio.sleep(5)
        else:
            self.assertEqual(await self._query_txt_record(test_name), text_value)
