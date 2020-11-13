import asyncio
import logging.config
import unittest
import uuid
from pathlib import Path

import dns.resolver

import acme_broker.util
from acme_broker.client import InfobloxClient, AcmeClient
from acme_broker.client.client import ChallengeSolverType
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

        self.test_name = self.config["infoblox_test"]["name"]

        dir_ = Path("./tmp") / self.name
        if not dir_.exists():
            dir_.mkdir(parents=True)

        self.path = dir_

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
        text_value = uuid.uuid4().hex
        await self.infoblox_client.set_txt_record(self.test_name, text_value)

        # with contextlib.suppress(dns.resolver.NXDOMAIN):

        tries = 10
        while tries > 0:
            if await self._query_txt_record(self.test_name) == text_value:
                break

            tries -= 1
            await asyncio.sleep(5)
        else:
            self.assertEqual(await self._query_txt_record(self.test_name), text_value)

    async def test_cert_acquisition(self):
        client_account_key_path = self.path / "client_account.key"
        acme_broker.util.generate_rsa_key(client_account_key_path)

        client_cert_key = acme_broker.util.generate_rsa_key(
            self.path / "client_cert.key"
        )

        csr = acme_broker.util.generate_csr(
            self.config["infoblox_test"]["le_name"],
            client_cert_key,
            self.path / "client.csr",
            names=[self.config["infoblox_test"]["le_name"]],
        )

        client = AcmeClient(
            directory_url=self.config["infoblox_test"]["client"]["directory"],
            private_key=self.path / "client_cert.key",
            contact=self.config["infoblox_test"]["client"]["contact"],
        )

        client.register_challenge_solver(
            (ChallengeSolverType.DNS_01,),
            self.infoblox_client,
        )

        await client.start()

        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(csr)),
            key=lambda s: s[::-1],
        )

        ord = await client.order_create(domains)
        await client.authorizations_complete(ord)
        finalized = await client.order_finalize(ord, csr)
        return await client.certificate_get(finalized)
