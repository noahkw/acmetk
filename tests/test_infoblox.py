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


class TestInfobloxClient:
    @property
    def name(self):
        return type(self).__name__[4:]

    @property
    def config_section(self):
        raise NotImplementedError

    def setUp(self) -> None:
        self.config = load_config("../debug.yml")
        with open("../infoblox", "r") as f:
            self.config["infoblox"]["password"] = f.read().strip()

        dir_ = Path("./tmp") / self.name
        if not dir_.exists():
            dir_.mkdir(parents=True)

        self.path = dir_
        self.account_key_path = (
            dir_ / self.config[self.config_section]["client"]["private_key"]
        )

        if not self.account_key_path.exists():
            acme_broker.util.generate_rsa_key(self.account_key_path)

    async def asyncSetUp(self) -> None:
        self.infoblox_client = InfobloxClient(**self.config["infoblox"])
        await self.infoblox_client.connect()

        self.client = AcmeClient(
            directory_url=self.config[self.config_section]["client"]["directory_url"],
            private_key=self.account_key_path,
            contact=self.config[self.config_section]["client"]["contact"],
        )

        self.client.register_challenge_solver(
            (ChallengeSolverType.DNS_01,),
            self.infoblox_client,
        )

        await self.client.start()

    async def asyncTearDown(self):
        await self.client.close()

    async def test_cert_acquisition(self):
        client_cert_key = acme_broker.util.generate_rsa_key(
            self.path / "client_cert.key"
        )

        csr = acme_broker.util.generate_csr(
            self.config[self.config_section]["domain_name"],
            client_cert_key,
            self.path / "client.csr",
            names=[self.config[self.config_section]["domain_name"]],
        )

        domains = sorted(
            map(lambda x: x.lower(), acme_broker.util.names_of(csr)),
            key=lambda s: s[::-1],
        )

        ord = await self.client.order_create(domains)
        await self.client.authorizations_complete(ord)
        finalized = await self.client.order_finalize(ord, csr)
        return await self.client.certificate_get(finalized)


class TestInfobloxClientLE(TestInfobloxClient, unittest.IsolatedAsyncioTestCase):
    @property
    def config_section(self):
        return "infoblox_test"

    async def _query_txt_record(self, name):
        resp = await asyncio.get_event_loop().run_in_executor(
            None, dns.resolver.resolve, name, "TXT"
        )
        log.info(resp.response.answer)
        txt_record = list(resp.rrset.items.items())[0][0]
        return txt_record.strings[0].decode()

    async def test_set_txt_record(self):
        test_name = self.config[self.config_section]["name"]
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


class TestInfobloxClientBoulder(TestInfobloxClient, unittest.IsolatedAsyncioTestCase):
    @property
    def config_section(self):
        return "boulder_test"

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.client.ssl = False

    async def test_cert_acquisition(self):
        await super().test_cert_acquisition()
