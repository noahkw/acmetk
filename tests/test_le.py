import logging
import unittest
import logging.config

import acme.messages

import acmetk.util
from acmetk.client import (
    AcmeClient,
    DummySolver,
)

from tests.test_ca import TestAcme

log = logging.getLogger("acmetk.test_le")


class TestLE(TestAcme, unittest.IsolatedAsyncioTestCase):
    DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

    @property
    def names(self):
        return [f"{i}.test.de" for i in range(5)]

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
            #            server_cert=self.config_sec.get("client", {}).get("server_cert", None),
        )

        client.register_challenge_solver(DummySolver())

        return client

    async def asyncSetUp(self) -> None:
        self.client = self._make_client(self.client_data.key_path, self.contact)

    async def asyncTearDown(self) -> None:
        await self.client.close()

    async def _run_one(self, client, csr):
        await client.start()

        domains = sorted(
            map(lambda x: x.lower(), acmetk.util.names_of(csr)),
            key=lambda s: s[::-1],
        )

        ord = await client.order_create(domains)
        await client.authorizations_complete(ord)

        await client.order_finalize(ord, csr)
        finalized = await client.order_finalize(ord, csr)
        return await client.certificate_get(finalized)

    async def _test_run(self):
        "disabled - no way to validate"
        await self._run_one(self.client, self.client_data.csr)

    async def test_ec_account(self):
        await self.client.close()
        self._make_key(self.client_data.key_path, ("EC", 256))
        self.client = self._make_client(self.client_data.key_path, self.contact)
        await self.client.start()

    async def test_keychange(self):
        await self.client.start()

        with self.assertRaisesRegex(
            acme.messages.Error,
            "New key specified by rollover request is the same as the old key",
        ) as e:
            await self.client.key_change(self.client_data.key_path)

        kp = self.client_data.key_path.parent / "keychange.key"

        self._make_key(kp, self.ACCOUNT_KEY_ALG_BITS)
        await self.client.key_change(kp)

        self._make_key(kp, ("RSA", 1024))
        with self.assertRaises(acme.messages.Error) as e:
            await self.client.key_change(kp)
        assert e.exception.detail in [
            "key size not supported: 1024",
            "JWS verification error",
        ], e.exception.detail

        self._make_key(kp, ("RSA", 1024 * 8))
        with self.assertRaises(acme.messages.Error) as e:
            await self.client.key_change(kp)
        assert e.exception.detail in ["key size not supported: 8192"], e.exception.detail

        self._make_key(kp, ("EC", 256))
        await self.client.key_change(kp)

        self._make_key(kp, ("EC", 384))
        await self.client.key_change(kp)

        self._make_key(kp, ("EC", 521))
        with self.assertRaisesRegex(
            acme.messages.Error,
            "(ECDSA curve P-521 not allowed)",
        ) as e:
            await self.client.key_change(kp)
        print(e.exception)


# disabled - ES signature format is asn1 not r || s
# class TestLEATEC(TestAcmetinyEC, TestAcme, unittest.IsolatedAsyncioTestCase):
#     DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
#     @property
#     def names(self):
#         return [f"{i}.test.de" for i in range(5)]
#
#     def setUp(self):
#         super().setUp()
#
#     async def test_run(self):
#         key_path = self.client_data.key_path.parent / "keychange.key"
# #        self._make_key(key_path, ("RSA", 1024*2))
#         self._make_key(key_path, ("EC", 256))
#         await self._run_acmetiny(
#             f"--directory-url {self.DIRECTORY} --disable-check --contact mailto:{self.contact} --account-key "
#             f"{key_path} --csr {self.client_data.csr_path} "
#             f"--acme-dir {self.path}/challenge"
#         )
