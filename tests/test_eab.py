import datetime
import json
import unittest
import urllib.parse

import acme.messages
import aiohttp
import html5lib
import josepy
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acmetk.server.external_account_binding import ExternalAccountBindingStore
from tests.test_ca import TestCertBotCA, TestOurClientCA


def generate_x509_client_cert(email):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Niedersachsen"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hannover"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Leibniz Universitaet Hannover"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ACME Toolkit"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    data = cert.public_bytes(serialization.Encoding.PEM)
    return urllib.parse.quote(data)


class TestEAB(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        from pathlib import Path

        import yaml

        from acmetk.database import Database

        self._config = yaml.safe_load(Path("tests/conf/debug.yml").read_text())
        self._db = Database(self._config["tests"]["LocalCA"]["services"]["ca"]["db"])
        self.eab_store = ExternalAccountBindingStore(self._db)

    async def test_create(self):
        kid = f"test+{int(datetime.datetime.now().timestamp())}@test.test"
        url = "https://x.org/test"

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = key.public_key()

        cred = await self.eab_store.create(kid, url, datetime.timedelta(hours=1))

        key_json = json.dumps(josepy.jwk.JWKRSA(key=pub_key).to_partial_json()).encode()
        v = cred._eab(key_json)
        assert await self.eab_store.verify(kid, v)

    async def test_create_multiple(self):
        ts = int(datetime.datetime.now().timestamp())
        kids = [f"test+{ts}-{i}@test.test" for i in range(2)]
        url = "https://x.org/test"

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_json = json.dumps(josepy.jwk.JWKRSA(key=key.public_key()).to_partial_json()).encode()

        creds = [await self.eab_store.create(kid, url, datetime.timedelta(hours=1)) for kid in kids]

        for kid, cred in zip(kids, creds):
            assert cred.kid == kid
            assert await self.eab_store.verify(kid, cred._eab(key_json))


async def get_eab(header, value) -> tuple[str, str]:
    async with aiohttp.ClientSession() as session:
        v = await session.get("http://localhost:8000/eab", headers={header: value})
        data = await v.content.read()

    document = html5lib.parse(data, treebuilder="etree", namespaceHTMLElements=False)

    kid = document.find("./body/p/input[@id='kid']").attrib["value"]
    hmac_key = document.find("./body/p/input[@id='hmac_key']").attrib["value"]

    return kid, hmac_key


class TestCertbotCA_EAB(TestCertBotCA):
    @property
    def config_sec(self):
        return self._config["tests"]["LocalCA_EAB"]

    def setUp(self) -> None:
        super().setUp()

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.eab_credentials = await get_eab(self.ca._c.eab.header, self.contact)

    async def test_register(self):
        kid, hmac_key = self.eab_credentials
        self.log.debug("kid: %s, hmac_key: %s", kid, hmac_key)
        await self._run(f"register --agree-tos  -m {kid} --eab-kid {kid} --eab-hmac-key={hmac_key}")

    async def test_run(self):
        pass

    async def test_subdomain_revocation(self):
        pass

    async def test_skey_revocation(self):
        pass

    async def test_renewal(self):
        pass

    async def test_unregister(self):
        pass

    async def test_bad_identifier(self):
        pass


class TestOurClientCA_EAB:
    @property
    def config_sec(self):
        return self._config["tests"]["LocalCA_EAB"]

    def setUp(self):
        super().setUp()

    async def test_register(self):
        self.client.eab_credentials = (None, None)
        with self.assertRaisesRegex(acme.messages.Error, "urn:ietf:params:acme:error:externalAccountRequired"):
            await self.client.start()

        self.client.eab_credentials = self.eab_credentials
        await self.client.start()

    async def test_expired(self):
        # Change the EAB's created timestamp to expire it

        async with self.ca._db.session() as session:
            cred = await self.ca._db.get_eab(session, self.client.eab_credentials.kid)
            cred.lifetime = datetime.timedelta(seconds=0)
            session.add(cred)
            await session.commit()

        with self.assertRaisesRegex(acme.messages.Error, "urn:ietf:params:acme:error:unauthorized"):
            await self.client.start()

    async def test_account_update(self):
        pass

    async def test_keychange(self):
        pass

    async def test_run_stress(self):
        pass


class TestOurClientCA_EAB_CERT(TestOurClientCA_EAB, TestOurClientCA):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.ca._c.eab.type = "x509"
        self.eab_credentials = self.client.eab_credentials = await get_eab(
            self.ca._c.eab.header, generate_x509_client_cert(self.client._contact["email"])
        )


class TestOurClientCA_EAB_EMAIL(TestOurClientCA_EAB, TestOurClientCA):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.ca._c.eab.type = "plain"
        self.eab_credentials = self.client.eab_credentials = await get_eab(self.ca._c.eab.header, self.contact)

    async def test_run(self):
        await super().test_run()
