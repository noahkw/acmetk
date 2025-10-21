import datetime
import json
import urllib.parse
import unittest
from unittest.mock import Mock

import josepy
import yarl

import acme.messages

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from acmetk.server.external_account_binding import (
    ExternalAccountBindingStore,
    AcmeEABMixin,
)
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


class TestEAB(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.eab_store = ExternalAccountBindingStore()

    def test_create(self):
        URL = yarl.URL("http://localhost/eab")

        request = Mock(
            headers={AcmeEABMixin.CLIENT_CERT_HEADER: generate_x509_client_cert("test@test.test")},
            url=URL,
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = key.public_key()

        self.eab_store.create(request)

        key_json = json.dumps(josepy.jwk.JWKRSA(key=pub_key).to_partial_json()).encode()
        signature = list(self.eab_store._pending.values())[0].signature(key_json)
        print(signature)


class TestCertbotCA_EAB(TestCertBotCA):
    @property
    def config_sec(self):
        return self._config["tests"]["LocalCA_EAB"]

    def setUp(self) -> None:
        super().setUp()

    async def test_register(self):
        URL = yarl.URL("http://localhost:8000/eab")
        request = Mock(
            headers={AcmeEABMixin.CLIENT_CERT_HEADER: generate_x509_client_cert(self.contact)},
            url=URL,
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        kid, hmac_key = self.ca._eab_store.create(request)

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
        self.client.eab_credentials = self.eab_credentials
        # Change the EAB's created timestamp to expire it
        list(self.ca._eab_store._pending.values())[0].when -= datetime.timedelta(hours=3, minutes=1)

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

        request = Mock(
            headers={AcmeEABMixin.CLIENT_CERT_HEADER: generate_x509_client_cert(self.client._contact["email"])},
            url=yarl.URL("http://localhost:8000/eab"),
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        self.client.eab_credentials = self.eab_credentials = self.ca._eab_store.create(request)
        self.log.debug("kid: %s, hmac_key: %s", self.eab_credentials[0], self.eab_credentials[1])


class TestOurClientCA_EAB_EMAIL(TestOurClientCA_EAB, TestOurClientCA):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()

        request = Mock(
            headers={AcmeEABMixin.CLIENT_EMAIL_HEADER: self.client._contact["email"]},
            url=yarl.URL("http://localhost:8000/eab"),
            app=Mock(router={"new-account": Mock(url_for=lambda: "new-account")}),
        )
        self.client.eab_credentials = self.eab_credentials = self.ca._eab_store.create(request)
        self.log.debug("kid: %s, hmac_key: %s", self.eab_credentials[0], self.eab_credentials[1])
