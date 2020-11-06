import logging

import josepy
from aiohttp import ClientSession
from acme import jws


import acme.messages


logger = logging.getLogger(__name__)


def load_key(filename):
    with open(filename, "rb") as pem:
        return pem.read()


class AcmeClient:
    def __init__(self, *, directory_url, private_key):
        self._session = ClientSession()

        self._directory_url = directory_url
        self._private_key = josepy.jwk.JWKRSA.load(load_key(private_key))

        self._directory = dict()
        self._nonces = set()
        self._account = None
        self._alg = josepy.RS256

    async def close(self):
        await self._session.close()

    async def get_directory(self):
        async with self._session.get(self._directory_url) as resp:
            self._directory = await resp.json()

    async def _get_nonce(self):
        async with self._session.head(self._directory["newNonce"]) as resp:
            logger.debug("Storing new nonce %s", resp.headers["Replay-Nonce"])
            self._nonces.add(resp.headers["Replay-Nonce"])

    async def register_account(self, email="", phone=""):
        reg = acme.messages.Registration.from_data(
            email=email, phone=phone, terms_of_service_agreed=True
        )

        await self._signed_request(reg, self._directory["newAccount"])

    def _wrap_in_jws(self, obj, nonce, url):
        jobj = obj.json_dumps(indent=2).encode() if obj else b""
        kwargs = {"nonce": acme.jose.b64decode(nonce), "url": url}
        if self._account is not None:
            kwargs["kid"] = self._account["uri"]
        return jws.JWS.sign(
            jobj, key=self._private_key, alg=self._alg, **kwargs
        ).json_dumps(indent=2)

    async def _signed_request(self, obj, url):
        payload = self._wrap_in_jws(obj, self._nonces.pop(), url)
        async with self._session.post(url, data=payload) as resp:
            text = await resp.text()
            logger.debug(text)
