import abc
import enum
import logging
import typing

import acme.messages
import josepy
from acme import jws
from aiohttp import ClientSession

from acme_broker import messages

logger = logging.getLogger(__name__)
NONCE_RETRIES = 5


def load_key(filename):
    with open(filename, "rb") as pem:
        return pem.read()


class ChallengeSolverType(enum.Enum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


class ChallengeSolver(abc.ABC):
    @abc.abstractmethod
    async def solve_challenge(self, challenge):
        pass


class DummySolver(ChallengeSolver):
    async def solve_challenge(self, challenge):
        return


class AcmeClient:
    def __init__(self, *, directory_url, private_key):
        self._session = ClientSession()

        self._directory_url = directory_url
        self._private_key = josepy.jwk.JWKRSA.load(load_key(private_key))

        self._directory = dict()
        self._nonces = set()
        self._account = None
        self._alg = josepy.RS256

        self._challenge_solvers = dict()

    async def close(self):
        await self._session.close()

    async def get_directory(self):
        async with self._session.get(self._directory_url) as resp:
            self._directory = await resp.json()

    async def _get_nonce(self, tries=NONCE_RETRIES):
        if tries < 1:
            raise ValueError(
                f"Could not fetch a valid nonce from the server after {NONCE_RETRIES} retries."
            )

        nonce = None
        try:
            nonce = self._nonces.pop()
        except KeyError:
            while not nonce:
                async with self._session.head(self._directory["newNonce"]) as resp:
                    logger.debug("Storing new nonce %s", resp.headers["Replay-Nonce"])
                    self._nonces.add(resp.headers["Replay-Nonce"])

                nonce = await self._get_nonce(tries=tries - 1)

        return nonce

    async def register_account(self, email=None, phone=None):
        reg = acme.messages.Registration.from_data(
            email=email, phone=phone, terms_of_service_agreed=True
        )

        resp, account_obj = await self._signed_request(
            reg, self._directory["newAccount"]
        )
        account_obj["kid"] = resp.headers["Location"]
        self._account = messages.Account.from_json(account_obj)

    async def get_orders(self):
        resp, orders = await self._signed_request(None, self._account["orders"])
        return orders

    async def get_authorization(self, authorization_url):
        resp, authorization = await self._signed_request(None, authorization_url)
        return acme.messages.Authorization.from_json(authorization)

    async def create_order(
        self, identifiers: typing.Union[typing.List[dict], typing.List[str]]
    ):
        order = messages.NewOrder.from_data(identifiers=identifiers)

        resp, order_obj = await self._signed_request(order, self._directory["newOrder"])
        return acme.messages.Order.from_json(order_obj)

    async def complete_authorizations(self, order: acme.messages.Order):
        authorizations = [
            await self.get_authorization(authorization_url)
            for authorization_url in order.authorizations
        ]
        return authorizations

    async def complete_challenge(self, challenge_url):
        pass

    def _wrap_in_jws(self, obj: typing.Optional[josepy.JSONDeSerializable], nonce, url):
        jobj = obj.json_dumps(indent=2).encode() if obj else b""
        kwargs = {"nonce": acme.jose.b64decode(nonce), "url": url}
        if self._account is not None:
            kwargs["kid"] = self._account["kid"]
        return jws.JWS.sign(
            jobj, key=self._private_key, alg=self._alg, **kwargs
        ).json_dumps(indent=2)

    async def _signed_request(
        self, obj: typing.Optional[josepy.JSONDeSerializable], url
    ):
        payload = self._wrap_in_jws(obj, await self._get_nonce(), url)

        async with self._session.post(url, data=payload) as resp:
            self._nonces.add(resp.headers.get("Replay-Nonce"))

            obj = await resp.json()
            logger.debug(obj)
            return resp, obj

    def register_challenge_solver(
        self,
        types: typing.Iterable[ChallengeSolverType],
        challenge_solver: ChallengeSolver,
    ):
        for type_ in types:
            if self._challenge_solvers.get(type_, None):
                raise ValueError(
                    f"A challenge solver of type '{type_}' is already registered."
                )
            else:
                logger.debug(
                    f"Registering {type(challenge_solver).__name__} as the Challenge Solver for types {types}"
                )
                self._challenge_solvers[type_] = challenge_solver
