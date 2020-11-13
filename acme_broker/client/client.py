import abc
import asyncio
import enum
import logging
import typing

import acme.messages
import josepy
from acme import jws
from aiohttp import ClientSession
from cryptography import x509

from acme_broker import messages

logger = logging.getLogger(__name__)
NONCE_RETRIES = 5


class AcmeClientException(Exception):
    pass


class CouldNotCompleteChallenge(AcmeClientException):
    def __init__(self, challenge, *args):
        super().__init__(*args)
        self.challenge = challenge

    def __str__(self):
        return f"Could not complete challenge: {self.challenge}"


class PollingException(AcmeClientException):
    def __init__(self, msg, obj, *args):
        super().__init__(*args)
        self.msg = msg
        self.obj = obj


def load_key(filename):
    with open(filename, "rb") as pem:
        return pem.read()


def is_valid(obj):
    return obj.status == acme.messages.STATUS_VALID


class ChallengeSolverType(enum.Enum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"


class ChallengeSolver(abc.ABC):
    @abc.abstractmethod
    async def complete_challenge(self, challenge):
        """Complete the given challenge.

        This method should complete the given challenge and then delay
        returning until the server is allowed to check for completion.

        :param challenge: The challenge to be completed
        :type challenge: acme.messages.ChallengeBody
        """
        pass


class DummySolver(ChallengeSolver):
    async def complete_challenge(self, challenge):
        logger.debug(
            f"(not) solving challenge {challenge.uri}, type {challenge.chall.typ}"
        )
        # await asyncio.sleep(1)


class AcmeClient:
    FINALIZE_DELAY = 10.0

    def __init__(self, *, directory_url, private_key, contact=None):
        self._session = ClientSession()

        self._directory_url = directory_url
        self._private_key = josepy.jwk.JWKRSA.load(load_key(private_key))
        self._contact = {k: v for k, v in contact.items() if len(v) > 0}

        self._directory = dict()
        self._nonces = set()
        self._account = None
        self._alg = josepy.RS256

        self._challenge_solvers = dict()

    async def close(self):
        await self._session.close()

    async def start(self):
        async with self._session.get(self._directory_url) as resp:
            self._directory = await resp.json()

        if not self._challenge_solvers.keys():
            raise ValueError(
                "There is no challenge solver registered with the client. Certificate retrieval will likely fail."
            )

        await self.account_register(**self._contact)

    async def account_register(self, email=None, phone=None) -> None:
        reg = acme.messages.Registration.from_data(
            email=email, phone=phone, terms_of_service_agreed=True
        )

        resp, account_obj = await self._signed_request(
            reg, self._directory["newAccount"]
        )
        account_obj["kid"] = resp.headers["Location"]
        self._account = messages.Account.from_json(account_obj)

    async def account_update(self, **kwargs) -> None:
        reg = acme.messages.Registration(**kwargs)

        _, account_obj = await self._signed_request(reg, self._account.kid)
        account_obj["kid"] = self._account.kid
        self._account = messages.Account.from_json(account_obj)

    async def account_lookup(self) -> None:
        reg = acme.messages.Registration.from_data(
            terms_of_service_agreed=True, only_return_existing=True
        )

        resp, account_obj = await self._signed_request(
            reg, self._directory["newAccount"]
        )
        account_obj["kid"] = resp.headers["Location"]
        self._account = messages.Account.from_json(account_obj)

    async def order_create(
        self, identifiers: typing.Union[typing.List[dict], typing.List[str]]
    ) -> acme.messages.Order:
        order = messages.NewOrder.from_data(identifiers=identifiers)

        _, order_obj = await self._signed_request(order, self._directory["newOrder"])
        return acme.messages.Order.from_json(order_obj)

    async def order_finalize(self, order, csr) -> acme.messages.Order:
        cert_req = messages.CertificateRequest(csr=csr)

        while True:
            try:
                resp, order_obj = await self._signed_request(cert_req, order.finalize)
                break
            except acme.messages.Error as e:
                # Make sure that the order is in state READY before moving on.
                if e.code == "orderNotReady":
                    await asyncio.sleep(self.FINALIZE_DELAY)
                else:
                    raise e

        finalized = await self._poll_until(
            self.order_get,
            resp.headers["Location"],
            predicate=is_valid,
            delay=3.0,
            max_tries=15,
        )
        return finalized

    async def order_get(self, order_url) -> acme.messages.Order:
        resp, order = await self._signed_request(None, order_url)
        return acme.messages.Order.from_json(order)

    async def orders_get(self) -> typing.List[str]:
        if "orders" not in self._account:
            return []

        _, orders = await self._signed_request(None, self._account["orders"])
        return orders

    async def authorization_get(self, authorization_url) -> acme.messages.Authorization:
        resp, authorization = await self._signed_request(None, authorization_url)
        return acme.messages.Authorization.from_json(authorization)

    async def authorizations_complete(self, order: acme.messages.Order) -> None:
        authorizations = [
            await self.authorization_get(authorization_url)
            for authorization_url in order.authorizations
        ]

        challenge_types = set(
            [
                ChallengeSolverType(challenge.chall.typ)
                for authorization in authorizations
                for challenge in authorization.challenges
            ]
        )
        possible_types = self._challenge_solvers.keys() & challenge_types

        if len(possible_types) == 0:
            raise ValueError(
                f"The server offered the following challenge types but there is no solver "
                f"that is able to complete them: {', '.join(possible_types)}"
            )

        chosen_challenge_type = possible_types.pop()
        solver = self._challenge_solvers[chosen_challenge_type]
        logger.debug(
            "Chosen challenge type: %s, solver: %s",
            chosen_challenge_type,
            type(solver).__name__,
        )

        processing_challenges = []

        for authorization in authorizations:
            for challenge in authorization.challenges:
                if ChallengeSolverType(challenge.chall.typ) == chosen_challenge_type:
                    await solver.complete_challenge(challenge)
                    processing_challenges.append(challenge)

                    break

        try:
            await asyncio.gather(
                *[
                    self._poll_until(
                        self.challenge_get, challenge.uri, predicate=is_valid, delay=5.0
                    )
                    for challenge in processing_challenges
                ]
            )
        except PollingException as e:
            raise CouldNotCompleteChallenge(e.obj)

        # Realistically, polling for the authorizations to become valid should never fail since we have already
        # ensured that one challenge per authorization is valid.
        await asyncio.gather(
            *[
                self._poll_until(
                    self.authorization_get, authorization_url, predicate=is_valid
                )
                for authorization_url in order.authorizations
            ]
        )

    async def challenge_get(self, challenge_url) -> acme.messages.ChallengeBody:
        _, challenge_obj = await self._signed_request(None, challenge_url)
        return acme.messages.ChallengeBody.from_json(challenge_obj)

    async def certificate_get(self, order) -> str:
        _, cert = await self._signed_request(None, order.certificate)
        return cert

    async def certificate_revoke(self, certificate: x509.Certificate) -> bool:
        cert_rev = messages.Revocation(certificate=certificate)
        resp, _ = await self._signed_request(cert_rev, self._directory["revokeCert"])

        return resp.status == 200

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

    async def _poll_until(
        self, coro, *args, predicate=None, delay=3.0, max_tries=5, **kwargs
    ):
        tries = max_tries
        result = await coro(*args, **kwargs)
        while tries > 0:
            logger.debug(
                "Polling %s%s, tries remaining: %d", coro.__name__, args, tries - 1
            )
            if predicate(result):
                break

            await asyncio.sleep(delay)
            result = await coro(*args, **kwargs)
            tries -= 1
        else:
            raise PollingException(
                f"Polling unsuccessful: {coro.__name__}{args}", result
            )

        return result

    async def _get_nonce(self):
        async def fetch_nonce():
            try:
                async with self._session.head(self._directory["newNonce"]) as resp:
                    logger.debug("Storing new nonce %s", resp.headers["Replay-Nonce"])
                    return resp.headers["Replay-Nonce"]
            except Exception as e:
                logger.exception(e)

        try:
            return self._nonces.pop()
        except KeyError:
            return await self._poll_until(fetch_nonce, predicate=lambda x: x, delay=5.0)

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

        async with self._session.post(
            url, data=payload, headers={"Content-Type": "application/jose+json"}
        ) as resp:
            if "Replay-Nonce" in resp.headers:
                self._nonces.add(resp.headers["Replay-Nonce"])

            if resp.content_type == "application/json":
                data = await resp.json()
            elif resp.content_type == "application/problem+json":
                raise acme.messages.Error.from_json(await resp.json())
            else:
                data = await resp.text()

            logger.debug(data)
            return resp, data
