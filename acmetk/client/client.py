import asyncio
import logging
import ssl
import typing
from dataclasses import dataclass

import acme.messages
import josepy
from acme import jws
from aiohttp import ClientSession, ClientResponseError
from cryptography.hazmat.primitives.asymmetric import rsa, ec

import acmetk.util
from acmetk.client.challenge_solver import ChallengeSolver
from acmetk.client.exceptions import PollingException, CouldNotCompleteChallenge
from acmetk.models import messages, ChallengeType
from acmetk.version import __version__

logger = logging.getLogger(__name__)
NONCE_RETRIES = 5


# Monkey patch acme's status codes to allow 'expired' for authorizations
STATUS_EXPIRED = acme.messages.Status("expired")


def is_valid(obj):
    return obj.status == acme.messages.STATUS_VALID


def is_invalid(obj):
    return obj.status in [acme.messages.STATUS_INVALID, STATUS_EXPIRED]


@dataclass
class ExternalAccountBindingCredentials:
    """Stores external account binding credentials to later create a binding JWS using
    :class:`~acme.messages.ExternalAccountBinding`.
    """

    kid: str
    """The external account binding's key identifier"""
    hmac_key: str
    """The external account binding's symmetric encryption key"""

    def create_eab(self, public_key: josepy.jwk.JWK, directory: dict) -> dict:
        """Creates an external account binding from the stored credentials.

        :param public_key: The account's public key
        :param directory: The ACME server's directory
        :return: The JWS representing the external account binding
        """
        if self.kid and self.hmac_key:
            return acme.messages.ExternalAccountBinding.from_data(
                public_key, self.kid, self.hmac_key, directory
            )
        else:
            raise ValueError("Must specify both kid and hmac_key")


class AcmeClient:
    """ACME compliant client."""

    FINALIZE_DELAY = 3.0
    """The delay in seconds between finalization attemps."""
    INVALID_NONCE_RETRIES = 5
    """The number of times the client should retry when the server returns the error *badNonce*."""

    def __init__(
        self,
        *,
        directory_url: str,
        private_key: str,
        contact: typing.Dict[str, str] = None,
        server_cert: str = None,
        kid: str = None,
        hmac_key: str = None,
    ):
        """Creates an :class:`AcmeClient` instance.

        :param directory_url: The ACME server's directory
        :param private_key: Path of the private key to use to register the ACME account. Must be a PEM-encoded RSA
            or EC key file.
        :param contact: :class:`dict` containing the contact info to supply on registration. May contain a key *phone*
            and a key *email*.
        :param server_cert: Path of the server certificate to add to the SSL context
        :param kid: The external account binding's key identifier to be used on registration
        :param hmac_key: The external account binding's symmetric encryption key to be used on registration
        """
        self._ssl_context = ssl.create_default_context()

        if server_cert:
            # Add our self-signed server cert for testing purposes.
            self._ssl_context.load_verify_locations(cafile=server_cert)

        self._session = ClientSession(
            headers={"User-Agent": f"acmetk Client {__version__}"}
        )

        self._directory_url = directory_url

        self._private_key, self._alg = self._open_key(private_key)
        # Filter empty strings
        self._contact = {k: v for k, v in contact.items() if len(v) > 0}

        self._directory = dict()
        self._nonces = set()
        self._account = None

        self._challenge_solvers = dict()
        self.eab_credentials = (kid, hmac_key)

    @property
    def eab_credentials(self) -> ExternalAccountBindingCredentials:
        """The client's currently stored external account binding credentials

        Getter:
            Returns the client's currently stored external account binding credentials to be used on registration.
        Setter:
            Sets the client's stored external account binding credentials

            :param credentials: The kid and hmac_key
            :raises: :class:`ValueError` If the tuple does not contain exactly the kid and hmac_key.
        """

        return self._eab_credentials

    @eab_credentials.setter
    def eab_credentials(self, credentials: typing.Tuple[str]):
        """Sets the client's stored external account binding credentials

        :param credentials: The kid and hmac_key
        :raises: :class:`ValueError` If the tuple does not contain exactly the kid and hmac_key.
        """
        if isinstance(credentials, tuple) and len(credentials) == 2:
            self._eab_credentials = ExternalAccountBindingCredentials(*credentials)
        else:
            raise ValueError("A tuple containing the kid and hmac_key is required")

    def _open_key(self, private_key):
        with open(private_key, "rb") as pem:
            data = pem.read()
            certs = acmetk.util.pem_split(data.decode())
            if len(certs) != 1:
                raise ValueError(f"Bad Private Key in file {private_key}")
            if isinstance(certs[0], rsa.RSAPrivateKeyWithSerialization):
                key = josepy.jwk.JWKRSA.load(data)
                alg = josepy.jwa.RS256
            elif isinstance(certs[0], ec.EllipticCurvePrivateKeyWithSerialization):
                key = josepy.jwk.JWKEC.load(data)
                alg = {
                    521: josepy.jwa.ES512,
                    256: josepy.jwa.ES256,
                    384: josepy.jwa.ES384,
                }[key.key._wrapped.key_size]
            else:
                raise ValueError(f"Bad Private Key in file {private_key}")
            return key, alg

    async def close(self):
        """Closes the client's session.

        The client may not be used for requests anymore after it has been closed.
        """
        await self._session.close()

    async def start(self):
        """Starts the client's session.

        This method must be called after initialization and before
        making requests to an ACME server, as it fetches the ACME directory
        and registers the private key with the server.

        It is advised to register at least one :class:`ChallengeSolver`
        using :meth:`register_challenge_solver` before starting the client.
        """
        async with self._session.get(
            self._directory_url, ssl=self._ssl_context
        ) as resp:
            self._directory = await resp.json()

        if not self._challenge_solvers.keys():
            logger.warning(
                "There is no challenge solver registered with the client. "
                "Certificate retrieval will likely fail."
            )

        if self._account:
            try:
                await self.account_lookup()
            except acme.messages.Error as e:
                if e.code != "accountDoesNotExist":
                    raise
                await self.account_register()
        else:
            await self.account_register()

    async def account_register(
        self,
        email: str = None,
        phone: str = None,
        kid: str = None,
        hmac_key: str = None,
    ) -> None:
        """Registers an account with the CA.

        Also sends the given contact information and stores the account internally
        for subsequent requests.
        If the private key is already registered, then the account is only queried.

        It is usually not necessary to call this method as the account is
        registered or fetched automatically in :meth:`start`.

        :param email: The contact email
        :param phone: The contact phone number
        :param kid: The external account binding's key identifier
        :param hmac_key: The external account binding's symmetric encryption key
        :raises: :class:`acme.messages.Error` If the server rejects any of the contact information, the private
            key, or the external account binding.
        """
        eab_credentials = (
            ExternalAccountBindingCredentials(kid, hmac_key)
            if kid and hmac_key
            else self.eab_credentials
        )

        try:
            external_account_binding = eab_credentials.create_eab(
                self._private_key.public_key(), self._directory
            )
        except ValueError:
            external_account_binding = None
            if self.eab_credentials.kid or self.eab_credentials.hmac_key:
                logger.warning(
                    "The external account binding credentials are invalid, "
                    "i.e. the kid or the hmac_key was not supplied. Trying without EAB."
                )

        reg = acme.messages.Registration.from_data(
            email=email or self._contact.get("email"),
            phone=phone or self._contact.get("phone"),
            terms_of_service_agreed=True,
            external_account_binding=external_account_binding,
        )

        resp, account_obj = await self._signed_request(
            reg, self._directory["newAccount"]
        )
        account_obj["kid"] = resp.headers["Location"]
        self._account = messages.Account.from_json(account_obj)

    async def account_update(self, **kwargs) -> None:
        """Updates the account's contact information.

        :param kwargs: Kwargs that are passed to :class:`acme.messages.Registration`'s constructor. May include a
            :class:`dict` *contact* containing new contact information or *status* set to
            :class:`acme.messages.STATUS_DEACTIVATED` to deactivate the account.
        :raises: :class:`acme.messages.Error` If the server rejects any of the contact info or the status
            update.
        """
        reg = acme.messages.Registration(**kwargs)

        _, account_obj = await self._signed_request(reg, self._account.kid)
        account_obj["kid"] = self._account.kid
        self._account = messages.Account.from_json(account_obj)

    async def account_lookup(self) -> None:
        """Looks up an account using the stored private key.

        Also stores the account internally for subsequent requests.

        :raises: :class:`acme.messages.Error` If no account associated with the private key exists.
        """
        reg = acme.messages.Registration.from_data(
            terms_of_service_agreed=True, only_return_existing=True
        )

        self._account = None  # Otherwise the kid is sent instead of the JWK. Results in the request failing.
        resp, account_obj = await self._signed_request(
            reg, self._directory["newAccount"]
        )
        account_obj["kid"] = resp.headers["Location"]
        self._account = messages.Account.from_json(account_obj)

    async def order_create(
        self, identifiers: typing.Union[typing.List[dict], typing.List[str]]
    ) -> messages.Order:
        """Creates a new order with the given identifiers.

        :param identifiers: :class:`list` of identifiers that the order should contain. May either be a list of
            fully qualified domain names or a list of :class:`dict` containing the *type* and *name* (both
            :class:`str`) of each identifier.
        :raises: :class:`acme.messages.Error` If the server is unwilling to create an order with the requested
            identifiers.
        :returns: The new order.
        """
        order = messages.NewOrder.from_data(identifiers=identifiers)

        resp, order_obj = await self._signed_request(order, self._directory["newOrder"])
        order_obj["url"] = resp.headers["Location"]
        return messages.Order.from_json(order_obj)

    async def order_finalize(
        self, order: messages.Order, csr: "cryptography.x509.CertificateSigningRequest"
    ) -> messages.Order:
        """Finalizes the order using the given CSR.

        The caller needs to ensure that this method is called with
        :py:func:`asyncio.wait_for` and a time-out value.
        Otherwise it may result in an infinite loop if the CA
        never reports the order's status as *ready*.

        :param order: Order that is to be finalized.
        :param csr: The CSR that is submitted to apply for certificate issuance.
        :raises:

            * :class:`acme.messages.Error` If the server is unwilling to finalize the order.
            * :class:`aiohttp.ClientResponseError` If the order does not exist.

        :returns: The finalized order.
        """
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
            negative_predicate=is_invalid,
            delay=5.0,
            max_tries=15,
        )
        return finalized

    async def order_get(self, order_url: str) -> messages.Order:
        """Fetches an order given its URL.

        :param order_url: The order's URL.
        :raises: :class:`aiohttp.ClientResponseError` If the order does not exist.
        :return: The fetched order.
        """
        resp, order = await self._signed_request(None, order_url)
        order["url"] = order_url
        return messages.Order.from_json(order)

    async def orders_get(self) -> typing.List[str]:
        """Fetches the account's orders list.

        :return: List containing the URLs of the account's orders.
        """
        if not self._account.orders:
            return []

        orders = []
        next_url = self._account["orders"]
        while True:
            resp, orders_chunk = await self._signed_request(None, next_url)
            orders.extend(orders_chunk["orders"])

            if link := resp.links.get("next", {}).get("url"):
                next_url = str(link)
            else:
                break

        return orders

    async def authorization_get(
        self, authorization_url: str
    ) -> acme.messages.Authorization:
        """Fetches an authorization given its URL.

        :param authorization_url: The authorization's URL.
        :raises: :class:`aiohttp.ClientResponseError` If the authorization does not exist.
        :return: The fetched authorization.
        """
        resp, authorization = await self._signed_request(None, authorization_url)
        return acme.messages.Authorization.from_json(authorization)

    async def authorizations_complete(self, order: acme.messages.Order) -> None:
        """Completes all authorizations associated with the given order.

        Uses one of the registered :class:`ChallengeSolver` to complete one challenge
        per authorization.

        :param order: Order whose authorizations should be completed.
        :raises: :class:`CouldNotCompleteChallenge` If completion of one of the authorizations' challenges failed.
        """
        authorizations = [
            await self.authorization_get(authorization_url)
            for authorization_url in order.authorizations
        ]

        challenge_types = set(
            [
                ChallengeType(challenge.chall.typ)
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

        challenges_to_complete: typing.List[
            typing.Tuple[acme.messages.Identifier, acme.messages.ChallengeBody]
        ] = []

        for authorization in authorizations:
            for challenge in authorization.challenges:
                if ChallengeType(challenge.chall.typ) == chosen_challenge_type:
                    challenges_to_complete.append((authorization.identifier, challenge))

                    break

        try:
            await self.challenges_complete(solver, challenges_to_complete)
        except Exception:
            await self.challenges_cleanup(solver, challenges_to_complete)
            raise
        else:
            await self.challenges_cleanup(solver, challenges_to_complete)

        # Realistically, polling for the authorizations to become valid should never fail since we have already
        # ensured that one challenge per authorization is valid.
        await asyncio.gather(
            *[
                self._poll_until(
                    self.authorization_get,
                    authorization_url,
                    predicate=is_valid,
                    negative_predicate=is_invalid,
                )
                for authorization_url in order.authorizations
            ]
        )

    async def challenges_cleanup(
        self,
        solver: ChallengeSolver,
        challenges: typing.List[
            typing.Tuple[acme.messages.Identifier, acme.messages.ChallengeBody]
        ],
    ):
        """Cleans up after the challenges leveraging the given solver.

        :param solver: The challenge solver to use.
        :param challenges: List of identifier, challenge tuples to clean up after."""
        await asyncio.gather(
            *[
                solver.cleanup_challenge(self._private_key, identifier, challenge)
                for identifier, challenge in challenges
            ]
        )

    async def challenges_complete(
        self,
        solver: ChallengeSolver,
        challenges: typing.List[
            typing.Tuple[acme.messages.Identifier, acme.messages.ChallengeBody]
        ],
    ):
        """Attempts to complete the challenges leveraging the given solver.

        :param solver: The challenge solver to use.
        :param challenges: List of identifier, challenge tuples to complete.
        :raises: :class:`CouldNotCompleteChallenge` If completion of one of the challenges failed.
        """
        # Complete the pending challenges
        await asyncio.gather(
            *[
                solver.complete_challenge(self._private_key, identifier, challenge)
                for (identifier, challenge) in challenges
            ]
        )

        # Tell the server that we are ready for challenge validation
        await asyncio.gather(
            *[self.challenge_validate(challenge.uri) for _, challenge in challenges]
        )

        # Poll until all challenges have become valid
        try:
            await asyncio.gather(
                *[
                    self._poll_until(
                        self.challenge_get,
                        challenge.uri,
                        predicate=is_valid,
                        negative_predicate=is_invalid,
                        delay=5.0,
                        max_tries=50,
                    )
                    for _, challenge in challenges
                ]
            )
        except PollingException as e:
            raise CouldNotCompleteChallenge(e.obj)

    async def challenge_get(self, challenge_url: str) -> acme.messages.ChallengeBody:
        """Fetches a challenge given its URL.

        :param challenge_url: The challenge's URL.
        :raises: :class:`aiohttp.ClientResponseError` If the challenge does not exist.
        :return: The fetched challenge.
        """
        _, challenge_obj = await self._signed_request(None, challenge_url)
        return acme.messages.ChallengeBody.from_json(challenge_obj)

    async def challenge_validate(self, challenge_url: str) -> None:
        """Initiates the given challenge's validation.

        :param challenge_url: The challenge's URL.
        :raises: :class:`aiohttp.ClientResponseError` If the challenge does not exist.
        """
        await self._signed_request(None, challenge_url, post_as_get=False)

    async def certificate_get(self, order: acme.messages.Order) -> str:
        """Downloads the given order's certificate.

        :param order: The order whose certificate to download.
        :raises:

            * :class:`aiohttp.ClientResponseError` If the certificate does not exist.
            * :class:`ValueError` If the order has not been finalized yet, i.e. the certificate \
                property is *None*.

        :return: The order's certificate encoded as PEM.
        """
        if not order.certificate:
            raise ValueError("This order has not been finalized")

        _, pem = await self._signed_request(None, order.certificate)

        return pem

    async def certificate_revoke(
        self,
        certificate: "cryptography.x509.Certificate",
        reason: messages.RevocationReason = None,
    ) -> bool:
        """Revokes the given certificate.

        :param certificate: The certificate to revoke.
        :param reason: Optional reason for revocation.
        :raises:

            * :class:`aiohttp.ClientResponseError` If the certificate does not exist.
            * :class:`acme.messages.Error` If the revocation did not succeed.

        :return: *True* if the revocation succeeded.
        """
        cert_rev = messages.Revocation(certificate=certificate, reason=reason)
        resp, _ = await self._signed_request(cert_rev, self._directory["revokeCert"])

        return resp.status == 200

    async def key_change(self, private_key):
        key, alg = self._open_key(private_key)
        key_change = messages.KeyChange(
            account=self._account["kid"], oldKey=self._private_key.public_key()
        )
        signed_key_change = messages.SignedKeyChange.from_data(
            key_change, key, alg, url=self._directory["keyChange"]
        )
        resp, data = await self._signed_request(
            signed_key_change, self._directory["keyChange"]
        )
        #        data["kid"] = resp.headers["Location"]
        #        self._account = messages.Account.from_json(data)
        self._private_key = key
        self._alg = alg

    def register_challenge_solver(
        self,
        challenge_solver: ChallengeSolver,
    ):
        """Registers a challenge solver with the client.

        The challenge solver is used to complete authorizations' challenges whose types it supports.

        :param challenge_solver: The challenge solver to register.
        :raises: :class:`ValueError` If a challenge solver is already registered that supports any of
            the challenge types that *challenge_solver* supports.
        """
        for challenge_type in challenge_solver.SUPPORTED_CHALLENGES:
            if self._challenge_solvers.get(challenge_type):
                raise ValueError(
                    f"A challenge solver for type {challenge_type} is already registered"
                )
            else:
                self._challenge_solvers[challenge_type] = challenge_solver

    async def _poll_until(
        self,
        coro,
        *args,
        predicate=None,
        negative_predicate=None,
        delay=3.0,
        max_tries=5,
        **kwargs,
    ):
        tries = max_tries
        result = await coro(*args, **kwargs)
        while tries > 0:
            logger.debug(
                "Polling %s%s, tries remaining: %d", coro.__name__, args, tries - 1
            )
            if predicate(result):
                break

            if negative_predicate(result):
                raise PollingException(
                    result,
                    f"Polling unsuccessful: {coro.__name__}{args}, {negative_predicate.__name__} became True",
                )

            await asyncio.sleep(delay)
            result = await coro(*args, **kwargs)
            tries -= 1
        else:
            raise PollingException(
                result, f"Polling unsuccessful: {coro.__name__}{args}"
            )

        return result

    async def _get_nonce(self):
        async def fetch_nonce():
            try:
                async with self._session.head(
                    self._directory["newNonce"], ssl=self._ssl_context
                ) as resp:
                    logger.debug("Storing new nonce %s", resp.headers["Replay-Nonce"])
                    return resp.headers["Replay-Nonce"]
            except Exception as e:
                logger.exception(e)

        try:
            return self._nonces.pop()
        except KeyError:
            return await self._poll_until(fetch_nonce, predicate=lambda x: x, delay=5.0)

    def _wrap_in_jws(
        self, obj: typing.Optional[josepy.JSONDeSerializable], nonce, url, post_as_get
    ):
        if post_as_get:
            jobj = obj.json_dumps(indent=2).encode() if obj else b""
        else:
            jobj = b"{}"
        kwargs = {"nonce": acme.jose.b64decode(nonce), "url": url}
        if self._account is not None:
            kwargs["kid"] = self._account["kid"]
        return jws.JWS.sign(
            jobj, key=self._private_key, alg=self._alg, **kwargs
        ).json_dumps(indent=2)

    async def _signed_request(
        self, obj: typing.Optional[josepy.JSONDeSerializable], url, post_as_get=True
    ):
        tries = self.INVALID_NONCE_RETRIES
        while tries > 0:
            try:
                payload = self._wrap_in_jws(
                    obj, await self._get_nonce(), url, post_as_get
                )
                return await self._make_request(payload, url)
            except acme.messages.Error as e:
                if e.code == "badNonce" and tries > 1:
                    tries -= 1
                    continue
                raise e

    async def _make_request(self, payload, url):
        async with self._session.post(
            url,
            data=payload,
            headers={"Content-Type": "application/jose+json"},
            ssl=self._ssl_context,
        ) as resp:
            if "Replay-Nonce" in resp.headers:
                self._nonces.add(resp.headers["Replay-Nonce"])

            if 200 <= resp.status < 300 and resp.content_type == "application/json":
                data = await resp.json()
            elif resp.content_type == "application/problem+json":
                raise acme.messages.Error.from_json(await resp.json())
            elif resp.status < 200 or resp.status >= 300:
                raise ClientResponseError(
                    resp.request_info, resp.history, status=resp.status
                )
            else:
                data = await resp.text()

            logger.debug(data)
            return resp, data
