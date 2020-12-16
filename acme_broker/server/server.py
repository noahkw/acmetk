import asyncio
import ipaddress
import json
import logging
import re
import typing
import uuid
import functools
import types

from email.utils import parseaddr

import acme.jws
import acme.messages
import josepy
import yarl
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.web_middlewares import middleware
import aiohttp_jinja2


from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


from acme_broker.server.management import AcmeManagement
from acme_broker import models


from acme_broker.models import messages
from acme_broker.client import CouldNotCompleteChallenge, AcmeClientException
from acme_broker.database import Database
from acme_broker.server import ChallengeValidator
from acme_broker.util import (
    url_for,
    generate_cert_from_csr,
    names_of,
    forwarded_url,
    pem_split,
    ConfigurableMixin,
)

from acme_broker.server.routes import routes

logger = logging.getLogger(__name__)


async def handle_get(request):
    return web.Response(status=405)


class AcmeResponse(web.Response):
    def __init__(self, nonce, directory_url, *args, links=None, **kwargs):
        super().__init__(*args, **kwargs)
        if links is None:
            links = []

        links.append(f'<{directory_url}>; rel="index"')

        self.headers.update(
            {
                "Replay-Nonce": nonce,
                "Cache-Control": "no-store",
                "Link": ", ".join(links),
            }
        )


class AcmeServerBase(AcmeManagement, ConfigurableMixin):
    """Base class for an ACME compliant server.

    Implementations must set the :attr:`config_name` attribute, so that the CLI script knows which
    configuration option corresponds to which server class.
    """

    config_name: str
    """The string that maps to the server implementation inside configuration files."""

    SUPPORTED_JWS_ALGORITHMS = (
        josepy.RS256,
        josepy.RS384,
        josepy.RS512,
        josepy.PS256,
        josepy.PS384,
        josepy.PS512,
    )
    """The JWS signing algorithms that the server supports."""

    SUPPORTED_ACCOUNT_KEYS = (rsa.RSAPublicKey,)

    SUPPORTED_CSR_KEYS = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)

    subclasses = []

    def __init__(
        self,
        *,
        rsa_min_keysize=2048,
        ec_min_keysize=256,
        tos_url=None,
        mail_suffixes=None,
        subnets=None,
        use_forwarded_header=False,
        **kwargs,
    ):
        self._min_keysize = {
            rsa.RSAPublicKey: rsa_min_keysize,
            ec.EllipticCurvePublicKey: ec_min_keysize,
        }
        self._tos_url = tos_url
        self._mail_suffixes = mail_suffixes
        self._subnets = (
            [ipaddress.ip_network(subnet) for subnet in subnets] if subnets else None
        )
        self._use_forwarded_header = use_forwarded_header

        self.app = web.Application(
            middlewares=[
                self.error_middleware,
                self.host_ip_middleware,
                self.aiohttp_jinja2_middleware,
            ]
        )
        # request.app['_service_'] available in jinja2 templates
        self.app["_service_"] = self

        self._add_routes()

        self._nonces = set()

        self._db: typing.Optional[Database] = None
        self._db_session = None

        self._challenge_validators = {}

    def _get_min_keysize(self, public_key):
        for key_type, key_size in self._min_keysize.items():
            if isinstance(public_key, key_type):
                return key_size
        else:
            raise ValueError("This key type is not supported.")

    def _add_routes(self):
        specific_routes = []

        for route_def in routes:
            specific_routes.append(
                web.RouteDef(
                    route_def.method,
                    route_def.path,
                    getattr(self, route_def.handler.__name__),
                    route_def.kwargs.copy(),
                )
            )

        self.app.add_routes(specific_routes)
        # catch-all get
        self.app.router.add_route("GET", "/{tail:.*}", handle_get)

    @classmethod
    async def create_app(
        cls, config: typing.Dict[str, typing.Any], **kwargs
    ) -> "AcmeServerBase":
        """A factory that also creates and initializes the database and session objects,
        reading the necessary arguments from the passed config dict.

        :param config: A dictionary holding the configuration. See :doc:`configuration` for supported options.
        :return: The server instance
        """
        db = Database(config["db"])

        instance = cls(
            **config,
            **kwargs,
        )
        instance._db = db
        instance._db_session = db.session

        return instance

    def _session(self, request):
        return self._db_session(
            info={"remote_host": request.get("actual_ip", "0.0.0.0")}
        )

    @classmethod
    async def runner(
        cls, config: typing.Dict[str, typing.Any], **kwargs
    ) -> typing.Tuple["aiohttp.web.AppRunner", "AcmeServerBase"]:
        """A factory that starts the server on the given hostname and port using an AppRunner
        after constructing a server instance using :meth:`.create_app`.

        :param config: A dictionary holding the configuration. See :doc:`configuration` for supported options.
        :param kwargs: Additional kwargs are passed to the :meth:`.create_app` call.
        :return: A tuple containing the app runner as well as the server instance.
        """
        instance = await cls.create_app(config, **kwargs)

        runner = web.AppRunner(instance.app)
        await runner.setup()

        site = web.TCPSite(runner, config["hostname"], config["port"])
        await site.start()

        return runner, instance

    @classmethod
    async def unix_socket(
        cls, config: typing.Dict[str, typing.Any], path: str, **kwargs
    ) -> typing.Tuple["aiohttp.web.AppRunner", "AcmeServerBase"]:
        """A factory that starts the server on a Unix socket bound to the given path using an AppRunner
        after constructing a server instance using :meth:`.create_app`.

        :param config: A dictionary holding the configuration. See :doc:`configuration` for supported options.
        :param path: Path of the unix socket.
        :param kwargs: Additional kwargs are passed to the :meth:`.create_app` call.
        :return: A tuple containing the app runner as well as the server instance.
        """
        instance = await cls.create_app(config, **kwargs)

        runner = web.AppRunner(instance.app)
        await runner.setup()

        site = web.UnixSite(runner, path)
        await site.start()

        return runner, instance

    def register_challenge_validator(self, validator: ChallengeValidator):
        """Registers a :class:`ChallengeValidator` with the server.

        The validator is subsequently used to validate challenges of all types that it
        supports.

        :param validator: The challenge validator to be registered.
        :raises: :class:`ValueError` If a challenge validator is already registered that supports any of
            the challenge types that *validator* supports.
        """
        for challenge_type in validator.SUPPORTED_CHALLENGES:
            if self._challenge_validators.get(challenge_type):
                raise ValueError(
                    f"A challenge validator for type {challenge_type} is already registered"
                )
            else:
                self._challenge_validators[challenge_type] = validator

    @property
    def _supported_challenges(self):
        return self._challenge_validators.keys()

    def _response(self, request, data=None, text=None, *args, **kwargs):
        if data and text:
            raise ValueError("only one of data, text, or body should be specified")
        elif data and (data is not sentinel):
            text = json.dumps(data)
            kwargs.update({"content_type": "application/json"})
        else:
            text = data or text

        return AcmeResponse(
            self._issue_nonce(),
            url_for(request, "directory"),
            *args,
            **kwargs,
            text=text,
        )

    def _issue_nonce(self):
        nonce = uuid.uuid4().hex
        self._nonces.add(nonce)
        return nonce

    def _verify_nonce(self, nonce):
        if nonce in self._nonces:
            self._nonces.remove(nonce)
        else:
            raise acme.messages.Error.with_code("badNonce", detail=nonce)

    async def _verify_request(
        self, request, session, key_auth: bool = False, post_as_get: bool = False
    ):
        """Verifies an ACME request whose payload is encapsulated in a JWS.

        `6.2. Request Authentication <https://tools.ietf.org/html/rfc8555#section-6.2>`_

        All requests to handlers apart from :meth:`new_nonce` and :meth:`directory`
        are authenticated.

        :param key_auth: True if the JWK inside the JWS should be used to \
            verify its signature. False otherwise
        :param post_as_get: True if a `POST-as-GET <https://tools.ietf.org/html/rfc8555#section-6.3>`_ \
            request is expected. False otherwise
        :raises:

            * :class:`aiohttp.web.HTTPNotFound` if the JWS contains a kid, \
                but the corresponding account does not exist.

            * :class:`acme.messages.Error` if any of the following are true:

                * The request does not contain a valid JWS
                * The handler expects a `POST-as-GET <https://tools.ietf.org/html/rfc8555#section-6.3>`_ request, \
                    but got a non-empty payload
                * The URL inside the JWS' signature is not equal to the actual request URL
                * The signature was created using an algorithm that the server does not support, \
                    see :attr:`SUPPORTED_JWS_ALGORITHMS`
                * The client supplied a bad nonce in the JWS signature
                * The JWS does not have *either* a JWK *or* a kid
                * The JWS' signature is invalid
                * There is a mismatch between the URL's kid and the JWS' kid
                * The account corresponding to the kid does not have status \
                    :attr:`acme_broker.models.AccountStatus.VALID`
        """
        data = await request.text()
        try:
            jws = acme.jws.JWS.json_loads(data)
        except josepy.errors.DeserializationError:
            raise acme.messages.Error.with_code(
                "malformed", detail="The request does not contain a valid JWS."
            )

        if post_as_get and jws.payload != b"":
            raise acme.messages.Error.with_code(
                "malformed",
                detail='The request payload must be b"" in a POST-as-GET request.',
            )

        sig = jws.signature.combined

        if sig.url != str(forwarded_url(request)):
            raise acme.messages.Error.with_code("unauthorized")

        if sig.alg not in self.SUPPORTED_JWS_ALGORITHMS:
            raise acme.messages.Error.with_code(
                "badSignatureAlgorithm",
                detail=f"Supported algorithms: {', '.join([str(alg) for alg in self.SUPPORTED_JWS_ALGORITHMS])}",
            )

        nonce = acme.jose.b64.b64encode(sig.nonce).decode()
        self._verify_nonce(nonce)

        # Check whether we have *either* a jwk or a kid
        if not ((sig.jwk is not None) ^ (sig.kid is not None)):
            raise acme.messages.Error.with_code("malformed")

        if key_auth:
            if not jws.verify(sig.jwk):
                raise acme.messages.Error.with_code("unauthorized")
            else:
                account = await self._db.get_account(session, key=sig.jwk)
        elif sig.kid:
            kid = yarl.URL(sig.kid).name

            if url_for(request, "accounts", kid=kid) != sig.kid:
                """Bug in the dehydrated client, accepted by boulder, so we accept it too.
                Dehydrated puts .../new-account/{kid} into the request signature, instead of
                .../accounts/{kid}."""
                kid_new_account_route = yarl.URL(url_for(request, "new-account"))
                kid_new_account_route = kid_new_account_route.with_path(
                    kid_new_account_route.path + "/" + kid
                )
                if str(kid_new_account_route) == sig.kid:
                    logger.debug("Buggy client kid account mismatch")
                else:
                    raise acme.messages.Error.with_code("malformed")
            elif "kid" in request.match_info and request.match_info["kid"] != kid:
                raise acme.messages.Error.with_code("malformed")

            account = await self._db.get_account(session, kid=kid)

            if not account:
                logger.info("Could not find account with kid %s", kid)
                raise acme.messages.Error.with_code("accountDoesNotExist")

            if account.status != models.AccountStatus.VALID:
                raise acme.messages.Error.with_code("unauthorized")

            if not jws.verify(account.key):
                raise acme.messages.Error.with_code("unauthorized")
        else:
            raise acme.messages.Error.with_code("malformed")

        return jws, account

    async def _verify_revocation(
        self, request, session
    ) -> (models.Certificate, messages.Revocation):
        try:
            # check whether the message is signed using an account key
            jws, account = await self._verify_request(request, session)
        except acme.messages.Error:
            data = await request.text()
            jws = acme.jws.JWS.json_loads(
                data
            )  # TODO: raise acme error on deserialization error
            account = None

        try:
            revocation = messages.Revocation.json_loads(jws.payload)
        except ValueError:
            raise acme.messages.Error.with_code("badRevocationReason")

        cert = revocation.certificate

        certificate = await self._db.get_certificate(session, certificate=cert)
        if not certificate:
            raise web.HTTPNotFound

        if account:
            # check that the account holds authorizations for all of the identifiers in the certificate
            if not account.validate_cert(cert):
                raise acme.messages.Error.with_code("unauthorized")
        else:
            # the request was probably signed with the certificate's key pair
            jwk = jws.signature.combined.jwk
            cert_key = josepy.util.ComparableRSAKey(cert.public_key())

            if cert_key != jwk.key:
                raise acme.messages.Error.with_code("malformed")

            if not jws.verify(jwk):
                raise acme.messages.Error.with_code("unauthorized")

        return certificate, revocation

    def _validate_contact_info(self, reg: acme.messages.Registration):
        for contact_url in reg.contact:
            if address := parseaddr(contact_url)[1]:
                # parseaddr also returns things like phone numbers as valid email addresses, skip these.
                if not re.match(r"[^@]+@[^@]+\.[^@]+", address):
                    continue

                # The contact URL contains an email address, validate it.
                if self._mail_suffixes and not any(
                    [address.endswith(suffix) for suffix in self._mail_suffixes]
                ):
                    raise acme.messages.Error.with_code(
                        "invalidContact",
                        detail=f"The contact email '{address}' is not supported.",
                    )

    @routes.get("/directory", name="directory")
    async def directory(self, request):
        """Handler that returns the server's directory.

        `7.1.1. Directory <https://tools.ietf.org/html/rfc8555#section-7.1.1>`_

        Only adds the URL to the ToS if *tos_url* was set during construction.

        :return: The directory object.
        """
        directory = {
            "newAccount": url_for(request, "new-account"),
            "newNonce": url_for(request, "new-nonce"),
            "newOrder": url_for(request, "new-order"),
            "revokeCert": url_for(request, "revoke-cert"),
            "meta": {},
        }

        if self._tos_url:
            directory["meta"]["termsOfService"] = self._tos_url

        return self._response(request, directory)

    @routes.get("/new-nonce", name="new-nonce", allow_head=True)
    async def new_nonce(self, request):
        """Handler that returns a new nonce.

        `7.2. Getting a Nonce <https://tools.ietf.org/html/rfc8555#section-7.2>`_

        :return: The nonce inside the *Replay-Nonce* header.
        """
        return self._response(request, status=204)

    @routes.post("/new-account", name="new-account")
    async def new_account(self, request):
        """Handler that registers a new account.

        `7.3. Account Management <https://tools.ietf.org/html/rfc8555#section-7.3>`_

        May also be used to find an existing account given a key.

        `7.3.1. Finding an Account URL Given a Key <https://tools.ietf.org/html/rfc8555#section-7.3.1>`_

        :raises: :class:`acme.messages.Error` if any of the following are true:

            * The public key's key size is insufficient
            * The account exists but its status is not :attr:`acme_broker.models.AccountStatus.VALID`
            * The client specified *only_return_existing* but no account with that public key exists
            * The client wants to create a new account but did not agree to the terms of service

        :return: The account object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, key_auth=True)
            reg = acme.messages.Registration.json_loads(jws.payload)
            jwk = jws.signature.combined.jwk
            pub_key = jwk.key._wrapped

            if isinstance(pub_key, self.SUPPORTED_ACCOUNT_KEYS):
                if (key_size := pub_key.key_size) < (
                    min_key_size := self._get_min_keysize(pub_key)
                ):
                    raise acme.messages.Error.with_code(
                        "badPublicKey",
                        detail=f"Only keys with at least {min_key_size} bits are accepted. (Keysize: {key_size})",
                    )
            else:
                raise acme.messages.Error.with_code(
                    "badPublicKey",
                    detail=f"At this moment, only the following keys are supported for accounts: "
                    f"{', '.join([key_type.__name__ for key_type in self.SUPPORTED_ACCOUNT_KEYS])}.",
                )

            if account:
                if account.status != models.AccountStatus.VALID:
                    raise acme.messages.Error.with_code("unauthorized")
                else:
                    return self._response(
                        request,
                        account.serialize(request),
                        headers={
                            "Location": url_for(request, "accounts", kid=account.kid)
                        },
                    )
            else:
                if reg.only_return_existing:
                    raise acme.messages.Error.with_code("accountDoesNotExist")
                elif not reg.terms_of_service_agreed:
                    raise acme.messages.Error(
                        typ="urn:ietf:params:acme:error:termsOfServiceNotAgreed",
                        title=f"The client must agree to the terms of service: {self._tos_url}.",
                    )
                else:  # create new account
                    self._validate_contact_info(reg)

                    new_account = models.Account.from_obj(jwk, reg)
                    session.add(new_account)
                    await session.flush()

                    serialized = new_account.serialize(request)
                    kid = new_account.kid
                    await session.commit()

                    return self._response(
                        request,
                        serialized,
                        status=201,
                        headers={"Location": url_for(request, "accounts", kid=kid)},
                    )

    @routes.post("/accounts/{kid}", name="accounts")
    async def accounts(self, request):
        """Handler that updates or queries the given account.

        `7.3.2.  Account Update <https://tools.ietf.org/html/rfc8555#section-7.3.2>`_

        Only updates to the account's status and contact fields are allowed.
        Returns the current account object if no updates were specified.

        :raises:

            * :class:`acme.messages.Error` If the requested update is not allowed.
            * :class:`aiohttp.web.HTTPNotFound` If the account does not exist.

        :return: The account object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            upd = messages.AccountUpdate.json_loads(jws.payload)

            self._validate_contact_info(upd)

            try:
                account.update(upd)
            except ValueError as e:
                raise acme.messages.Error.with_code("malformed", detail=e.args[0])

            serialized = account.serialize(request)

            await session.commit()

        return self._response(request, serialized)

    @routes.post("/new-order", name="new-order")
    async def new_order(self, request):
        """Handler that creates a new order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            obj = acme.messages.NewOrder.json_loads(jws.payload)

            order = models.Order.from_obj(account, obj, self._supported_challenges)
            session.add(order)

            await session.flush()
            serialized = order.serialize(request)
            order_id = order.order_id
            await session.commit()

        return self._response(
            request,
            serialized,
            status=201,
            headers={"Location": url_for(request, "order", id=str(order_id))},
        )

    @routes.post("/authz/{id}", name="authz")
    async def authz(self, request):
        """Handler that updates or queries the given authorization.

        `7.5. Identifier Authorization <https://tools.ietf.org/html/rfc8555#section-7.5>`_

        Only updates to the authorization's status field are allowed.

        `7.5.2.  Deactivating an Authorization <https://tools.ietf.org/html/rfc8555#section-7.5.2>`_

        :raises:

            * :class:`acme.messages.Error` If the requested update is not allowed.
            * :class:`aiohttp.web.HTTPNotFound` If the authorization does not exist.

        :return: The authorization object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            authz_id = request.match_info["id"]
            upd = messages.AuthorizationUpdate.json_loads(jws.payload)

            authorization = await self._db.get_authz(session, account.kid, authz_id)
            if not authorization:
                raise web.HTTPNotFound

            try:
                authorization.update(upd)
            except ValueError as e:
                raise acme.messages.Error.with_code("malformed", detail=e.args[0])

            serialized = authorization.serialize(request)
            await session.commit()

        return self._response(request, serialized)

    @routes.post("/challenge/{id}", name="challenge")
    async def challenge(self, request):
        """Handler that queries the given challenge and initiates its validation.

        `7.5.1. Responding to Challenges <https://tools.ietf.org/html/rfc8555#section-7.5.1>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the challenge does not exist.

        :return: The challenge object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            challenge_id = request.match_info["id"]

            challenge = await self._db.get_challenge(session, account.kid, challenge_id)
            if not challenge:
                raise web.HTTPNotFound

            if challenge.status == models.ChallengeStatus.PENDING:
                challenge.status = models.ChallengeStatus.PROCESSING

            serialized = challenge.serialize(request)
            kid = account.kid
            authz_url = challenge.authorization.url(request)
            await session.commit()

        asyncio.ensure_future(
            self._handle_challenge_validate(request, kid, challenge_id)
        )
        return self._response(request, serialized, links=[f'<{authz_url}>; rel="up"'])

    @routes.post("/revoke-cert", name="revoke-cert")
    async def revoke_cert(self, request):
        """Handler that initiates revocation of the given certificate.

        `7.6.  Certificate Revocation <https://tools.ietf.org/html/rfc8555#section-7.6>`_

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The client specified an unsupported revocation reason
                * The client's account does not hold authorizations for all identifiers in the certificate
                * If the message was signed using the certificate's private key

                    * The public key of the certificate and the JWK differ
                    * The JWS' signature is invalid

        :return: HTTP status code *200* if the revocation succeeded.
        """
        async with self._session(request) as session:
            certificate, revocation = await self._verify_revocation(request, session)

            certificate.revoke(revocation.reason)

            await session.commit()

        return self._response(request, status=200)

    @routes.post("/order/{id}", name="order")
    async def order(self, request):
        """Handler that queries the given order.

        `7.1.3. Order Objects <https://tools.ietf.org/html/rfc8555#section-7.1.3>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(
                request, session, post_as_get=True
            )
            order_id = request.match_info["id"]

            order = await self._db.get_order(session, account.kid, order_id)
            if not order:
                raise web.HTTPNotFound

            await order.validate()

            return self._response(request, order.serialize(request))

    @routes.post("/orders/{id}", name="orders")
    async def orders(self, request):
        """Handler that retrieves the account's orders list.

        `7.1.2.1.  Orders List <https://tools.ietf.org/html/rfc8555#section-7.1.2.1>`_

        :return: An object with key *orders* that holds the account's orders list.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(
                request, session, post_as_get=True
            )

            return self._response(request, {"orders": account.orders_list(request)})

    async def _validate_order(
        self, request, session
    ) -> (models.Order, x509.CertificateSigningRequest):
        jws, account = await self._verify_request(request, session)
        order_id = request.match_info["id"]

        order = await self._db.get_order(session, account.kid, order_id)
        if not order:
            raise web.HTTPNotFound

        await order.validate()

        if order.status == models.OrderStatus.INVALID:
            raise acme.messages.Error(
                typ="orderInvalid",
                detail="This order cannot be finalized because it is invalid.",
            )

        if order.status != models.OrderStatus.READY:
            raise acme.messages.Error.with_code("orderNotReady")

        csr = messages.CertificateRequest.json_loads(jws.payload).csr
        pub_key = csr.public_key()
        logger.debug(
            "Received CSR; Type: %s, Key Size: %s bits", type(pub_key), pub_key.key_size
        )

        if isinstance(pub_key, self.SUPPORTED_CSR_KEYS):
            if (key_size := pub_key.key_size) < (
                min_key_size := self._get_min_keysize(pub_key)
            ):
                raise acme.messages.Error.with_code(
                    "badPublicKey",
                    detail=f"Only keys with at least {min_key_size} bits are accepted. (Keysize: {key_size})",
                )
        else:
            raise acme.messages.Error.with_code(
                "badPublicKey",
                detail=f"At this moment, only the following keys are supported in CSRs: "
                f"{', '.join([key_type.__name__ for key_type in self.SUPPORTED_CSR_KEYS])}.",
            )

        if not csr.is_signature_valid:
            raise acme.messages.Error.with_code(
                "badCSR", detail="The CSR's signature is invalid."
            )
        elif not order.validate_csr(csr):
            raise acme.messages.Error.with_code(
                "badCSR",
                detail="The requested identifiers in the CSR differ from those "
                "that this order has authorizations for.",
            )

        return order, csr

    @routes.post("/order/{id}/finalize", name="finalize-order")
    async def finalize_order(self, request):
        """Handler that initiates finalization of the given order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        Specifically: https://tools.ietf.org/html/rfc8555#page-47

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The order is not in state :class:`acme_broker.models.OrderStatus.READY`
                * The CSR's public key size is insufficient
                * The CSR's signature is invalid
                * The identifiers that the CSR requests differ from those that the \
                    order has authorizations for

        :return: The updated order object.
        """
        async with self._session(request) as session:
            order, csr = await self._validate_order(request, session)

            order.csr = csr
            order.status = models.OrderStatus.PROCESSING

            serialized = order.serialize(request)
            order_id = str(order.order_id)
            kid = order.account_kid
            await session.commit()

        asyncio.ensure_future(self.handle_order_finalize(request, kid, order_id))
        return self._response(
            request,
            serialized,
            headers={"Location": url_for(request, "order", id=order_id)},
        )

    @routes.post("/certificate/{id}", name="certificate")
    async def certificate(self, request):
        """Handler that queries the given certificate.

        `7.4.2. Downloading the Certificate <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
        :return: The certificate's full chain in PEM format.
        """
        raise NotImplementedError

    async def _handle_challenge_validate(self, request, kid, challenge_id):
        logger.debug("Validating challenge %s", challenge_id)

        async with self._session(request) as session:
            challenge = await self._db.get_challenge(session, kid, challenge_id)

            """We want the reverse proxy application to always be able to issue certificates for itself inside the
            Docker container.
            Challenge validation would likely fail in that case. In the RequestIPDNS challenge for example,
            the domain name does not resolve to 127.0.0.1 which is the host IP the request originates.

            For that reason, we start a second instance of the relay that uses loose/no checks but is only
            available within the Docker container.
            """
            validator = self._challenge_validators[challenge.type]
            await challenge.validate(session, request, validator)

            await session.commit()

    async def handle_order_finalize(self, request, kid: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method should be called after the order's status has been set
        to :class:`acme_broker.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        It should retrieve the order from the database and either generate
        the certificate from the stored CSR itself or submit it to another
        CA.

        Afterwards the certificate should be stored alongside the order.
        The *full_chain* attribute needs to be populated and returned
        to the client in :meth:`certificate` if the certificate was
        generated by another CA.

        :param kid: The account's id
        :param order_id: The order's id
        """
        raise NotImplementedError

    @middleware
    async def host_ip_middleware(self, request, handler):
        """Middleware that checks whether the requesting host's IP
        is part of any of the subnets that are whitelisted.

        :returns:

            * HTTP status code *403* if the host's IP is not part of any of the whitelisted subnets.
            * HTTP status code *400* if there is a *X-Forwarded-For* header spoofing attack going on.

        """
        forwarded_for = request.headers.get("X-Forwarded-For")

        """If the X-Forwarded-For header is set, then we need to check whether the app is configured
        to be behind a reverse proxy. Otherwise, there may be a spoofing attack going on."""
        if forwarded_for and not self._use_forwarded_header:
            return web.Response(
                status=400,
                text=f"{type(self).__name__}: The X-Forwarded-For header is being spoofed.",
            )

        """Read the X-Forwarded-For header if the server is behind a reverse proxy.
        Otherwise, use the host address directly."""
        host_ip = ipaddress.ip_address(forwarded_for or request.remote)

        """Attach the actual host IP to the request for re-use in the handler."""
        request["actual_ip"] = host_ip

        if self._subnets and not any([host_ip in subnet for subnet in self._subnets]):
            return web.Response(
                status=403,
                text=f"{type(self).__name__}: This service is only available from within certain networks."
                " Please contact your system administrator.",
            )

        return await handler(request)

    @middleware
    async def aiohttp_jinja2_middleware(self, request, handler):
        if isinstance(handler, functools.partial) and (
            handler := handler.keywords["handler"]
        ):
            # using subapps -> functools.partial
            # aiohttp_jinja2 context
            request[aiohttp_jinja2.REQUEST_CONTEXT_KEY] = {"request": request}
        elif isinstance(handler, types.MethodType):
            if handler.__self__.__class__ == web.AbstractRoute:
                pass
            else:
                request[aiohttp_jinja2.REQUEST_CONTEXT_KEY] = {"request": request}
        elif isinstance(handler, types.FunctionType):  # index_of
            pass
        else:
            raise TypeError(handler)
        return await handler(request)

    @middleware
    async def error_middleware(self, request, handler):
        """Middleware that converts errors thrown in handlers to ACME compliant JSON and
        attaches the specified status code to the response.

        :returns: The ACME error converted to JSON.
        """
        try:
            response = await handler(request)
        except acme.messages.Error as error:
            serialized = error.json_dumps()
            logger.debug("Returned ACME error: %s", serialized)
            return self._response(
                request,
                text=serialized,
                status=messages.get_status(error.code),
                content_type="application/problem+json",
            )
        else:
            return response


class AcmeCA(AcmeServerBase):
    """ACME compliant Certificate Authority."""

    config_name = "ca"

    SUPPORTED_CSR_KEYS = (rsa.RSAPublicKey,)

    def __init__(self, *, cert, private_key, **kwargs):
        super().__init__(**kwargs)

        with open(cert, "rb") as pem:
            self._cert = x509.load_pem_x509_certificate(pem.read())

        with open(private_key, "rb") as pem:
            self._private_key = serialization.load_pem_private_key(pem.read(), None)

    @classmethod
    async def create_app(cls, config, **kwargs):
        db = Database(config["db"])

        ca = cls(
            **config,
            **kwargs,
        )
        ca._db = db
        ca._db_session = db.session

        return ca

    async def handle_order_finalize(self, request, kid: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acme_broker.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        It retrieves the order from the database and generates
        the certificate from the stored CSR, signing it using the CA's private key.

        Afterwards the certificate is stored alongside the order.

        :param kid: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            order = await self._db.get_order(session, kid, order_id)

            cert = generate_cert_from_csr(order.csr, self._cert, self._private_key)
            order.certificate = models.Certificate(
                status=models.CertificateStatus.VALID, cert=cert
            )

            order.status = models.OrderStatus.VALID
            await session.commit()

    # @routes.post("/certificate/{id}", name="certificate")
    async def certificate(self, request):
        async with self._session(request) as session:
            jws, account = await self._verify_request(
                request, session, post_as_get=True
            )
            certificate_id = request.match_info["id"]

            certificate = await self._db.get_certificate(
                session, account.kid, certificate_id
            )
            if not certificate:
                raise web.HTTPNotFound

            return self._response(
                request,
                text=certificate.cert.public_bytes(serialization.Encoding.PEM).decode()
                + self._cert.public_bytes(serialization.Encoding.PEM).decode(),
            )


class AcmeRelayBase(AcmeServerBase):
    """Base for an ACME server that relays requests to a remote CA using an internal ACME client.

    The account that is used to sign requests to the remote CA is shared between all users of the relay server.

    At this time, challenges and authorizations are not shared between the relay server and
    the remote CA. Instead, the relay has to make sure that all authorizations for a given order
    are valid before applying for certificate issuance.
    """

    def __init__(self, *, client, **kwargs):
        super().__init__(**kwargs)
        self._client = client

    @classmethod
    async def create_app(
        cls, config: typing.Dict[str, typing.Any], **kwargs
    ) -> "AcmeRelayBase":
        """A factory that also creates and initializes the database and session objects,
        reading the necessary arguments from the passed config dict.

        :param config: A dictionary holding the configuration. See :doc:`configuration` for supported options.
        :return: The server instance
        """
        db = Database(config["db"])

        config.pop("client")

        instance = cls(
            **config,
            **kwargs,
        )
        instance._db = db
        instance._db_session = db.session

        return instance

    # @routes.post("/certificate/{id}", name="certificate")
    async def certificate(self, request):
        """Handler that queries the given certificate.

        `7.4.2. Downloading the Certificate <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_

        Returns the full chain as retrieved from the CA by the internal client.

        :raises: :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
        :return: The certificate's full chain in PEM format.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(
                request, session, post_as_get=True
            )
            certificate_id = request.match_info["id"]

            certificate = await self._db.get_certificate(
                session, account.kid, certificate_id
            )
            if not certificate:
                raise web.HTTPNotFound

            return self._response(
                request,
                text=certificate.full_chain,
            )

    # @routes.post("/revoke-cert", name="revoke-cert")
    async def revoke_cert(self, request):
        """Handler that initiates revocation of the given certificate.

        `7.6.  Certificate Revocation <https://tools.ietf.org/html/rfc8555#section-7.6>`_

        The revocation is first relayed to the remote CA using the internal client
        before being processed internally.

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The client specified an unsupported revocation reason
                * The client's account does not hold authorizations for all identifiers in the certificate
                * If the message was signed using the certificate's private key

                    * The public key of the certificate and the JWK differ
                    * The JWS' signature is invalid

        :return: HTTP status code *200* if the revocation succeeded.
        """
        async with self._session(request) as session:
            certificate, revocation = await self._verify_revocation(request, session)

            revocation_succeeded = await self._client.certificate_revoke(
                certificate.cert, reason=revocation.reason
            )
            if not revocation_succeeded:
                raise acme.messages.Error.with_code("unauthorized")

            certificate.revoke(revocation.reason)

            await session.commit()

        return self._response(request, status=200)

    async def _obtain_and_store_cert(
        self, order: models.Order, order_ca: acme.messages.Order
    ):
        full_chain = await self._client.certificate_get(order_ca)
        certs = pem_split(full_chain)

        if len(certs) < 2:
            logger.info(
                "Less than two certs in full chain for order %s. Cannot store client cert",
                order.order_id,
            )
            order.status = models.OrderStatus.INVALID
        else:
            order.certificate = models.Certificate(
                status=models.CertificateStatus.VALID,
                cert=certs[0],
                full_chain=full_chain,
            )

            order.status = models.OrderStatus.VALID


class AcmeBroker(AcmeRelayBase):
    """Server that relays requests to a remote CA employing a "broker" model.

    Orders are only relayed to the remote CA when the finalization is already processing.
    This means that errors that may occur at the remote CA during order creation or finalization
    cannot be shown to the end user transparently. If that is a concern, then
    the :class:`AcmeProxy` class should be used instead.
    """

    config_name = "broker"

    async def handle_order_finalize(self, request, kid: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acme_broker.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        The order is relayed to the remote CA here and the entire
        certificate acquisition process is handled by the internal client.
        The obtained certificate's full chain is then stored in the database.

        If the certificate acquisition fails, then the order's status is set
        to :class:`acme_broker.models.OrderStatus.INVALID`.

        :param kid: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            order = await self._db.get_order(session, kid, order_id)

            try:
                order_ca = await self._client.order_create(list(names_of(order.csr)))
                await self._client.authorizations_complete(order_ca)
                finalized = await self._client.order_finalize(order_ca, order.csr)
                await self._obtain_and_store_cert(order, finalized)
            except acme.messages.Error as e:
                logger.info("Could not create order %s with remote CA: %s", order_id, e)
                order.proxied_error = e
                order.status = models.OrderStatus.INVALID
            except CouldNotCompleteChallenge as e:
                logger.info(
                    "Could not complete challenge %s associated with order %s",
                    e.challenge.uri,
                    order_id,
                )
                order.proxied_error = e.challenge.error
                order.status = models.OrderStatus.INVALID
            except AcmeClientException as e:
                logger.info(
                    "Could not complete a challenge associated with order %s due to a general client exception: %s",
                    order_id,
                    e,
                )
                order.status = models.OrderStatus.INVALID

            await session.commit()


class AcmeProxy(AcmeRelayBase):
    """Server that relays requests to a remote CA employing a "proxy" model.

    Orders are relayed to the remote CA transparently, which allows for
    the possibility to show errors to the end user as they occur at the remote CA.
    """

    config_name = "proxy"

    # @routes.post("/new-order", name="new-order")
    async def new_order(self, request):
        """Handler that creates a new order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        The order is also relayed to the remote CA by the internal client.
        This means that errors that might occur during the creation process
        are transparently shown to the end user.

        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            obj = acme.messages.NewOrder.json_loads(jws.payload)

            identifiers = [
                {"type": identifier.typ, "value": identifier.value}
                for identifier in obj.identifiers
            ]
            order_ca = await self._client.order_create(identifiers)

            order = models.Order.from_obj(account, obj, self._supported_challenges)
            order.proxied_url = order_ca.url
            session.add(order)

            await session.flush()
            serialized = order.serialize(request)
            kid = account.kid
            order_id = order.order_id
            await session.commit()

        asyncio.ensure_future(self._complete_challenges(request, kid, order_id))
        return self._response(
            request,
            serialized,
            status=201,
            headers={"Location": url_for(request, "order", id=str(order_id))},
        )

    async def _complete_challenges(self, request, kid, order_id):
        logger.debug("Completing challenges for order %s", order_id)
        async with self._session(request) as session:
            order = await self._db.get_order(session, kid, order_id)

            order_ca = await self._client.order_get(order.proxied_url)
            try:
                await self._client.authorizations_complete(order_ca)
            except CouldNotCompleteChallenge as e:
                logger.info(
                    "Could not complete challenge %s associated with order %s",
                    e.challenge.uri,
                    order_id,
                )
                order.proxied_error = e.challenge.error
                order.status = models.OrderStatus.INVALID
            except AcmeClientException as e:
                logger.info(
                    "Could not complete a challenge associated with order %s due to a general client exception: %s",
                    order_id,
                    e,
                )
                order.status = models.OrderStatus.INVALID

            await session.commit()

    # @routes.post("/order/{id}/finalize", name="finalize-order")
    async def finalize_order(self, request):
        """Handler that initiates finalization of the given order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        Specifically: https://tools.ietf.org/html/rfc8555#page-47

        The order is refetched via the client using the stored *proxied_url*.
        The client then attempts to finalize the order at the remote CA.
        If an error is raised here, then it is transparently shown to the end user.

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The order is not in state :class:`acme_broker.models.OrderStatus.READY`
                * The CSR's public key size is insufficient
                * The CSR's signature is invalid
                * The identifiers that the CSR requests differ from those that the \
                    order has authorizations for

        :return: The updated order object.
        """
        async with self._session(request) as session:
            order, csr = await self._validate_order(request, session)
            order_ca = await self._client.order_get(order.proxied_url)

            try:
                """AcmeClient.order_finalize does not return if the order never becomes valid.
                Thus, we handle that case here and set the order's status to invalid
                if the CA takes too long."""
                await asyncio.wait_for(self._client.order_finalize(order_ca, csr), 10.0)
            except asyncio.TimeoutError:
                # TODO: consider returning notReady instead to let the client try again
                order.status = models.OrderStatus.INVALID
            else:
                """The CA's order is valid, we can set our order's status to PROCESSING and
                request the certificate from the CA in _handle_order_finalize."""
                order.status = models.OrderStatus.PROCESSING

            order.csr = csr
            serialized = order.serialize(request)
            kid = order.account_kid
            order_id = str(order.order_id)
            order_processing = order.status == models.OrderStatus.PROCESSING
            await session.commit()

        if order_processing:
            asyncio.ensure_future(self.handle_order_finalize(request, kid, order_id))

        return self._response(
            request,
            serialized,
            headers={"Location": url_for(request, "order", id=order_id)},
        )

    async def handle_order_finalize(self, request, kid: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acme_broker.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        The order is refetched from the remote CA here after which the internal client
        downloads the certificate and stores its full chain in the database.

        :param kid: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            order = await self._db.get_order(session, kid, order_id)

            order_ca = await self._client.order_get(order.proxied_url)
            await self._obtain_and_store_cert(order, order_ca)

            await session.commit()
