import abc
import asyncio
import collections
import cProfile
import datetime
import functools
import ipaddress
import json
import logging
import pstats
import re
import string
import types
import typing
import uuid
from email.utils import parseaddr

import acme.jws
import acme.messages
import aiohttp_jinja2
import josepy
import yarl
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.web_middlewares import middleware
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

import pydantic
from pydantic import Field
from pydantic_settings import BaseSettings

import acmetk.util
from acmetk.server.metrics import PrometheusMetricsMixin
from acmetk.util import CertID
from acmetk import models
from acmetk.client import CouldNotCompleteChallenge, AcmeClientException, AcmeClient
from acmetk.database import Database
from acmetk.models import messages
from acmetk.server import ChallengeValidator
from acmetk.server.base import ServiceBase
from acmetk.server.external_account_binding import AcmeEABMixin
from acmetk.server.management import AcmeManagementMixin
from acmetk.server.routes import routes
from acmetk.version import __version__
from acmetk.plugin_base import PluginRegistry

if typing.TYPE_CHECKING:
    import aiohttp

logger = logging.getLogger(__name__)

ChallengeValidatorRegistry = PluginRegistry.get_registry(ChallengeValidator)


async def handle_get(request: web.Request) -> web.Response:
    return web.Response(status=405)


class AcmeResponse(web.Response):
    def __init__(self, nonce, directory_url, *args, links=None, **kwargs):
        super().__init__(*args, **kwargs)
        if links is None:
            links = []

        links.append(f'<{directory_url}>; rel="index"')
        self.headers.extend(("Link", link) for link in links)

        self.headers.update(
            {
                "Server": f"acmetk Server {__version__}",
                "Replay-Nonce": nonce,
                "Cache-Control": "no-store",
            }
        )


async def on_startup(app: web.Application):
    pass


async def on_shutdown(app: web.Application):
    obj: AcmeServerBase = app[AcmeServerBase.ServerKey]
    await obj.on_shutdown(app)


async def on_cleanup(app: web.Application):
    obj: AcmeServerBase = app[AcmeServerBase.ServerKey]
    await obj.on_cleanup(app)


class AcmeServerBase(PrometheusMetricsMixin, AcmeEABMixin, AcmeManagementMixin, ServiceBase, abc.ABC):
    """Base class for an ACME compliant server.

    Implementations must also be registered with the plugin registry via
    :meth:`~acmetk.plugin_base.PluginRegistry.register_plugin`, so that the CLI script knows which configuration
    option corresponds to which server class.
    """

    ServerKey: web.AppKey

    ORDERS_LIST_CHUNK_LEN = 10
    """Number of order links to include per request."""

    SUPPORTED_JWS_ALGORITHMS = (
        josepy.jwa.RS256,
        josepy.jwa.RS384,
        josepy.jwa.RS512,
        josepy.jwa.PS256,
        josepy.jwa.PS384,
        josepy.jwa.PS512,
        josepy.jwa.ES256,
        josepy.jwa.ES384,
        josepy.jwa.ES512,
    )
    """The JWS signing algorithms that the server supports."""

    SUPPORTED_EAB_JWS_ALGORITHMS = (
        josepy.jwa.HS256,
        josepy.jwa.HS384,
        josepy.jwa.HS512,
    )
    """The symmetric JWS signing algorithms that the server supports for external account bindings."""

    SUPPORTED_ACCOUNT_KEYS = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
    """The types of public keys that the server supports when creating ACME accounts."""

    SUPPORTED_CSR_KEYS = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
    """The types of public keys that the server supports in a certificate signing request."""

    VALID_DOMAIN_RE = re.compile(
        r"^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*"
        r"(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$"
    )

    """using from https://stackoverflow.com/questions/
    10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd

    better than nothing, but  accepts names ending with -
    """

    AuthorizationLifetimeDays: int = 7
    PendingAuthorizationLifetimeDays: int = 29
    """
    https://github.com/letsencrypt/boulder/blob/3fcaebe934a5f52440976b38a05aa43b743dbe92/cmd/boulder-ra/main.go#L258
    """

    class Config(BaseSettings):
        rsa_min_keysize: int = 2048
        """
        minmum RSA keysize in bits
        """

        ec_min_keysize: int = 256
        """
        minimum EC keysize in bits
        """
        tos_url: str = ""
        """
        terms of service url
        """
        mail_suffixes: list[str] = Field(default_factory=list)
        """
        allowed mail suffixes for EAB
        """
        subnets: list[str] = Field(default_factory=list)
        """
        no idea
        """
        use_forwarded_header: bool = False
        """
        retrieve client ip address from X-Forwarded-For header
        """
        allow_wildcard: bool = False
        """
        allow wildcard certificates
        """
        challenge_validators: list[typing.Literal["dns01", "http01", "tlsalpn01", "requestipdns", "dummy"]] = Field(
            default_factory=list
        )
        """
        list of challenge validators to use for validation
        """
        hostname: str = ""
        """hostname of the server - e.g. 0.0.0.0 or localhost"""
        port: int = 0
        """port to bind to"""
        path: str = ""
        """
        unix domain socket - exclusive with host,port
        """
        db: pydantic.PostgresDsn = ""
        """
        database connection string
        """
        mgmt: AcmeManagementMixin.Config = Field(
            default_factory=lambda: AcmeManagementMixin.Config(authentication=False)
        )
        """
        management ui configuration
        """
        eab: AcmeEABMixin.Config = Field(default_factory=lambda: AcmeEABMixin.Config(required=False))
        """
        External Authentication Binding configuration
        """

        metrics: PrometheusMetricsMixin.Config = Field(
            default_factory=lambda: PrometheusMetricsMixin.Config(enable=False)
        )
        """
        prometheus metrics export at /metrics
        """

    def __init__(
        self,
        cfg: Config,
    ):
        self._mgmt_cfg: AcmeManagementMixin.Config = cfg.mgmt
        self._eab_cfg: AcmeEABMixin.Config = cfg.eab
        self._metrics_cfg: PrometheusMetricsMixin.Config = cfg.metrics

        super().__init__()

        self._keysize: dict[str, dict[type, tuple[int, int]]] = {
            "csr": {
                rsa.RSAPublicKey: (cfg.rsa_min_keysize, 4096),
                ec.EllipticCurvePublicKey: (cfg.ec_min_keysize, 384),
            },
            "account": {
                rsa.RSAPublicKey: (cfg.rsa_min_keysize, 4096),
                ec.EllipticCurvePublicKey: (cfg.ec_min_keysize, 521),
            },
        }
        self._tos_url: str = cfg.tos_url
        self._mail_suffixes: list[str] = cfg.mail_suffixes
        self._subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
            [ipaddress.ip_network(subnet) for subnet in cfg.subnets] if cfg.subnets else []
        )
        self._use_forwarded_header: bool = cfg.use_forwarded_header
        self._allow_wildcard: bool = cfg.allow_wildcard

        middlewares = [
            self.error_middleware,
            self.host_ip_middleware,
            self.mgmt_auth_middleware,
            self.aiohttp_jinja2_middleware,
        ]

        if self._metrics_cfg.enable:
            from acmetk.server.metrics import prometheus_middleware_factory

            prometheus_middleware = prometheus_middleware_factory(
                metrics_prefix="acmetk", registry=self._metrics_registry
            )
            middlewares = [*middlewares[:2], prometheus_middleware, *middlewares[2:]]

        self.app = web.Application(
            middlewares=middlewares,
        )

        self._add_routes()

        self._nonces: set[str] = set()

        self._db: Database = Database(str(cfg.db))
        self._db_session: sessionmaker = self._db.session

        self._challenge_validators: dict[str, ChallengeValidator] = {}

        self.register_challenge_validators(
            [ChallengeValidatorRegistry.get_plugin(name)() for name in cfg.challenge_validators]
        )

    async def on_startup(self, app: web.Application):
        await super().on_startup(app)

    async def on_run(self, app: web.Application):
        await super().on_run(app)

    async def on_shutdown(self, app: web.Application):
        await super().on_shutdown(app)

    async def on_cleanup(self, app: web.Application):
        await super().on_cleanup(app)
        await self._db.engine.dispose()

    def _match_keysize(self, public_key, what):
        for key_type, key_size in self._keysize[what].items():
            if isinstance(public_key, key_type):
                (low, high) = key_size
                break
        else:
            raise ValueError("This key type is not supported.")
        if low <= public_key.key_size <= high:
            return
        raise ValueError(
            f"{public_key.__class__.__name__} Keysize for {what} has to be {low} <= {public_key.key_size=} <= {high}"
        )

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
    async def create_app(cls, config: Config) -> "AcmeServerBase":
        """A factory that also creates and initializes the database and session objects,
        reading the necessary arguments from the passed config dict.

        :param config: A Config object holding the configuration. See :doc:`configuration` for supported options.
        :return: The server instance
        """
        instance: AcmeServerBase = cls(config)
        instance.app[AcmeServerBase.ServerKey] = instance
        instance.app.on_startup.append(instance.on_startup)
        instance.app.on_cleanup.append(instance.on_cleanup)
        instance.app.on_shutdown.append(instance.on_shutdown)
        return instance

    def _session(self, request: web.Request) -> AsyncSession:
        return self._db_session(info={"remote_host": request.get("actual_ip", "0.0.0.0")})

    @classmethod
    async def runner(cls, config: Config) -> tuple["aiohttp.web.AppRunner", "AcmeServerBase"]:
        """A factory that starts the server on the given hostname and port using an AppRunner
        after constructing a server instance using :meth:`.create_app`.

        :param config: A dictionary holding the configuration. See :doc:`configuration` for supported options.
        :param kwargs: Additional kwargs are passed to the :meth:`.create_app` call.
        :return: A tuple containing the app runner as well as the server instance.
        """
        instance = await cls.create_app(config)

        runner = web.AppRunner(instance.app)
        await runner.setup()

        if config.hostname and config.port:
            site = web.TCPSite(runner, config.hostname, config.port)
        elif config.path:
            site = web.UnixSite(runner, config.path)
        await site.start()
        await instance.on_run(instance.app)

        return runner, instance

    def register_challenge_validators(self, validators: list[ChallengeValidator]):
        """Registers a list of :class:`ChallengeValidator` with the server.
        :param validators: A list of :class:`ChallengeValidator` instances.
        """
        for v in validators:
            self.register_challenge_validator(v)

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
                raise ValueError(f"A challenge validator for type {challenge_type} is already registered")
            else:
                self._challenge_validators[challenge_type] = validator

    @property
    def _supported_challenges(self):
        return self._challenge_validators.keys()

    def _response(self, request: web.Request, data=None, text=None, *args, **kwargs) -> web.Response:
        if data and text:
            raise ValueError("only one of data, text, or body should be specified")
        elif data and (data is not sentinel):
            text = json.dumps(data)
            kwargs.update({"content_type": "application/json"})
        else:
            text = data or text

        return AcmeResponse(
            self._issue_nonce(),
            acmetk.util.url_for(request, "directory"),
            *args,
            **kwargs,
            text=text,
        )

    def _issue_nonce(self) -> str:
        nonce = uuid.uuid4().hex
        self._nonces.add(nonce)
        return nonce

    def _verify_nonce(self, nonce: str) -> None:
        if nonce in self._nonces:
            self._nonces.remove(nonce)
        else:
            raise acme.messages.Error.with_code("badNonce", detail=nonce)

    async def _verify_request(
        self,
        request: web.Request,
        session: AsyncSession,
        key_auth: bool = False,
        post_as_get: bool = False,
        expunge_account: bool = True,
    ) -> tuple[acme.jws.JWS, models.Account]:
        """Verifies an ACME request whose payload is encapsulated in a JWS.

        `6.2. Request Authentication <https://tools.ietf.org/html/rfc8555#section-6.2>`_

        All requests to handlers apart from :meth:`new_nonce` and :meth:`directory`
        are authenticated.

        :param key_auth: *True* if the JWK inside the JWS should be used to \
            verify its signature. False otherwise
        :param post_as_get: *True* if a `POST-as-GET <https://tools.ietf.org/html/rfc8555#section-6.3>`_ \
            request is expected. False otherwise
        :param expunge_account: *True* if the account object should be expunged from the session. \
            Needs to be False if the account object is to be updated in the database later.
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
                * The client supplied a bad nonce in the JWS' protected header
                * The JWS does not have *either* a JWK *or* a kid
                * The JWS' signature is invalid
                * There is a mismatch between the URL's kid and the JWS' kid
                * The account corresponding to the kid does not have status \
                    :attr:`acmetk.models.AccountStatus.VALID`
        """
        data = await request.text()
        account_id: str
        account: models.Account | None
        try:
            jws = acme.jws.JWS.json_loads(data)
        except josepy.errors.DeserializationError:
            raise acme.messages.Error.with_code("malformed", detail="The request does not contain a valid JWS.")

        if post_as_get and jws.payload != b"":
            raise acme.messages.Error.with_code(
                "malformed",
                detail='The request payload must be b"" in a POST-as-GET request.',
            )

        sig: acme.jws.Header = jws.signature.combined

        if sig.url != str(acmetk.util.forwarded_url(request)):
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
            # check whether key was supplied - josepy.errors.Error: No key found - malformed
            if not jws.verify(sig.jwk):
                raise acme.messages.Error.with_code("unauthorized")
            else:
                account = await self._db.get_account(session, key=sig.jwk)
        elif sig.kid:
            account_id = yarl.URL(sig.kid).name

            if acmetk.util.url_for(request, "accounts", account_id=account_id) != sig.kid:
                """Bug in the dehydrated client, accepted by boulder, so we accept it too.
                Dehydrated puts .../new-account/{kid} into the request signature, instead of
                .../accounts/{kid}."""
                kid_new_account_route = yarl.URL(acmetk.util.url_for(request, "new-account"))
                kid_new_account_route = kid_new_account_route.with_path(kid_new_account_route.path + "/" + account_id)
                if str(kid_new_account_route) == sig.kid:
                    logger.debug("Buggy client kid account mismatch")
                else:
                    raise acme.messages.Error.with_code("malformed")
            elif "account_id" in request.match_info and request.match_info["account_id"] != account_id:
                raise acme.messages.Error.with_code("malformed")

            account = await self._db.get_account(session, account_id=account_id)

            if account is None:
                logger.info("Could not find account with account_id %s", account_id)
                raise acme.messages.Error.with_code("accountDoesNotExist")

            if account.status != models.AccountStatus.VALID:
                raise acme.messages.Error.with_code("unauthorized")

            if not jws.verify(account.key):
                raise acme.messages.Error.with_code("unauthorized")
        else:
            raise acme.messages.Error.with_code("malformed")

        # Fix bug where models that contain the "account" object do not get populated properly -
        # most likely due to caching.
        if account and expunge_account:
            session.expunge(account)

        return jws, account

    async def _verify_revocation(
        self, request: web.Request, session: AsyncSession
    ) -> (models.Certificate, messages.Revocation):
        jws: acme.jws.JWS
        account: models.Account | None
        certificate: models.Certificate
        try:
            # check whether the message is signed using an account key
            jws, account = await self._verify_request(request, session)
        except acme.messages.Error:
            data = await request.text()

            try:
                jws = acme.jws.JWS.json_loads(data)
            except josepy.errors.DeserializationError:
                raise acme.messages.Error.with_code("malformed", detail="The request does not contain a valid JWS.")
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
            # Check whether the cert was originally issued for that account
            if not certificate.account_of.account_id == account.account_id:
                raise acme.messages.Error.with_code("unauthorized")
        else:
            # The request was probably signed with the certificate's key pair
            jwk = jws.signature.combined.jwk
            if isinstance(
                cert_key := cert.public_key(),
                ec.EllipticCurvePublicKeyWithSerialization,
            ):
                cert_key = josepy.util.ComparableECKey(cert_key)
            elif isinstance(cert_key := cert.public_key(), rsa.RSAPublicKeyWithSerialization):
                cert_key = josepy.util.ComparableRSAKey(cert_key)

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
                if self._mail_suffixes and not any([address.endswith(suffix) for suffix in self._mail_suffixes]):
                    raise acme.messages.Error.with_code(
                        "invalidContact",
                        detail=f"The contact email '{address}' is not supported.",
                    )

    def _verify_order(self, obj: acme.messages.NewOrder, wildcardonly=False):
        """Verify the identifiers in an Order

        Remove wildcards and validate with regex

        :raises:

            * :class:`acme.messages.Error` If the Order has invalid identifiers.
        """

        identifiers_: dict[str, list[acme.messages.Identifier]] = collections.defaultdict(list)
        for i in obj.identifiers:
            identifiers_[i.typ.name].append(i)

        try:
            for k, identifiers in identifiers_.items():
                if k == models.IdentifierType.DNS:
                    # wildcard
                    if self._allow_wildcard is False and True in set(
                        map(
                            lambda identifier: identifier.value.startswith("*"),
                            identifiers,
                        )
                    ):
                        raise ValueError("The ACME server can not issue a wildcard certificate")
                    if wildcardonly:
                        return

                    # idna decoding xn-- …
                    try:
                        list(
                            map(
                                lambda identifier: identifier.value.encode("ascii").decode("idna"),
                                identifiers,
                            )
                        )
                    except UnicodeError:
                        raise ValueError("Domain name contains malformed punycode")

                    # not lowercase
                    r = set(
                        map(
                            lambda identifier: identifier.value.lower() == identifier.value,
                            identifiers,
                        )
                    )
                    if False in r:
                        raise ValueError("Domain name is not lowercase")

                    # regex
                    r = set(
                        map(
                            lambda identifier: self.VALID_DOMAIN_RE.match(identifier.value.lstrip("*.")) is not None,
                            identifiers,
                        )
                    )
                    if False in r:
                        raise ValueError("Domain name contains an invalid character")

                    # ends with a letter
                    r = set(
                        map(
                            lambda identifier: identifier.value[-1] in string.ascii_lowercase,
                            identifiers,
                        )
                    )
                    if False in r:
                        raise ValueError("Domain name does not end with a valid public suffix (TLD)")
                elif k == "ip":
                    try:
                        [ipaddress.ip_address(i.value) for i in identifiers]
                    except TypeError:
                        raise ValueError(i.value)

                else:
                    raise ValueError(f"unknown identifier type {k}")

        except ValueError as e:
            raise acme.messages.Error.with_code("rejectedIdentifier", detail=e.args[0])

    def _directory_data(self, request):
        directory = {
            "newAccount": acmetk.util.url_for(request, "new-account"),
            "newNonce": acmetk.util.url_for(request, "new-nonce"),
            "newOrder": acmetk.util.url_for(request, "new-order"),
            "revokeCert": acmetk.util.url_for(request, "revoke-cert"),
            "keyChange": acmetk.util.url_for(request, "key-change"),
            "renewalInfo": acmetk.util.url_for(request, "renewal-info", aci="")[:-1],
            "meta": {
                "profiles": {
                    "classic": "https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/",
                    "shortlived": "https://letsencrypt.org/2025/01/16/6-day-and-ip-certs/",
                }
            },
        }

        if self._tos_url:
            directory["meta"]["termsOfService"] = self._tos_url

        if self._eab_cfg.required is not None:
            directory["meta"]["externalAccountRequired"] = self._eab_cfg.required
        return directory

    @routes.get("/directory", name="directory")
    async def directory(self, request: web.Request) -> web.Response:
        """Handler that returns the server's directory.

        `7.1.1. Directory <https://tools.ietf.org/html/rfc8555#section-7.1.1>`_

        Only adds the URL to the ToS if *tos_url* was set during construction.

        :return: The directory object.
        """
        directory = self._directory_data(request)
        return self._response(request, directory)

    @routes.get("/new-nonce", name="new-nonce", allow_head=True)
    async def new_nonce(self, request: web.Request) -> web.Response:
        """Handler that returns a new nonce.

        `7.2. Getting a Nonce <https://tools.ietf.org/html/rfc8555#section-7.2>`_

        :return: The nonce inside the *Replay-Nonce* header.
        """
        if request.method == "GET":
            return self._response(request, status=204)
        else:
            "request.method == 'HEAD'"
            return self._response(request, status=200)

    @routes.post("/new-account", name="new-account")
    async def new_account(self, request: web.Request) -> web.Response:
        """Handler that registers a new account.

        `7.3. Account Management <https://tools.ietf.org/html/rfc8555#section-7.3>`_

        May also be used to find an existing account given a key.

        `7.3.1. Finding an Account URL Given a Key <https://tools.ietf.org/html/rfc8555#section-7.3.1>`_

        :raises: :class:`acme.messages.Error` if any of the following are true:

            * The public key's key size is insufficient
            * The account exists but its status is not :attr:`acmetk.models.AccountStatus.VALID`
            * The client specified *only_return_existing* but no account with that public key exists
            * The client wants to create a new account but did not agree to the terms of service

        :return: The account object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, key_auth=True)
            reg = acme.messages.Registration.json_loads(jws.payload)
            jwk = jws.signature.combined.jwk
            pub_key: RSAPublicKey | EllipticCurvePublicKey = jwk.key._wrapped

            self._validate_account_key(pub_key)

            if account:
                if account.status != models.AccountStatus.VALID:
                    raise acme.messages.Error.with_code("unauthorized")
                else:
                    return self._response(
                        request,
                        account.serialize(request),
                        headers={
                            "Location": acmetk.util.url_for(request, "accounts", account_id=str(account.account_id))
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
                    if self._eab_cfg.required:
                        self.verify_eab(request, pub_key, reg)

                    self._validate_contact_info(reg)

                    new_account = models.Account.from_obj(jwk, reg)
                    session.add(new_account)
                    await session.flush()

                    serialized = new_account.serialize(request)
                    account_id = new_account.account_id
                    await session.commit()

                    return self._response(
                        request,
                        serialized,
                        status=201,
                        headers={"Location": acmetk.util.url_for(request, "accounts", account_id=str(account_id))},
                    )

    def _validate_account_key(self, pub_key: RSAPublicKey | EllipticCurvePublicKey):
        if isinstance(pub_key, self.SUPPORTED_ACCOUNT_KEYS):
            try:
                self._match_keysize(pub_key, "account")
            except ValueError as e:
                raise acme.messages.Error.with_code(
                    "badPublicKey",
                    detail=e.args[0],
                )
        else:
            raise acme.messages.Error.with_code(
                "badPublicKey",
                detail=f"At this moment, only the following keys are supported for accounts: "
                f"{', '.join([key_type.__name__ for key_type in self.SUPPORTED_ACCOUNT_KEYS])}.",
            )

    @routes.post("/accounts/{account_id}", name="accounts")
    async def accounts(self, request: web.Request) -> web.Response:
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
            jws, account = await self._verify_request(request, session, expunge_account=False)
            upd: messages.AccountUpdate = messages.AccountUpdate.json_loads(jws.payload)

            if self._eab_cfg.required and upd.contact:
                raise acme.messages.Error.with_code(
                    "unauthorized",
                    detail="Updates to the contact field are not allowed since external account binding is required.",
                )

            self._validate_contact_info(upd)

            try:
                account.update(upd)
            except ValueError as e:
                raise acme.messages.Error.with_code("malformed", detail=e.args[0])

            serialized = account.serialize(request)

            await session.commit()

        return self._response(request, serialized)

    @routes.post("/new-order", name="new-order")
    async def new_order(self, request: web.Request) -> web.Response:
        """Handler that creates a new order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            obj = messages.NewOrder.json_loads(jws.payload)
            self._verify_order(obj)
            if obj.replaces:
                """
                https://www.rfc-editor.org/rfc/rfc9773.html#name-extensions-to-the-order-obj

                Servers SHOULD check that …
                """
                repl: models.Certificate

                repl = await self._db.get_certificate(session, certid=obj.replaces)
                if repl is None:
                    raise acme.messages.Error.with_code(
                        "serverInternal",
                        detail="could not find an order for the given certificate",
                    )

                if repl.account_of.account_id != account.account_id:
                    """the identified certificate and the newOrder request correspond to the same ACME Account,"""
                    raise acme.messages.Error.with_code(
                        "unauthorized",
                        detail="requester account did not request the certificate being replaced by this order",
                    )

                if not (
                    {(i.type.value, i.value) for i in repl.order.identifiers}
                    & {(i.typ.name, i.value) for i in obj.identifiers}
                ):
                    """that they share at least one identifier,"""
                    raise acme.messages.Error.with_code(
                        "serverInternal",
                        detail="at least one identifier in the new order and existing order must match",
                    )

                if repl.replaced_by and any(i.status != models.OrderStatus.INVALID for i in repl.replaced_by):
                    """
                    and that the identified certificate has not already been marked as replaced by a different Order
                    that is not "invalid"
                    """
                    raise acme.messages.Error.with_code(
                        "alreadyReplaced",
                        detail=(
                            "The request specified a predecessor certificate which has already beenmarked as replaced."
                        ),
                    )

                # Can't attach instance <Account at 0x…>;
                # another instance with key (<class 'acmetk.models.base.Entity'>, (…,), None)
                # is already present in this session.
                session.expunge_all()

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
            headers={"Location": acmetk.util.url_for(request, "order", id=str(order_id))},
        )

    @routes.post("/authz/{id}", name="authz")
    async def authz(self, request: web.Request) -> web.Response:
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

            authorization = await self._db.get_authz(session, account.account_id, authz_id)
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
    async def challenge(self, request: web.Request) -> web.Response:
        """Handler that queries the given challenge and initiates its validation.

        `7.5.1. Responding to Challenges <https://tools.ietf.org/html/rfc8555#section-7.5.1>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the challenge does not exist.

        :return: The challenge object.
        """

        validate_challenge = True
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            challenge_id = request.match_info["id"]

            challenge = await self._db.get_challenge(session, account.account_id, challenge_id)
            if not challenge:
                raise web.HTTPNotFound

            if challenge.status == models.ChallengeStatus.PENDING:
                challenge.status = models.ChallengeStatus.PROCESSING
            else:
                validate_challenge = False

            serialized = challenge.serialize(request)
            account_id = account.account_id
            authz_url = challenge.authorization.url(request)
            await session.commit()

        if validate_challenge:
            asyncio.ensure_future(self._handle_challenge_validate(request, account_id, challenge_id))
        return self._response(request, serialized, links=[f'<{authz_url}>; rel="up"'])

    @routes.post("/revoke-cert", name="revoke-cert")
    async def revoke_cert(self, request: web.Request) -> web.Response:
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
    async def order(self, request: web.Request) -> web.Response:
        """Handler that queries the given order.

        `7.1.3. Order Objects <https://tools.ietf.org/html/rfc8555#section-7.1.3>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, post_as_get=True)
            order_id = request.match_info["id"]

            order = await self._db.get_order(session, account.account_id, order_id)
            if not order:
                raise web.HTTPNotFound

            await order.validate()

            return self._response(request, order.serialize(request))

    @routes.post("/orders/{id}", name="orders")
    async def orders(self, request: web.Request) -> web.Response:
        """Handler that retrieves the account's chunked orders list.

        `7.1.2.1.  Orders List <https://tools.ietf.org/html/rfc8555#section-7.1.2.1>`_

        :return: An object with key *orders* that holds a chunk of the account's orders list.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, post_as_get=True)
            try:
                cursor = int(request.query.get("cursor", 0))
                orders = await self._db.get_orders_list(session, account.account_id, self.ORDERS_LIST_CHUNK_LEN, cursor)
            except ValueError:
                raise web.HTTPBadRequest(text="Cursor must be an integer >= 0.")

            if len(orders) == 0:
                raise web.HTTPNotFound(text="No orders found. Try a lower cursor value or create some orders first.")

            """The next two lines ensure that the extra order we query to see if there more orders is not returned
            to the client. If there are no more orders after the current cursor, then return all of them."""
            more_orders = len(orders) == (self.ORDERS_LIST_CHUNK_LEN + 1)
            orders = orders[:-1] if more_orders else orders

            return self._response(
                request,
                {"orders": [order.url(request) for order in orders if order.status == models.OrderStatus.PENDING]},
                links=(
                    [f'<{acmetk.util.next_url(account.orders_url(request), cursor)}>; rel="next"']
                    if more_orders
                    else []
                ),
            )

    async def _validate_order(
        self, request: web.Request, session: AsyncSession
    ) -> (models.Order, x509.CertificateSigningRequest):
        jws, account = await self._verify_request(request, session)
        order_id = request.match_info["id"]

        order = await self._db.get_order(session, account.account_id, order_id)
        if not order:
            raise web.HTTPNotFound

        await order.validate()

        if order.status == models.OrderStatus.INVALID:
            raise acme.messages.Error.with_code(
                "orderNotReady",
                detail="This order cannot be finalized because it is invalid.",
            )

        if order.status != models.OrderStatus.READY:
            raise acme.messages.Error.with_code("orderNotReady")

        csr = messages.CertificateRequest.json_loads(jws.payload).csr
        pub_key = csr.public_key()
        logger.debug("Received CSR; Type: %s, Key Size: %s bits", type(pub_key), pub_key.key_size)

        if isinstance(pub_key, self.SUPPORTED_CSR_KEYS):
            try:
                self._match_keysize(pub_key, "csr")
            except ValueError as e:
                raise acme.messages.Error.with_code(
                    "badPublicKey",
                    detail=e.args[0],
                )
        else:
            raise acme.messages.Error.with_code(
                "badPublicKey",
                detail=f"At this moment, only the following keys are supported in CSRs: "
                f"{', '.join([key_type.__name__ for key_type in self.SUPPORTED_CSR_KEYS])}.",
            )

        if not csr.is_signature_valid:
            raise acme.messages.Error.with_code("badCSR", detail="The CSR's signature is invalid.")
        elif not order.validate_csr(csr):
            raise acme.messages.Error.with_code(
                "badCSR",
                detail="The requested identifiers in the CSR differ from those that this order has authorizations for.",
            )

        return order, csr

    @routes.post("/order/{id}/finalize", name="finalize-order")
    async def finalize_order(self, request: web.Request) -> web.Response:
        """Handler that initiates finalization of the given order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        Specifically: https://tools.ietf.org/html/rfc8555#page-47

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The order is not in state :class:`acmetk.models.OrderStatus.READY`
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
            account_id = order.account.account_id
            await session.commit()

        asyncio.ensure_future(self.handle_order_finalize(request, account_id, order_id))
        return self._response(
            request,
            serialized,
            headers={"Location": acmetk.util.url_for(request, "order", id=order_id)},
        )

    @routes.post("/certificate/{id}", name="certificate")
    @abc.abstractmethod
    async def certificate(self, request: web.Request) -> web.Response:
        """Handler that queries the given certificate.

        `7.4.2. Downloading the Certificate <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_

        :raises: :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
        :return: The certificate's full chain in PEM format.
        """
        pass

    async def _handle_challenge_validate(self, request: web.Request, account_id, challenge_id) -> None:
        logger.debug("Validating challenge %s", challenge_id)

        async with self._session(request) as session:
            challenge = await self._db.get_challenge(session, account_id, challenge_id)

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

    @routes.post("/key-change", name="key-change")
    async def key_change(self, request: web.Request) -> web.Response:
        """7.3.5.  Account Key Rollover"""
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            payload = jws.payload.decode()
            inner_jws = acme.jws.JWS.json_loads(payload)

            """The inner JWS MUST meet the normal requirements …"""
            sig = inner_jws.signature.combined
            if sig.alg not in self.SUPPORTED_JWS_ALGORITHMS:
                raise acme.messages.Error.with_code(
                    "badSignatureAlgorithm",
                    detail=f"Supported algorithms: {', '.join([str(alg) for alg in self.SUPPORTED_JWS_ALGORITHMS])}",
                )

            """, with the following differences:"""

            if inner_jws.signature.combined.url != jws.signature.combined.url:
                """The inner JWS MUST have the same "url" header parameter as the outer JWS."""
                raise acme.messages.Error.with_code(
                    "malformed",
                    detail="The inner JWS of the keychange url mismatches the outer JWS url.",
                )

            if inner_jws.signature.combined.nonce:
                """The inner JWS MUST omit the "nonce" header parameter."""
                raise acme.messages.Error.with_code(
                    "malformed",
                    detail="The inner JWS has a nonce.",
                )

            if inner_jws.signature.combined.jwk is None:
                """The inner JWS MUST have a "jwk" header parameter, containing the public key of the new key pair."""
                raise acme.messages.Error.with_code(
                    "malformed",
                    detail="The inner JWS of the keychange lacks a jwk.",
                )

            if not inner_jws.verify(sig.jwk):
                """4.  Check that the inner JWS verifies using the key in its "jwk" field."""
                raise acme.messages.Error.with_code("unauthorized")

            key_change = messages.KeyChange.json_loads(inner_jws.payload)

            if key_change.account != acmetk.util.url_for(request, "accounts", account_id=str(account.account_id)):
                """7.  Check that the "account" field of the keyChange object contains
                the URL for the account matching the old key (i.e., the "kid"
                field in the outer JWS)."""
                raise acme.messages.Error.with_code("malformed", detail="The KeyChange object account mismatches")

            if key_change.oldKey != account.key:
                """8.  Check that the "oldKey" field of the keyChange object is the same as the account key for the
                account in question."""
                raise acme.messages.Error.with_code("malformed", detail="The KeyChange object oldKey mismatches")

            kid = account._jwk_kid(sig.jwk)
            in_use = await self._db.get_account(session, kid=kid)

            if in_use:
                """9. Check that no account exists whose account key is the same as the key in the "jwk" header
                parameter of the inner JWS."""
                raise acme.messages.Error.with_code("malformed", detail="The KeyChange object key already in use")

            """key size validation"""
            self._validate_account_key(sig.jwk.key._wrapped)

            account.kid = kid
            account.key = inner_jws.signature.combined.jwk
            await session.merge(account)
            await session.commit()

            serialized = account.serialize(request)

            return self._response(
                request,
                serialized,
                headers={"Location": acmetk.util.url_for(request, "accounts", account_id=str(account.account_id))},
            )

    @routes.get("/renewal-info/{aci}", name="renewal-info")
    async def renewal_info(self, request: web.Request) -> web.Response:
        """
        4.1. The RenewalInfo Resource

        https://www.rfc-editor.org/rfc/rfc9773.html#name-the-renewalinfo-resource
        """
        aci = CertID.from_identifier(request.match_info["aci"])

        async with self._session(request) as session:
            c = await self._db.get_certificate(session, certid=aci.identifier)
            if c is None:
                raise ValueError("Not found")
            cert: x509.Certificate = c.cert

        tw = cert.not_valid_after_utc - cert.not_valid_before_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        start = cert.not_valid_before_utc + (tw / 3)
        end = cert.not_valid_before_utc + (tw / 3) * 2

        r = messages.RenewalInfo(suggestedWindow=messages.RenewalInfo.TimeWindow(start=start, end=end))

        rtrya: int = min((start - now).seconds, 24 * 3600)
        """
        4.3.1. Server Choice of Retry-After

        https://www.rfc-editor.org/rfc/rfc9773.html#section-4.3.1
        """

        return self._response(request, r.to_json(), headers={"Retry-After": str(rtrya)})

    @routes.get("/metrics", name="metrics")
    async def metrics(self, request: web.Request) -> web.StreamResponse:
        return await super().metrics(request)

    @abc.abstractmethod
    async def handle_order_finalize(self, request: web.Request, account_id: str, order_id: str) -> web.Response:
        """Method that handles the actual finalization of an order.

        This method should be called after the order's status has been set
        to :class:`acmetk.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        It should retrieve the order from the database and either generate
        the certificate from the stored CSR itself or submit it to another
        CA.

        Afterwards the certificate should be stored alongside the order.
        The *full_chain* attribute needs to be populated and returned
        to the client in :meth:`certificate` if the certificate was
        generated by another CA.

        :param account_id: The account's id
        :param order_id: The order's id
        """
        pass

    @middleware
    async def host_ip_middleware(self, request: web.Request, handler):
        """Middleware that checks whether the requesting host's IP
        is part of any of the subnets that are whitelisted.

        :returns:

            * HTTP status code *403* if the host's IP is not part of any of the whitelisted subnets.
            * HTTP status code *400* if there is a *X-Forwarded-For* header spoofing attack going on.

        """

        if forwarded_for := request.headers.get("X-Forwarded-For"):
            forwarded_for = forwarded_for.partition(",")[0].strip()

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
    async def aiohttp_jinja2_middleware(self, request: web.Request, handler):
        if isinstance(handler, functools.partial) and (handler := handler.keywords["handler"]):
            # using subapps -> functools.partial
            # aiohttp_jinja2 context
            request[aiohttp_jinja2.REQUEST_CONTEXT_KEY] = {
                "request": request,
                "cprofile": cProfile,
                "pstats": pstats,
                "service": self,
            }
        elif isinstance(handler, types.MethodType):
            if handler.__self__.__class__ == web.AbstractRoute:
                pass
            else:
                request[aiohttp_jinja2.REQUEST_CONTEXT_KEY] = {
                    "request": request,
                    "cprofile": cProfile,
                    "pstats": pstats,
                    "service": self,
                }
        elif isinstance(handler, types.FunctionType):  # index_of
            pass
        else:
            raise TypeError(handler)
        return await handler(request)

    @middleware
    async def error_middleware(self, request: web.Request, handler):
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
        except web.HTTPException as error:
            raise error from None
        except Exception as unexpected_error:
            logger.exception(unexpected_error)
            raise web.HTTPInternalServerError(text=str(unexpected_error)) from None
        else:
            return response


AcmeServerBase.ServerKey = web.AppKey("Server", AcmeServerBase)


@PluginRegistry.register_plugin("ca")
class AcmeCA(AcmeServerBase):
    """ACME compliant Certificate Authority."""

    class Config(AcmeServerBase.Config):
        type: typing.Literal["ca"] = "ca"
        cert: str = ""
        """
        The CA's Root Certificate.
        """
        private_key: str = ""
        """
        The private key of the CA.
        """

    def __init__(self, cfg: Config):
        super().__init__(cfg)

        with open(cfg.cert, "rb") as pem:
            self._cert = x509.load_pem_x509_certificate(pem.read())

        with open(cfg.private_key, "rb") as pem:
            self._private_key = serialization.load_pem_private_key(pem.read(), None)

    async def handle_order_finalize(self, request: web.Request, account_id: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acmetk.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        It retrieves the order from the database and generates
        the certificate from the stored CSR, signing it using the CA's private key.

        Afterwards the certificate is stored alongside the order.

        :param account_id: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            order = await self._db.get_order(session, account_id, order_id)

            cert = acmetk.util.generate_cert_from_csr(order.csr, self._cert, self._private_key)
            order.certificate = models.Certificate(
                status=models.CertificateStatus.VALID,
                cert=cert,
                certid=CertID.from_cert(cert).identifier,
            )

            order.status = models.OrderStatus.VALID
            await session.commit()

    # @routes.post("/certificate/{id}", name="certificate")
    async def certificate(self, request: web.Request) -> web.Response:
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, post_as_get=True)
            certificate_id = request.match_info["id"]

            certificate = await self._db.get_certificate(session, account.account_id, certificate_id)
            if not certificate:
                raise web.HTTPNotFound

            return self._response(
                request,
                body=certificate.cert.public_bytes(serialization.Encoding.PEM)
                + self._cert.public_bytes(serialization.Encoding.PEM),
                links=None,
                content_type="application/pem-certificate-chain",
            )


class AcmeRelayBase(AcmeServerBase):
    """Base for an ACME server that relays requests to a remote CA using an internal ACME client.

    The account that is used to sign requests to the remote CA is shared between all users of the relay server.

    At this time, challenges and authorizations are not shared between the relay server and
    the remote CA. Instead, the relay has to make sure that all authorizations for a given order
    are valid before applying for certificate issuance.
    """

    class Config(AcmeServerBase.Config):
        client: AcmeClient.Config = Field(default_factory=AcmeClient.Config)
        """
        The ACME client used to retrieve certificates.
        """

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self._client: AcmeClient = AcmeClient(cfg.client)

    async def on_run(self, app: web.Application):
        await super().on_run(app)
        await self._client.start()

    async def on_shutdown(self, app: web.Application):
        await super().on_shutdown(app)
        await self._client.close()

    async def directory(self, request: web.Request) -> web.Response:
        directory = self._directory_data(request)

        if self._client._directory.meta.profiles:
            # profiles is a frozendict, … is not JSON serializeable
            directory["meta"]["profiles"] = dict(self._client._directory.meta.profiles)

        if self._client._directory._jobj.get("renewalInfo"):
            del directory["renewalInfo"]

        return self._response(request, directory)

    # @routes.post("/certificate/{id}", name="certificate")
    async def certificate(self, request: web.Request) -> web.Response:
        """Handler that queries the given certificate.

        `7.4.2. Downloading the Certificate <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_

        Returns the full chain as retrieved from the CA by the internal client.

        :raises: :class:`aiohttp.web.HTTPNotFound` If the certificate does not exist.
        :return: The certificate's full chain in PEM format.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session, post_as_get=True)
            certificate_id = request.match_info["id"]

            certificate = await self._db.get_certificate(session, account.account_id, certificate_id)
            if not certificate:
                raise web.HTTPNotFound

            return self._response(
                request,
                body=certificate.full_chain.encode(),
                links=None,
                content_type="application/pem-certificate-chain",
            )

    # @routes.post("/revoke-cert", name="revoke-cert")
    async def revoke_cert(self, request: web.Request) -> web.Response:
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

            revocation_succeeded = await self._client.certificate_revoke(certificate.cert, reason=revocation.reason)
            if not revocation_succeeded:
                raise acme.messages.Error.with_code("unauthorized")

            certificate.revoke(revocation.reason)

            await session.commit()

        return self._response(request, status=200)

    async def obtain_and_store_cert(self, order: models.Order, order_ca: acme.messages.Order):
        """Method that obtains the certificate for the given order from the remote CA and stores it.

        This method should be called after the finalization of the order has been completed
        in :meth:`~AcmeServerBase.handle_order_finalize`.

        :param order: The relay's order
        :param order_ca: The remote CA's order object
        """
        full_chain = await self._client.certificate_get(order_ca)
        certs = acmetk.util.pem_split(full_chain)

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
                certid=CertID.from_cert(certs[0]).identifier,
            )

            order.status = models.OrderStatus.VALID


@PluginRegistry.register_plugin("broker")
class AcmeBroker(AcmeRelayBase):
    """Server that relays requests to a remote CA employing a "broker" model.

    Orders are only relayed to the remote CA when the finalization is already processing.
    This means that errors that may occur at the remote CA during order creation or finalization
    cannot be shown to the end user transparently. If that is a concern, then
    the :class:`AcmeProxy` class should be used instead.
    """

    class Config(AcmeRelayBase.Config):
        type: typing.Literal["broker"] = "broker"

    async def handle_order_finalize(self, request: web.Request, account_id: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acmetk.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        The order is relayed to the remote CA here and the entire
        certificate acquisition process is handled by the internal client.
        The obtained certificate's full chain is then stored in the database.

        If the certificate acquisition fails, then the order's status is set
        to :class:`acmetk.models.OrderStatus.INVALID`.

        :param account_id: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            # TODO: no _validate_order?
            order = await self._db.get_order(session, account_id, order_id)

            try:
                order_ca = await self._client.order_create(list(acmetk.util.names_of(order.csr)))
                await self._client.authorizations_complete(order_ca)
                finalized = await self._client.order_finalize(order_ca, order.csr)
                await self.obtain_and_store_cert(order, finalized)
            except acme.messages.Error as e:
                logger.exception("Could not create order %s with remote CA", order_id)
                order.proxied_error = e
                order.status = models.OrderStatus.INVALID
            except CouldNotCompleteChallenge as e:
                logger.info(
                    "Could not complete challenge %s associated with order %s",
                    e.challenge.uri,
                    order_id,
                )
                order.proxied_error = e.challenge.error or (e.args[0] if e.args else None)
                order.status = models.OrderStatus.INVALID
            except AcmeClientException:
                logger.exception(
                    "Could not complete a challenge associated with order %s due to a general client exception",
                    order_id,
                )
                order.status = models.OrderStatus.INVALID

            await session.commit()


@PluginRegistry.register_plugin("proxy")
class AcmeProxy(AcmeRelayBase):
    """Server that relays requests to a remote CA employing a "proxy" model.

    Orders are relayed to the remote CA transparently, which allows for
    the possibility to show errors to the end user as they occur at the remote CA.
    """

    class Config(AcmeRelayBase.Config):
        type: typing.Literal["proxy"] = "proxy"

    # @routes.post("/new-order", name="new-order")
    async def new_order(self, request: web.Request) -> web.Response:
        """Handler that creates a new order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        The order is also relayed to the remote CA by the internal client.
        This means that errors that might occur during the creation process
        are transparently shown to the end user.

        :return: The order object.
        """
        async with self._session(request) as session:
            jws, account = await self._verify_request(request, session)
            obj = messages.NewOrder.json_loads(jws.payload)
            self._verify_order(obj, wildcardonly=True)
            identifiers = [{"type": identifier.typ, "value": identifier.value} for identifier in obj.identifiers]

            location, order_ca = await self._client.order_create(
                identifiers,
                replaces=obj.replaces,
                profile=obj.profile,
                return_location=True,
            )

            order = models.Order.from_obj(account, obj, self._supported_challenges, location)
            session.add(order)

            await session.flush()
            serialized = order.serialize(request)
            account_id = account.account_id
            order_id = order.order_id
            await session.commit()

        asyncio.ensure_future(self._complete_challenges(request, account_id, order_id))
        return self._response(
            request,
            serialized,
            status=201,
            headers={"Location": acmetk.util.url_for(request, "order", id=str(order_id))},
        )

    async def _complete_challenges(self, request: web.Request, account_id, order_id):
        logger.debug("Completing challenges for order %s", order_id)
        async with self._session(request) as session:
            order = await self._db.get_order(session, account_id, order_id)

            order_ca = await self._client.order_get(order.proxied_url)
            try:
                await self._client.authorizations_complete(order_ca)
            except CouldNotCompleteChallenge as e:
                logger.info(
                    "Could not complete challenge %s associated with order %s",
                    e.challenge.uri,
                    order_id,
                )
                order.proxied_error = e.challenge.error or (e.args[0] if e.args else None)
                order.status = models.OrderStatus.INVALID
            except AcmeClientException:
                logger.exception(
                    "Could not complete a challenge associated with order %s due to a general client exception",
                    order_id,
                )
                order.status = models.OrderStatus.INVALID

            await session.commit()

    # @routes.post("/order/{id}/finalize", name="finalize-order")
    async def finalize_order(self, request: web.Request) -> web.Response:
        """Handler that initiates finalization of the given order.

        `7.4. Applying for Certificate Issuance <https://tools.ietf.org/html/rfc8555#section-7.4>`_

        Specifically: https://tools.ietf.org/html/rfc8555#page-47

        The order is refetched via the client using the stored *proxied_url*.
        The client then attempts to finalize the order at the remote CA.
        If an error is raised here, then it is transparently shown to the end user.

        :raises:

            * :class:`aiohttp.web.HTTPNotFound` If the order does not exist.
            * :class:`acme.messages.Error` if any of the following are true:

                * The order is not in state :class:`acmetk.models.OrderStatus.READY`
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
                await asyncio.wait_for(self._client.order_finalize(order_ca, csr), 120.0)
            except asyncio.TimeoutError:
                logger.info(f"finalize_order timeout for order {order.order_id}")
                order.status = models.OrderStatus.INVALID
                raise acme.messages.Error.with_code(
                    "orderNotReady",
                    detail="This order cannot be finalized because it timed out",
                )
            else:
                """The CA's order is valid, we can set our order's status to PROCESSING and
                request the certificate from the CA in _handle_order_finalize."""
                order.status = models.OrderStatus.PROCESSING

            order.csr = csr
            serialized = order.serialize(request)
            account_id = order.account_id
            order_id = str(order.order_id)
            order_processing = order.status == models.OrderStatus.PROCESSING
            await session.commit()

        if order_processing:
            asyncio.ensure_future(self.handle_order_finalize(request, account_id, order_id))

        return self._response(
            request,
            serialized,
            headers={"Location": acmetk.util.url_for(request, "order", id=order_id)},
        )

    async def handle_order_finalize(self, request: web.Request, account_id: str, order_id: str):
        """Method that handles the actual finalization of an order.

        This method is called after the order's status has been set
        to :class:`acmetk.models.OrderStatus.PROCESSING` in :meth:`finalize_order`.

        The order is refetched from the remote CA here after which the internal client
        downloads the certificate and stores its full chain in the database.

        :param account_id: The account's id
        :param order_id: The order's id
        """
        logger.debug("Finalizing order %s", order_id)

        async with self._session(request) as session:
            order = await self._db.get_order(session, account_id, order_id)

            order_ca = await self._client.order_get(order.proxied_url)
            await self.obtain_and_store_cert(order, order_ca)

            await session.commit()

    async def renewal_info(self, request: web.Request) -> web.Response:
        """
        4.1. The RenewalInfo Resource

        https://www.rfc-editor.org/rfc/rfc9773.html#name-the-renewalinfo-resource
        """
        r, rtrya = self._client.renewalinfo_get(request.match_info["aci"])
        return self._response(request, r.to_json(), headers={"Retry-After": str(rtrya)})
