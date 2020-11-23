import asyncio
import json
import logging
import re
import typing
import uuid
from email.utils import parseaddr

import acme.jws
import acme.messages
import josepy
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.web_middlewares import middleware
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acme_broker import models, messages
from acme_broker.client import CouldNotCompleteChallenge
from acme_broker.database import Database
from acme_broker.util import (
    url_for,
    generate_cert_from_csr,
    names_of,
    forwarded_url,
    pem_split,
)

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


class AcmeServerBase:
    SUPPORTED_JWS_ALGORITHMS = (
        josepy.RS256,
        josepy.RS384,
        josepy.RS512,
        josepy.PS256,
        josepy.PS384,
        josepy.PS512,
    )

    def __init__(
        self, *, rsa_min_keysize=2048, tos_url=None, mail_suffixes=None, **kwargs
    ):
        self._rsa_min_keysize = rsa_min_keysize
        self._tos_url = tos_url
        self._mail_suffixes = mail_suffixes

        self.app = web.Application(middlewares=[self._error_middleware])

        self.app.add_routes(
            [
                web.post("/new-account", self._new_account, name="new-account"),
                web.head("/new-nonce", self._new_nonce, name="new-nonce"),
                web.post("/new-order", self._new_order, name="new-order"),
                web.post("/revoke-cert", self._revoke_cert, name="revoke-cert"),
                web.post("/order/{id}", self._order, name="order"),
                web.post(
                    "/order/{id}/finalize", self._finalize_order, name="finalize-order"
                ),
                web.post("/orders/{id}", self._orders, name="orders"),
                web.post("/accounts/{kid}", self._accounts, name="accounts"),
                web.post("/authz/{id}", self._authz, name="authz"),
                web.post("/challenge/{id}", self._challenge, name="challenge"),
                web.post("/certificate/{id}", self._certificate, name="certificate"),
                web.get("/directory", self._get_directory, name="directory"),
            ]
        )
        self.app.router.add_route("GET", "/new-nonce", self._new_nonce)

        # catch-all get
        self.app.router.add_route("GET", "/{tail:.*}", handle_get),

        self._nonces = set()

        self._db: typing.Optional[Database] = None
        self._session = None

    @classmethod
    async def create_app(cls, config, **kwargs):
        db = Database(config["db"])
        await db.begin()

        ca = cls(
            rsa_min_keysize=config.get("rsa_min_keysize"),
            tos_url=config.get("tos_url"),
            mail_suffixes=config.get("mail_suffixes"),
            **kwargs,
        )
        ca._db = db
        ca._session = db.session

        return ca

    @classmethod
    async def runner(cls, config, **kwargs):
        instance = await cls.create_app(config, **kwargs)

        runner = web.AppRunner(instance.app)
        await runner.setup()

        site = web.TCPSite(runner, config["hostname"], config["port"])
        await site.start()

        return runner, instance

    @classmethod
    async def unix_socket(cls, config, path, **kwargs):
        instance = await cls.create_app(config, **kwargs)

        runner = web.AppRunner(instance.app)
        await runner.setup()

        site = web.UnixSite(runner, path)
        await site.start()

        return runner, instance

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
        logger.debug("Storing new nonce %s", nonce)
        self._nonces.add(nonce)
        return nonce

    def _verify_nonce(self, nonce):
        if nonce in self._nonces:
            logger.debug("Successfully verified nonce %s", nonce)
            self._nonces.remove(nonce)
        else:
            raise acme.messages.Error.with_code("badNonce", detail=nonce)

    async def _verify_request(self, request, session, key_auth=False):
        data = await request.text()
        try:
            jws = acme.jws.JWS.json_loads(data)
        except josepy.errors.DeserializationError:
            raise acme.messages.Error.with_code(
                "malformed", detail="The request does not contain a valid JWS."
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

        logger.debug("Request has a %s", "jwk" if sig.jwk else "kid")

        if key_auth:
            if not jws.verify(sig.jwk):
                raise acme.messages.Error.with_code("unauthorized")
            else:
                account = await self._db.get_account(session, key=sig.jwk)
        elif sig.kid:
            kid = sig.kid.split("/")[-1]  # TODO: yarl

            if url_for(request, "accounts", kid=kid) != jws.signature.combined.kid:
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

    async def _verify_revocation(self, request, session) -> models.Certificate:
        try:
            # check whether the message is signed using an account key
            jws, account = await self._verify_request(request, session, key_auth=False)
        except acme.messages.Error:
            data = await request.text()
            jws = acme.jws.JWS.json_loads(
                data
            )  # TODO: raise acme error on deserialization error
            account = None

        revocation = messages.Revocation.json_loads(jws.payload)
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

        return certificate

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

    async def _get_directory(self, request):
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

    async def _new_nonce(self, request):
        return self._response(request, status=204)

    async def _new_account(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=True)
            reg = acme.messages.Registration.json_loads(jws.payload)
            jwk = jws.signature.combined.jwk

            if jwk.key.key_size < self._rsa_min_keysize:
                raise acme.messages.Error.with_code("badPublicKey")

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

    async def _accounts(self, request):
        async with self._session() as session:
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

    async def _new_order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            obj = acme.messages.NewOrder.json_loads(jws.payload)

            order = models.Order.from_obj(account, obj)
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

    async def _authz(self, request):
        async with self._session() as session:
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

    async def _challenge(self, request):
        async with self._session() as session:
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

        asyncio.ensure_future(self._handle_challenge_validate(kid, challenge_id))
        return self._response(request, serialized, links=[f'<{authz_url}>; rel="up"'])

    async def _revoke_cert(self, request):
        async with self._session() as session:
            certificate = await self._verify_revocation(request, session)

            # TODO: do actual revocation logic
            certificate.status = models.CertificateStatus.REVOKED
            await session.commit()

        return self._response(request, status=200)

    async def _order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
            order_id = request.match_info["id"]

            order = await self._db.get_order(session, account.kid, order_id)
            if not order:
                raise web.HTTPNotFound

            return self._response(request, order.serialize(request))

    async def _orders(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)

            return self._response(request, {"orders": account.orders_list(request)})

    async def _validate_order(
        self, request, session
    ) -> (models.Order, x509.CertificateSigningRequest):
        jws, account = await self._verify_request(request, session, key_auth=False)
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

        if csr.public_key().key_size < self._rsa_min_keysize:
            raise acme.messages.Error.with_code(
                "badPublicKey",
                detail=f"Only RSA keys with more than {self._rsa_min_keysize} bits are accepted.",
            )
        elif not csr.is_signature_valid:
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

    async def _finalize_order(self, request):
        async with self._session() as session:
            order, csr = await self._validate_order(request, session)

            order.csr = csr
            order.status = models.OrderStatus.PROCESSING

            serialized = order.serialize(request)
            order_id = str(order.order_id)
            kid = order.account_kid
            await session.commit()

        asyncio.ensure_future(self._handle_order_finalize(kid, order_id))
        return self._response(
            request,
            serialized,
            headers={"Location": url_for(request, "order", id=order_id)},
        )

    async def _certificate(self, request):
        raise NotImplementedError

    async def _handle_challenge_validate(self, kid, challenge_id):
        logger.debug("Validating challenge %s", challenge_id)

        async with self._session() as session:
            challenge = await self._db.get_challenge(session, kid, challenge_id)
            # simulate requests to Let's Encrypt CA
            # await asyncio.sleep(3)
            await challenge.validate(session)
            await session.commit()

    async def _handle_order_finalize(self, kid, order_id):
        raise NotImplementedError

    @middleware
    async def _error_middleware(self, request, handler):
        """
        Converts errors thrown in handlers to ACME compliant JSON and
        attaches the specified status code to the response.
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
    def __init__(self, *, cert, private_key, **kwargs):
        super().__init__(**kwargs)

        with open(cert, "rb") as pem:
            self._cert = x509.load_pem_x509_certificate(pem.read())

        with open(private_key, "rb") as pem:
            self._private_key = serialization.load_pem_private_key(pem.read(), None)

    @classmethod
    async def create_app(cls, config, **kwargs):
        db = Database(config["db"])
        await db.begin()

        ca = cls(
            rsa_min_keysize=config.get("rsa_min_keysize"),
            tos_url=config.get("tos_url"),
            mail_suffixes=config.get("mail_suffixes"),
            cert=config["cert"],
            private_key=config["private_key"],
            **kwargs,
        )
        ca._db = db
        ca._session = db.session

        return ca

    async def _handle_order_finalize(self, kid, order_id):
        logger.debug("Finalizing order %s", order_id)

        async with self._session() as session:
            order = await self._db.get_order(session, kid, order_id)
            # simulate requests to Let's Encrypt CA
            # await asyncio.sleep(3)

            cert = generate_cert_from_csr(order.csr, self._cert, self._private_key)
            order.certificate = models.Certificate(
                status=models.CertificateStatus.VALID, cert=cert
            )

            order.status = models.OrderStatus.VALID
            await session.commit()

    async def _certificate(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
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


class AcmeServerClientBase(AcmeServerBase):
    """Base for an ACME server that talks to a CA using an ACME client."""

    def __init__(self, *, client, **kwargs):
        super().__init__(**kwargs)
        self._client = client

    async def _certificate(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
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

    async def _revoke_cert(self, request):
        async with self._session() as session:
            certificate = await self._verify_revocation(request, session)

            revocation_succeeded = await self._client.certificate_revoke(
                certificate.cert
            )
            if not revocation_succeeded:
                raise acme.messages.Error.with_code("unauthorized")

            certificate.status = models.CertificateStatus.REVOKED
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


class AcmeBroker(AcmeServerClientBase):
    async def _handle_order_finalize(self, kid, order_id):
        logger.debug("Finalizing order %s", order_id)

        async with self._session() as session:
            order = await self._db.get_order(session, kid, order_id)

            order_ca = await self._client.order_create(list(names_of(order.csr)))

            try:
                await self._client.authorizations_complete(order_ca)
                finalized = await self._client.order_finalize(order_ca, order.csr)
                await self._obtain_and_store_cert(order, finalized)
            except CouldNotCompleteChallenge as e:
                logger.info(
                    "Could not complete challenge %s associated with order %s",
                    e.challenge.uri,
                    order_id,
                )
                order.status = models.OrderStatus.INVALID

            await session.commit()


class AcmeProxy(AcmeServerClientBase):
    async def _new_order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            obj = acme.messages.NewOrder.json_loads(jws.payload)

            identifiers = [
                {"type": identifier.typ, "value": identifier.value}
                for identifier in obj.identifiers
            ]
            ca_order = await self._client.order_create(identifiers)

            order = models.Order.from_obj(account, obj)
            order.proxied_url = ca_order.url
            session.add(order)

            await session.flush()
            serialized = order.serialize(request)
            kid = account.kid
            order_id = order.order_id
            await session.commit()

        asyncio.ensure_future(self._complete_challenges(kid, order_id))
        return self._response(
            request,
            serialized,
            status=201,
            headers={"Location": url_for(request, "order", id=str(order_id))},
        )

    async def _complete_challenges(self, kid, order_id):
        logger.debug("Completing challenges for order %s", order_id)
        async with self._session() as session:
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
                order.status = models.OrderStatus.INVALID

            await session.commit()

    async def _finalize_order(self, request):
        async with self._session() as session:
            order, csr = await self._validate_order(request, session)
            order_ca = await self._client.order_get(order.proxied_url)

            try:
                # AcmeClient.order_finalize does not return if the order never becomes valid.
                # Thus, we handle that case here and set the order's status to invalid
                # if the CA takes too long.
                await asyncio.wait_for(self._client.order_finalize(order_ca, csr), 10.0)
            except asyncio.TimeoutError:
                # TODO: consider returning notReady instead to let the client try again
                order.status = models.OrderStatus.INVALID
            else:
                # The CA's order is valid, we can set our order's status to PROCESSING and
                # request the certificate from the CA in _handle_order_finalize.
                order.status = models.OrderStatus.PROCESSING

            order.csr = csr
            serialized = order.serialize(request)
            kid = order.account_kid
            order_id = str(order.order_id)
            order_processing = order.status == models.OrderStatus.PROCESSING
            await session.commit()

        if order_processing:
            asyncio.ensure_future(self._handle_order_finalize(kid, order_id))

        return self._response(
            request,
            serialized,
            headers={"Location": url_for(request, "order", id=order_id)},
        )

    async def _handle_order_finalize(self, kid, order_id):
        logger.debug("Finalizing order %s", order_id)

        async with self._session() as session:
            order = await self._db.get_order(session, kid, order_id)

            order_ca = await self._client.order_get(order.proxied_url)
            await self._obtain_and_store_cert(order, order_ca)

            await session.commit()
