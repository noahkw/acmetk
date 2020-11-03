import asyncio
import json
import logging
import typing
from typing import Any, Optional

import acme.messages
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.typedefs import JSONEncoder, LooseHeaders
from aiohttp.web_middlewares import middleware
from cryptography.exceptions import InvalidSignature

from acme_broker import models
from acme_broker.database import Database
from acme_broker.util import (
    generate_nonce,
    sha256_hex_digest,
    serialize_pubkey,
    url_for,
    generate_root_cert,
    generate_cert_from_csr,
    serialize_cert,
    decode_csr,
)

logger = logging.getLogger(__name__)


async def handle_get(request):
    return web.Response(status=405)


class AcmeResponse(web.Response):
    def __init__(self, *args, nonce, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers.update({"Replay-Nonce": nonce, "Cache-Control": "no-store"})

    @staticmethod
    def json(
        data: Any = sentinel,
        *,
        nonce=None,
        text: str = None,
        body: bytes = None,
        status: int = 200,
        reason: Optional[str] = None,
        headers: LooseHeaders = None,
        content_type: str = "application/json",
        dumps: JSONEncoder = json.dumps,
    ) -> web.Response:
        if data is not sentinel:
            if text or body:
                raise ValueError("only one of data, text, or body should be specified")
            else:
                text = dumps(data)
        return AcmeResponse(
            text=text,
            body=body,
            status=status,
            reason=reason,
            headers=headers,
            content_type=content_type,
            nonce=nonce,
        )


class AcmeCA:
    def __init__(self, host, base_route="/acme"):
        self._host = host
        self._base_route = base_route

        self.main_app = web.Application()
        self.ca_app = web.Application(middlewares=[self._error_middleware])

        self.ca_app.add_routes(
            [
                web.post("/new-account", self._new_account, name="new-account"),
                web.head("/new-nonce", self._new_nonce, name="new-nonce"),
                web.post("/new-order", self._new_order, name="new-order"),
                web.post("/order/{id}", self._order, name="order"),
                web.post(
                    "/order/{id}/finalize", self._finalize_order, name="finalize-order"
                ),
                web.post("/revoke-cert", self._revoke_cert, name="revoke-cert"),
                web.post("/accounts/{kid}", self._accounts, name="accounts"),
                web.post("/authz/{id}", self._authz, name="authz"),
                web.post("/challenge/{id}", self._challenge, name="challenge"),
                web.post("/certificate/{id}", self._certificate, name="certificate"),
            ]
        )
        self.ca_app.router.add_route("GET", "/new-nonce", self._new_nonce)

        # catch-all get
        self.ca_app.router.add_route("GET", "/{tail:.*}", handle_get),

        self.main_app.add_routes(
            [
                web.get("/directory", self._get_directory, name="directory"),
                # catch-all get
                # web.get('/{tail:.*}', handle_get),
            ]
        )
        self.main_app.add_subapp(base_route, self.ca_app)

        self._nonces = set()

        self._db: typing.Optional[Database] = None
        self._session = None

        # TODO: add possibility to persist/load root cert
        self.root_cert, self.root_key = generate_root_cert(
            "DE", "Lower Saxony", "Hanover", "Acme Broker", "AB CA"
        )

    @classmethod
    async def runner(cls, hostname, port, db_connection_string):
        ca = AcmeCA(host=f"http://{hostname}:{port}", base_route="/acme")
        db = Database(db_connection_string)
        await db.begin()

        ca._db = db
        ca._session = db.session

        runner = web.AppRunner(ca.main_app)
        await runner.setup()

        site = web.TCPSite(runner, hostname, port)
        await site.start()

        return runner, ca

    def _issue_nonce(self):
        nonce = generate_nonce()
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
        logger.debug("Verifying request")

        data = await request.text()
        jws = acme.jws.JWS.json_loads(data)
        sig = jws.signature

        # TODO: send error if verification unsuccessful
        protected = json.loads(sig.protected)

        nonce = protected.get("nonce", None)
        self._verify_nonce(nonce)

        # Check whether we have *either* a jwk or a kid
        if not ((sig.combined.jwk is not None) ^ (sig.combined.kid is not None)):
            raise acme.messages.Error.with_code("malformed")

        logger.debug("Request has a %s", "jwk" if sig.combined.jwk else "kid")

        if key_auth:
            try:
                jws.verify(sig.combined.jwk)
            except InvalidSignature:
                raise acme.messages.Error.with_code("badPublicKey")
            else:
                account = await self._db.get_account(session, key=sig.combined.jwk.key)
        elif sig.combined.kid:
            kid = sig.combined.kid.split("/")[-1]

            if url_for(request, "accounts", kid=kid) != jws.signature.combined.kid:
                raise acme.messages.Error.with_code("malformed")
            elif "kid" in request.match_info and request.match_info["kid"] != kid:
                raise acme.messages.Error.with_code("malformed")

            account = await self._db.get_account(session, kid=kid)

            if not account:
                logger.info("Could not find account with kid %s", kid)
                raise acme.messages.Error.with_code("accountDoesNotExist")
        else:
            raise acme.messages.Error.with_code("malformed")

        return jws, account

    async def _get_directory(self, request):
        directory = acme.messages.Directory(
            {
                "newAccount": url_for(request, "new-account"),
                "newNonce": url_for(request, "new-nonce"),
                "newOrder": url_for(request, "new-order"),
                "revokeCert": url_for(request, "revoke-cert"),
            }
        )

        return AcmeResponse.json(directory.to_json(), nonce=self._issue_nonce())

    async def _new_nonce(self, request):
        return AcmeResponse(
            status=204,
            headers={
                "Cache-Control": "no-store",
            },
            nonce=self._issue_nonce(),
        )

    async def _new_account(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=True)
            reg = acme.messages.Registration.json_loads(jws.payload)
            key = jws.signature.combined.jwk.key

            if account:
                if account.status != models.AccountStatus.VALID:
                    raise acme.messages.Error.with_code("unauthorized")
                else:
                    return AcmeResponse.json(
                        account.serialize(),
                        nonce=self._issue_nonce(),
                        headers={
                            "Location": url_for(request, "accounts", kid=account.kid)
                        },
                    )
            else:
                if reg.only_return_existing:
                    raise acme.messages.Error.with_code("accountDoesNotExist")
                elif not reg.terms_of_service_agreed:
                    # TODO: make available and link to ToS
                    raise acme.messages.Error(
                        typ="urn:ietf:params:acme:error:termsOfServiceNotAgreed",
                        title="The client must agree to the terms of service.",
                    )
                else:  # create new account
                    new_account = models.Account(
                        key=key,
                        kid=sha256_hex_digest(serialize_pubkey(key)),
                        status=models.AccountStatus.VALID,
                        contact=json.dumps(reg.contact),
                    )
                    serialized = new_account.serialize()
                    session.add(new_account)
                    kid = new_account.kid
                    await session.commit()
                    return AcmeResponse.json(
                        serialized,
                        status=201,
                        nonce=self._issue_nonce(),
                        headers={"Location": url_for(request, "accounts", kid=kid)},
                    )

    async def _accounts(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            upd = acme.messages.Registration.json_loads(jws.payload)

            account.update(upd)

            serialized = account.serialize()

            await session.commit()
            return AcmeResponse.json(serialized, status=200, nonce=self._issue_nonce())

    async def _new_order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            obj = acme.messages.NewOrder.json_loads(jws.payload)

            order = models.Order.from_obj(account, obj)
            session.add(order)

            await session.flush()
            serialized = order.serialize(request=request)
            order_id = order.order_id
            await session.commit()

        return AcmeResponse.json(
            serialized,
            status=201,
            nonce=self._issue_nonce(),
            headers={"Location": url_for(request, "order", id=str(order_id))},
        )

    async def _authz(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            authz_id = request.match_info["id"]

            authorization = await self._db.get_authz(session, account.kid, authz_id)
            if not authorization:
                raise web.HTTPNotFound

            serialized = authorization.serialize(request=request)
            await session.commit()

        return AcmeResponse.json(serialized, nonce=self._issue_nonce(), status=200)

    async def _challenge(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session)
            challenge_id = request.match_info["id"]

            challenge = await self._db.get_challenge(session, account.kid, challenge_id)
            if not challenge:
                raise web.HTTPNotFound

            challenge.status = models.ChallengeStatus.PROCESSING

            serialized = challenge.serialize(request=request)
            kid = account.kid
            authz_url = challenge.authorization.url(request)
            await session.commit()

            asyncio.ensure_future(self._handle_challenge_finalize(kid, challenge_id))

        return AcmeResponse.json(
            serialized,
            nonce=self._issue_nonce(),
            status=200,
            headers={"Link": f'<{authz_url}>; rel="up"'},
        )

    async def _revoke_cert(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=True)

        return AcmeResponse(nonce=self._issue_nonce(), status=404)

    async def _order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
            order_id = request.match_info["id"]

            order = await self._db.get_order(session, account.kid, order_id)
            if not order:
                raise web.HTTPNotFound

            serialized = order.serialize(request)

            await session.commit()

        return AcmeResponse.json(serialized, nonce=self._issue_nonce(), status=200)

    async def _finalize_order(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
            order_id = request.match_info["id"]

            order = await self._db.get_order(session, account.kid, order_id)
            if not order:
                raise web.HTTPNotFound

            if order.status != models.OrderStatus.READY:
                raise acme.messages.Error.with_code("orderNotReady")

            obj = json.loads(jws.payload)
            csr = decode_csr(obj["csr"])

            order.csr = csr
            order.status = models.OrderStatus.PROCESSING

            serialized = order.serialize(request=request)
            kid = account.kid
            await session.commit()

            asyncio.ensure_future(self._handle_order_finalize(kid, order_id))

        return AcmeResponse.json(
            serialized,
            nonce=self._issue_nonce(),
            status=200,
            headers={"Location": url_for(request, "order", id=order_id)},
        )

    async def _certificate(self, request):
        async with self._session() as session:
            jws, account = await self._verify_request(request, session, key_auth=False)
            certificate_id = request.match_info["id"]

            certificate = await self._db.get_certificate(
                session, account.kid, certificate_id
            )
            if not certificate:
                raise web.HTTPNotFound

            cert = certificate.cert

        return AcmeResponse(
            text=serialize_cert(self.root_cert).decode()
            + serialize_cert(cert).decode(),
            nonce=self._issue_nonce(),
            status=200,
        )

    async def _handle_challenge_finalize(self, kid, challenge_id):
        logger.debug("Finalizing challenge %s", challenge_id)

        async with self._session() as session:
            challenge = await self._db.get_challenge(session, kid, challenge_id)
            # simulate requests to Let's Encrypt CA
            # await asyncio.sleep(3)
            await challenge.finalize(session)
            await session.commit()

    async def _handle_order_finalize(self, kid, order_id):
        # await asyncio.sleep(2)
        logger.debug("Finalizing order %s", order_id)

        async with self._session() as session:
            order = await self._db.get_order(session, kid, order_id)

            cert = generate_cert_from_csr(order.csr, self.root_cert, self.root_key)
            order.certificate = models.Certificate(
                status=models.CertificateStatus.VALID, cert=cert
            )

            order.status = models.OrderStatus.VALID
            await session.commit()

    @middleware
    async def _error_middleware(self, request, handler):
        """
        Converts errors thrown in handlers to ACME compliant JSON and
        attaches the specified status code to the response.
        """
        try:
            response = await handler(request)
        except acme.messages.errors.Error as error:
            status = 400
            if error.code == "orderNotReady":
                status = 403
            if error.code == "accountDoesNotExist":
                status = 404

            return AcmeResponse.json(
                error.json_dumps(),
                status=status,
                nonce=self._issue_nonce(),
                content_type="application/problem+json",
            )
        else:
            return response


class AcmeProxy(AcmeCA):
    pass


class AcmeBroker(AcmeCA):
    pass
