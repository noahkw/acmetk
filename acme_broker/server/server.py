import json
import logging
from typing import Any, Optional

import acme.messages
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.typedefs import JSONEncoder, LooseHeaders

from acme_broker.util import generate_nonce

logger = logging.getLogger(__name__)


async def handle_get(request):
    return web.Response(status=405)


class AcmeResponse(web.Response):
    def __init__(self, *args, nonce, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers.update({'Replay-Nonce': nonce})

    @staticmethod
    def json(data: Any = sentinel, *, nonce=None,
             text: str = None,
             body: bytes = None,
             status: int = 200,
             reason: Optional[str] = None,
             headers: LooseHeaders = None,
             content_type: str = 'application/json',
             dumps: JSONEncoder = json.dumps) -> web.Response:
        if data is not sentinel:
            if text or body:
                raise ValueError("only one of data, text, or body should be specified")
            else:
                text = dumps(data)
        return AcmeResponse(text=text, body=body, status=status, reason=reason,
                            headers=headers, content_type=content_type, nonce=nonce)


class AcmeCA:
    def __init__(self, base_directory='http://localhost:8000/acme'):
        self._base_directory = base_directory

        self._routes = web.RouteTableDef()
        self.app = web.Application()
        self.app.router.add_route('GET', '/directory', self._get_directory)
        self.app.router.add_route('POST', '/acme/new-account', self._new_account)
        self.app.router.add_route('HEAD', '/acme/new-nonce', self._new_nonce)
        self.app.router.add_route('GET', '/acme/new-nonce', self._new_nonce)
        self.app.router.add_route('GET', '/{tail:.*}', handle_get)

        self.directory = acme.messages.Directory({
            'newAccount': f'{self._base_directory}/new-account',
            'newNonce': f'{self._base_directory}/new-nonce',
            'newOrder': f'{self._base_directory}/new-order',
            'revokeCert': f'{self._base_directory}/revoke-cert',
        })

        self._nonces = set()

    @staticmethod
    async def runner(hostname='localhost', port=8000):
        ca = AcmeCA()
        runner = web.AppRunner(ca.app)
        await runner.setup()

        site = web.TCPSite(runner, hostname, port)
        await site.start()

        return runner

    def run(self, port=8000):
        logger.info('Starting ACME CA on port %i', port)
        web.run_app(self.app, port=port)

    def _issue_nonce(self):
        nonce = generate_nonce()
        logger.debug('Storing new nonce %s', nonce)
        self._nonces.add(nonce)
        return nonce

    def _verify_nonce(self, nonce):
        logger.debug('Verifying nonce %s', nonce)
        if nonce in self._nonces:
            logger.debug('Successfully verified nonce %s', nonce)
            self._nonces.remove(nonce)
        else:
            raise acme.messages.errors.BadNonce(nonce, 'This nonce was not issued')

    async def _verify_request(self, request):
        data = await request.text()
        jws = acme.jws.JWS.json_loads(data)

        sig = jws.signature

        protected = json.loads(sig.protected)
        nonce = protected['nonce']

        # TODO: send error if verification unsuccessful
        self._verify_nonce(nonce)
        jws.verify(jws.signature.combined.jwk)

        return jws

    async def _get_directory(self, request):
        return AcmeResponse.json(self.directory.to_json(), nonce=self._issue_nonce())

    async def _new_nonce(self, request):
        return AcmeResponse(status=204, headers={
            'Cache-Control': 'no-store',
        }, nonce=self._issue_nonce())

    async def _new_account(self, request):
        jws = await self._verify_request(request)
        reg = acme.messages.Registration.json_loads(jws.payload)

        return AcmeResponse.json({
            "status": "valid",
            "contact": [
                "mailto:cert-admin@example.org",
                "mailto:admin@example.org"
            ],
            "termsOfServiceAgreed": True,
            "orders": "https://example.com/acme/orders/rzGoeA"
        }, status=200, nonce=self._issue_nonce())


class AcmeProxy(AcmeCA):
    pass


class AcmeBroker(AcmeCA):
    pass


def create_app():
    acme_ca_ = AcmeCA()
    return acme_ca_.app
