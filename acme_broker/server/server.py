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
    def __init__(self, host, base_route='/acme'):
        self._host = host
        self._base_route = base_route

        self.main_app = web.Application()
        self.ca_app = web.Application()

        self.ca_app.add_routes([
            web.post('/new-account', self._new_account),
            web.head('/new-nonce', self._new_nonce),
            # catch-all get
            web.get('/{tail:.*}', handle_get),
        ])
        self.ca_app.router.add_route('GET', '/new-nonce', self._new_nonce)

        self.main_app.add_routes([
            web.get('/directory', self._get_directory),
            # catch-all get
            # web.get('/{tail:.*}', handle_get),
        ])
        self.main_app.add_subapp(base_route, self.ca_app)

        self._nonces = set()

    @staticmethod
    async def runner(hostname='localhost', port=8000):
        ca = AcmeCA(host=f'http://{hostname}:{port}', base_route='/acme')
        runner = web.AppRunner(ca.main_app)
        await runner.setup()

        site = web.TCPSite(runner, hostname, port)
        await site.start()

        return runner

    def run(self, port=8000):
        logger.info('Starting ACME CA on port %i', port)
        web.run_app(self.main_app, port=port)

    def url_for(self, request, route: str):
        return f'{self._host}{self._base_route}/{route}'

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
        directory = acme.messages.Directory({
            'newAccount': self.url_for(request, 'new-account'),
            'newNonce': self.url_for(request, 'new-nonce'),
            'newOrder': self.url_for(request, 'new-order'),
            'revokeCert': self.url_for(request, 'revoke-cert'),
        })

        return AcmeResponse.json(directory.to_json(), nonce=self._issue_nonce())

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
    acme_ca = AcmeCA(host=f'http://localhost:8000', base_route='/acme')
    return acme_ca.main_app
