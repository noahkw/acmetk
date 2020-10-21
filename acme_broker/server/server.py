import acme.messages
from aiohttp import web


async def handle_get(request):
    return web.Response(status=405)


class AcmeCA:
    def __init__(self, base_directory='http://localhost:8000/acme'):
        self._base_directory = base_directory

        self._routes = web.RouteTableDef()
        self.app = web.Application()
        self.app.router.add_route('GET', '/directory', self._get_directory)
        self.app.router.add_route('POST', '/acme/new-account', self._new_account)
        self.app.router.add_route('HEAD', '/acme/new-nonce', self._new_nonce)
        self.app.router.add_route('GET', '/{tail:.*}', handle_get)

        self.directory = acme.messages.Directory({
            'newAccount': f'{self._base_directory}/new-account',
            'newNonce': f'{self._base_directory}/new-nonce',
            'newOrder': f'{self._base_directory}/new-order',
            'revokeCert': f'{self._base_directory}/revoke-cert',
        })

    def run(self):
        web.run_app(self.app)

    async def _get_directory(self, request):
        return web.json_response(self.directory.to_json())

    async def _new_nonce(self, request):
        return web.Response(status=200, headers={
            'Replay-Nonce': 'asd',
            'Cache-Control': 'no-store',
        })

    async def _new_account(self, request):
        print(await request.json())
        return web.json_response({
            "status": "valid",
            "contact": [
                "mailto:cert-admin@example.org",
                "mailto:admin@example.org"
            ],
            "termsOfServiceAgreed": True,
            "orders": "https://example.com/acme/orders/rzGoeA"
        }, status=200, headers={
            'Replay-Nonce': 'asdf'
        })


class AcmeProxy(AcmeCA):
    pass


class AcmeBroker(AcmeCA):
    pass


def create_app():
    acme_ca_ = AcmeCA()
    return acme_ca_.app


if __name__ == '__main__':
    acme_ca = AcmeCA()
    acme_ca.run()
