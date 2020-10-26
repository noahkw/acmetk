import json
import logging
import typing
from typing import Any, Optional

import acme.messages
from aiohttp import web
from aiohttp.helpers import sentinel
from aiohttp.typedefs import JSONEncoder, LooseHeaders

from acme_broker import models
from acme_broker.database import Database
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

        ])
        self.ca_app.router.add_route('GET', '/new-nonce', self._new_nonce)

        # catch-all get
        self.ca_app.router.add_route('GET', '/{tail:.*}', handle_get),

        self.main_app.add_routes([
            web.get('/directory', self._get_directory),
            # catch-all get
            # web.get('/{tail:.*}', handle_get),
        ])
        self.main_app.add_subapp(base_route, self.ca_app)

        self._nonces = set()

        self._db: typing.Optional[Database] = None
        self._session = None

    @classmethod
    async def runner(cls, hostname='localhost', **kwargs):
        log_level = logging.getLevelName(kwargs.pop('log_level', logging.INFO))
        log_file = kwargs.pop('log_file', None)
        port = kwargs.pop('port', 8000)
        debug = kwargs.pop('debug', False)
        db_user = kwargs.pop('db_user')
        db_pass = kwargs.pop('db_pass')
        db_host = kwargs.pop('db_host')
        db_port = kwargs.pop('db_port', 5432)
        db_database = kwargs.pop('db_database')

        logging.basicConfig(filename=log_file, level=log_level)
        logging.debug("""Passed Args: Log level '%s'
                                Log file '%s', 
                                Port %d, 
                                Debug '%s',
                                DB-user '%s',
                                DB-pass %s,
                                DB-host '%s',
                                DB-port %d,
                                DB-database '%s'""", log_level, log_file, port,
                      debug, db_user,
                      '***' if db_pass else None,
                      db_host, db_port, db_database)

        ca = AcmeCA(host=f'http://{hostname}:{port}', base_route='/acme')
        db = Database(db_user, db_pass, db_host, db_port, db_database, echo=log_level == logging.DEBUG)

        await db.begin()

        ca._db = db
        ca._session = db.session

        runner = web.AppRunner(ca.main_app)
        await runner.setup()

        site = web.TCPSite(runner, hostname, port)
        await site.start()

        return runner

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

        key = jws.signature.combined.jwk.key

        account = await self._db.get_account(key)

        if account:
            pass
        else:
            if reg.only_return_existing:
                msg = acme.messages.Error.with_code('accountDoesNotExist')
                return AcmeResponse.json(msg.to_json(), status=400, nonce=self._issue_nonce(),
                                         headers={'Cache-Control': 'no-store'})
            else:  # create new account
                async with self._session() as session:
                    new_account = models.Account(key=key, status=models.AccountStatus.VALID,
                                                 contact=json.dumps(reg.contact),
                                                 termsOfServiceAgreed=reg.terms_of_service_agreed)
                    serialized = new_account.serialize()
                    session.add(account)

                    await session.commit()
                    return AcmeResponse.json(serialized, nonce=self._issue_nonce(), headers={
                        'Cache-Control': 'no-store', 'Location': self.url_for(request, '/acme')
                    })


class AcmeProxy(AcmeCA):
    pass


class AcmeBroker(AcmeCA):
    pass
