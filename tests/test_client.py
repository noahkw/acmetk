import os
import shlex
import unittest
import asyncio
import shutil
import collections

import josepy
import logging
import logging.config

from cryptography.hazmat.primitives import serialization


import lee.client
import lee.ca
import lee.main
from lee.util import names_of


log = logging.getLogger('lee.test_client')


DEFAULT_NETWORK_TIMEOUT = 45
from pathlib import Path

ClientData = collections.namedtuple('data', ['key','csr','path'])

class TestClient:
    DIRECTORY = 'http://localhost:12345/brkr/directory'
    EC = False

    @property
    def NAME(self):
        return self.__class__.__name__[4:]


    def setUp(self) -> None:
        self.log = logging.getLogger(f'lee.tests.{self.NAME}')
        self.CONTACT = f'koetter+{self.NAME}@luis.uni-hannover.de'
        dir = Path('./tests/tmp') / self.NAME
        if not dir.exists():
            dir.mkdir(parents=True)
        key = lee.ca.generate_rsa_key(dir / 'account.key')

        if self.EC:
            thekey = lee.ca.generate_ec_key(dir / 'the.key')
        else:
            thekey = lee.ca.generate_rsa_key(dir / 'the.key')

        csr = lee.ca.generate_csr(thekey, dir / 'the.csr', CN=f"{self.NAME}.test.de", sans=3)
        self.data = ClientData(key, csr, dir)
        self._rmtree = ['the.csr']

    def tearDown(self):
        for i in self._rmtree:
            if Path(i).is_absolute():
                log.error(f"{i} is not relative")
                continue

            if (path:= self.data.path / i).is_dir():
                log.info(f'rmtree {path}')
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                log.info(f'unlink {path}')
                path.unlink()



    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        runner,*_ = await lee.main.main('conf/debug.yaml')
        logging.config.dictConfig(runner.app['config']['logging'])
        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()

class TestClientProxy(TestClient):
    DIRECTORY = 'http://localhost:12345/proxy/directory'

class TestClientEC(TestClient):
    EC = True

class TestClientProxyEC(TestClient):
    EC = True

class TestBrokerClient(TestClient, unittest.IsolatedAsyncioTestCase):
    _supported_challenges = frozenset(['dns-01'])
    def setUp(self):
        TestClient.setUp(self)
        try:
            (self.data.path / 'alpn').mkdir()
        except:
            pass
        self._rmtree.append('alpn/')
        self._rmtree.append('thecrt.pem')

    async def _client(self):
        client = await lee.client.client_for(self.data.key, self.CONTACT, self.DIRECTORY, ssl=lee.views.the_ctx())
        self.addAsyncCleanup(client.net.session.close)
        return client

    async def test_Register(self):
        import acme
        self._rmtree.append('account.key')
        key,csr,path = self.data

        client = await self._client()

        # reset
        regr = await client.query_registration(client.net.account)
        update = regr.body.update(contact=(self.CONTACT,))
        r = await client.update_registration(regr, update)

        # set
        regr = await client.query_registration(client.net.account)
        self.assertEqual((self.CONTACT,), regr.body.contact)
        newcontact = tuple(map(lambda x: '{}+update@{}'.format(*x.split('@')), regr.body.contact))
        update = regr.body.update(contact=newcontact)
        r = await client.update_registration(regr, update)
        self.assertEqual(update.contact, r.body.contact)

        # unregister
        await client.deactivate_registration(regr)
        with self.assertRaises(acme.errors.ClientError):
            await client.deactivate_registration(regr)


    async def test_run(self):
        import acme
        key,csr,path = self.data

        client = await self._client()

        with open(path / 'the.csr', "rb") as f:
            data = f.read()
        order = await client.new_order(data)

        for authz in order.authorizations:
            if not authz.body.challenges:
                continue
            for challb in authz.body.challenges:
                if challb.chall.typ not in self._supported_challenges:
                    continue
                response, validation = challb.response_and_validation(client.net.key,
                                                                      domain=authz.body.identifier.value)
                await client.answer_challenge(challb, response)

                if challb.chall.typ == 'dns-01':
                    continue
                elif challb.chall.typ == 'tls-alpn-01':
                    (cert, key) = validation
                    import OpenSSL
                    with open(path / f'alpn/alpn-{authz.body.identifier.value}-cert.pem', 'wb') as f:
                        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
                    with open(path / f'alpn/alpn-{authz.body.identifier.value}-key.pem', 'wb') as f:
                        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
                elif challb.chall.typ == 'http-01':
                    continue
                else:
                    ValueError(challb.chall.typ)


        while True:

            try:
                r = await client.finalize_order(order, None)
                with open(path / 'thecrt.pem', 'wt') as f:
                    f.write(r.fullchain_pem)
                break
            except acme.messages.Error as e:
                if e.code == 'orderNotReady':
                    await asyncio.sleep(1)
                    continue
            except acme.errors.ClientError as e:
                if e.args[0].status == 403:
                    break
            except Exception as e:
                log.exception(e)
                await asyncio.sleep(1)

        crt = r.fullchain_pem.split("\n\n")[0]
        import OpenSSL
        crt = josepy.ComparableX509(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, crt))
        r = await client.revoke(crt, lee.ca.CA.rfc5280_reason_code['unspecified'])

        with self.assertRaises(acme.errors.ClientError):
            r = await client.revoke(crt, lee.ca.CA.rfc5280_reason_code['unspecified'])

        for authz in order.authorizations:
            await client.deactivate_authorization(authz)
            with self.assertRaises(acme.errors.ClientError):
                await client.deactivate_authorization(authz)


class TestBrokerClientProxy(TestClientProxy, TestBrokerClient):
    pass

class TestBrokerClientEC(TestClientEC, TestBrokerClient):
    pass

class TestBrokerClientProxyEC(TestClientProxyEC, TestBrokerClient):
    pass

class TestECBrokerClient(TestClient, unittest.IsolatedAsyncioTestCase):
    _supported_challenges = frozenset(['dns-01'])
    def setUp(self):
        TestClient.setUp(self)

    async def _client(self):
        key = lee.ca.generate_ec_key(self.data.path / 'ec-account.key')
        self._rmtree.append('ec-account.key')
        client = await lee.client.client_for(key, self.CONTACT, self.DIRECTORY)
        self.addAsyncCleanup(client.net.session.close)
        return client

    async def test_Register(self):
        import acme
        self._rmtree.append('ec-account.key')
        key,csr,path = self.data

        # josepy JWKES is not implemented
        with self.assertRaises(TypeError) as e:
            client = await self._client()
        self.assertEqual(e.exception.args[0], '__init__() takes exactly the following arguments:  (key given)')


class TestCertBot(TestClient, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestClient.setUp(self)
        with open(self.data.path / 'certbot.ini', 'wt') as f:
            f.write(f'''server = {self.DIRECTORY}
config-dir = ./{self.data.path}/etc/letsencrypt
work-dir = /home/common/venv-le/bin/ 
logs-dir = /home/common/venv-le/var/log
''')
        self._rmtree.extend(['archive', 'renewal', 'live'])

    async def _run(self, cmd):
        argv = shlex.split(f'--non-interactive -c {self.data.path}/certbot.ini ' + cmd)
        import certbot._internal.main as cbm

        r = await self.loop.run_in_executor(None, cbm.main, argv)
        return r

    async def test_run(self):
        import certbot.util
        import certbot._internal.log
        import certbot._internal.error_handler

        certbot.util.atexit_register = lambda func, *argv, **kwargs: log.info(f"patched certbot.util.atexit_register for {func}")
        certbot._internal.error_handler.ErrorHandler._set_signal_handlers = lambda x: log.info("patched certbot._internal.error_handler.ErrorHandler._set_signal_handlers")
        certbot._internal.log.pre_arg_parse_setup = lambda: log.info('patched certbot._internal.log.pre_arg_parse_setup')
        certbot._internal.log.post_arg_parse_setup = lambda x: log.info('patched certbot._internal.log.post_arg_parse_setup')

        await self._run('certificates')

        logging.config.dictConfig(self.runner.app['config']['logging'])

        await self._run(f'register --agree-tos  -m {self.CONTACT}')
        domains = sorted(map(lambda x: x.lower(), names_of(self.data.csr)), key=lambda s: s[::-1])
        arg = ' --domain '.join(domains)
        await self._run(f'certonly --webroot --webroot-path {self.data.path} --domain {arg}')
        arg = ' --domain '.join(map(lambda s: f'dns.{s}',domains))
        await self._run(f'certonly --manual --manual-public-ip-logging-ok --preferred-challenges=dns --manual-auth-hook "echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg}')
        arg = ' --domain '.join(map(lambda s: f'http.{s}', domains))
        await self._run(f'certonly --manual --manual-public-ip-logging-ok --preferred-challenges=http --manual-auth-hook "echo $CERTBOT_VALIDATION" --manual-cleanup-hook /bin/true --domain {arg}')
        for j in ['','dns.','http.']:
            try:
                await self._run(f'revoke --cert-path {self.data.path}/etc/letsencrypt/live/{j}{domains[0]}/cert.pem')
            except Exception as e:
                log.error(e)
        await self._run('renew')

    async def test_Register(self):
        await self._run(f'register --agree-tos  -m {self.CONTACT}')

    async def test_Unregister(self):
        try:
            await self._run("unregister --agree-tos")
        except:
            pass
        await self.test_Register()
        await self._run("unregister --agree-tos")


class TestCertBotProxy(TestCertBot, TestBrokerClient):
    pass


class Testaioacme(TestClient, unittest.IsolatedAsyncioTestCase):
    async def test_Register(self):
        self._rmtree.append('account.key')
        from aioacme.aioacme.client import new_client
        from aioacme.aioacme.identifier import DnsName
        import aioacme.aioacme.errors

        _key, csr, path = self.data
        key = josepy.JWKRSA.load(_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        client = await new_client(self.DIRECTORY, 'easy')
        self.addAsyncCleanup(client.close)
        await client.refresh_nonce()
        try:
            acc = await client.existing_account_from_key(key)
            log.info(acc)
        except Exception as e:
            await client.new_account(key, [self.CONTACT], True, None)
            acc = await client.existing_account_from_key(key)
            log.info(acc)


    async def test_run(self):
        from aioacme.aioacme.client import new_client
        from aioacme.aioacme.identifier import DnsName
        import aioacme.aioacme.errors

        _key, csr, path = self.data
        key = josepy.JWKRSA.load(_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        client = await new_client(self.DIRECTORY, 'easy')
        self.addAsyncCleanup(client.close)
        await client.refresh_nonce()
        try:
            acc = await client.existing_account_from_key(key)
            log.info(acc)
        except Exception as e:
            await client.new_account(key, [self.CONTACT], True, None)
            acc = await client.existing_account_from_key(key)
            log.info(acc)
        try:
            cert_url, order, authorizations = await acc.new_order(
                [DnsName(i) for i in names_of(csr)])
        except aioacme.aioacme.errors.ErrorResponse as e:
            log.exception(e)
            pass

        for url, authz in authorizations:
            for challenge in authz.challenges:
                if challenge.type != 'http-01':
                    continue
                await acc.begin_http_01_challenge(challenge)

        h = await acc.finalize_order(str(order.finalize_url), csr.public_bytes(serialization.Encoding.DER))

        while True:
            try:
                status, header, data = await acc.client._post_with_key_id(str(cert_url), b'', acc.private_key,
                                                                          acc.account_href)
                if 'certificate' in data:
                    break
            except aioacme.aioacme.errors.ErrorResponse as e:
                log.exception(e)
            await asyncio.sleep(1)

        with self.assertRaises(aioacme.aioacme.errors.ProtocolError) as e:
            status, header, data = await acc.client._post_with_key_id(data['certificate'], b'', acc.private_key,
                                                                      acc.account_href)
        # certificate
        data = e.exception.args[3]
        print(data)


class TestaioacmeProxy(Testaioacme, TestBrokerClient):
    pass


class Testacmetiny(TestClient, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestClient.setUp(self)
        path = self.data.path
        for n in ['challenge']:
            if not (r := (path / n)).exists():
                r.mkdir()

    async def _run_acmetiny(self, cmd):
        import acme_tiny.acme_tiny as at
        argv = shlex.split(cmd)
        log.info(shlex.join(argv))
        r = await self.loop.run_in_executor(None, at.main, argv)
        return r

    async def test_run(self):
        key,csr,path = self.data
        await self._run_acmetiny(f'--directory-url {self.DIRECTORY} --disable-check --contact {self.CONTACT} --account-key {self.data.path}/account.key --csr {self.data.path}/the.csr --acme-dir {self.data.path}/challenge ')


class TestacmetinyProxy(Testacmetiny, TestBrokerClient):
    pass


class Testacmesh(TestClient, unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        TestClient.setUp(self)
        path = self.data.path
        for n in ['run','config','www','certs']:
            if not (r:=(path / n)).exists():
                r.mkdir()
        self._rmtree.extend(['www','certs'])

    async def asyncSetUp(self) -> None:
        await TestClient.asyncSetUp(self)
        if True or not (self.data.path / 'config/ca/localhost/account.key').exists():
            os.chdir('acme.sh')
            await self._run(f'./acme.sh  --no-color --log /dev/null --log-level 0 --home ../{self.data.path}/run --install --nocron --noprofile', prefix=False)
            os.chdir('..')

    async def _run(self, _cmd, prefix=True):
        if prefix:
            cmd = f'{self.data.path}/run/acme.sh --no-color --log /dev/null --log-level 0 --config-home {self.data.path}/config/ --cert-home {self.data.path}/certs --server {self.DIRECTORY} ' + _cmd
        else:
            cmd = _cmd
        log.info(cmd)
        p = await asyncio.create_subprocess_exec(*shlex.split(cmd), stdout=asyncio.subprocess.PIPE)
        def llog(_line, logger):
            if not _line:
                return
            args = _line.decode().strip().split(']', maxsplit=2)
            if len(args) == 2:
                logger(args[1])
            else:
                logger(_line)

        while r:=await p.stdout.readline():
            llog(r,log.info)

    async def test_run(self):
        key,csr,path = self.data
        await self._run(f"""--register-account --accountemail {self.CONTACT}""")
        domains = ' '.join(['--domain {}'.format(d) for d in names_of(csr)])
        await self._run(f"""--issue {domains} --webroot {path}/www/ --force""")


class TestacmeshProxy(Testacmetiny, TestBrokerClient):
    pass
