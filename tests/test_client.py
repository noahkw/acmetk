import asyncio
import collections
import json
import logging
import shlex
import shutil
import unittest
from pathlib import Path

import josepy
from configobj import ConfigObj

import acme_broker.util
from acme_broker import AcmeCA, models

log = logging.getLogger('acme_broker.test_client')

DEFAULT_NETWORK_TIMEOUT = 45

ClientData = collections.namedtuple('data', ['key', 'csr', 'path'])


class TestClient(unittest.IsolatedAsyncioTestCase):
    DIRECTORY = 'http://localhost:8000/directory'

    @property
    def name(self):
        return self.__class__.__name__[4:]

    def setUp(self) -> None:
        self.log = logging.getLogger(f'acme_broker.tests.{self.name}')
        self.contact = f'woehler+{self.name}@luis.uni-hannover.de'
        dir_ = Path('./tmp') / self.name
        if not dir_.exists():
            dir_.mkdir(parents=True)

        key = acme_broker.util.generate_rsa_key(dir_ / 'account.key')
        thekey = acme_broker.util.generate_rsa_key(dir_ / 'the.key')
        csr = acme_broker.util.generate_csr(f'{self.name}.test.de', thekey, dir_ / 'the.csr',
                                            names=[f'{self.name}.test.de'])

        self.data = ClientData(key, csr, dir_)

        self._rmtree = ['the.csr']

    def tearDown(self):
        for i in self._rmtree:
            if Path(i).is_absolute():
                log.error(f"{i} is not relative")
                continue

            if (path := self.data.path / i).is_dir():
                log.info(f'rmtree {path}')
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                log.info(f'unlink {path}')
                path.unlink()

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        config = ConfigObj('../debug.ini', unrepr=True)
        runner, ca = await AcmeCA.runner(**config)
        self.runner = runner
        self.ca = ca

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()

    async def test_run(self):
        # await asyncio.sleep(600)
        pass

    async def test_add_account(self):
        with open(r'test_account.pub', 'rb') as pem:
            b = pem.read()

        pubkey = acme_broker.util.deserialize_pubkey(b)

        async with self.ca._session() as session:
            account = models.Account(key=josepy.util.ComparableRSAKey(pubkey), status=models.AccountStatus.VALID,
                                     contact=json.dumps(()),
                                     termsOfServiceAgreed=True)
            session.add(account)

            result = await self.ca._db.get_account(session, pubkey)

            assert acme_broker.util.serialize_pubkey(result.key) == acme_broker.util.serialize_pubkey(account.key)
            assert result.key == account.key
            assert account.serialize() == result.serialize()

            await session.commit()


class TestAcmetiny(TestClient):
    def setUp(self) -> None:
        TestClient.setUp(self)
        path = self.data.path
        for n in ['challenge']:
            if not (r := (path / n)).exists():
                r.mkdir()

    async def _run_acmetiny(self, cmd):
        import acme_tiny as at
        argv = shlex.split(cmd)
        log.info(shlex.join(argv))
        r = await self.loop.run_in_executor(None, at.main, argv)
        return r

    async def test_run(self):
        key, csr, path = self.data
        account_key_path = path / 'account.key'
        csr_path = path / 'the.csr'

        self.assertTrue(account_key_path.exists())
        self.assertTrue(csr_path.exists())

        await self._run_acmetiny(
            f'--directory-url {self.DIRECTORY} --disable-check --contact {self.contact} --account-key '
            f'{account_key_path} --csr {csr_path} --acme-dir {self.data.path}/challenge ')
