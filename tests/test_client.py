import asyncio
import collections
import logging
import shlex
import shutil
import unittest
from pathlib import Path

import acme_broker.util
from acme_broker import AcmeCA

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
        runner = await AcmeCA.runner()
        #  logging.basicConfig(filename='test_client.log', level=logging.DEBUG)
        logging.basicConfig(level=logging.DEBUG)
        self.runner = runner

    async def asyncTearDown(self) -> None:
        await self.runner.shutdown()
        await self.runner.cleanup()

    async def test_run(self):
        await asyncio.sleep(600)
        pass


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
