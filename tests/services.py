import logging

import aiohttp_jinja2
import jinja2

import acmetk.util
from acmetk import AcmeCA
from acmetk.main import _url_for


class TestService:
    def __init__(self, tmpdir):
        self.tmpdir = tmpdir
        self.log = logging.getLogger(f"acmetk.tests.{self.__class__.__name__}")

        ca_key_path = self.tmpdir / "root.key"

        acmetk.util.generate_root_cert(
            ca_key_path,
            "DE",
            "Lower Saxony",
            "Hanover",
            "Acme Toolkit",
            self.__class__.__name__,
        )

    async def close(self):
        pass


class CAService(TestService):

    async def run(self, port, db, **kwargs):
        runner, ca = await AcmeCA.runner(
            config=dict(
                port=port,
                hostname="localhost",
                db=db.format(database="acme-ca"),
                cert=self.tmpdir / "root.crt",
                private_key=self.tmpdir / "root.key",
                **kwargs,
            )
        )

        aiohttp_jinja2.setup(runner.app, loader=jinja2.FileSystemLoader("./tpl/"))
        aiohttp_jinja2.get_env(runner.app).globals.update({"url_for": _url_for, "names_of_csr": acmetk.util.names_of})

        #        await ca._db._recreate()

        self.runner = runner
        self.ca = ca

    async def close(self):
        await self.runner.shutdown()
