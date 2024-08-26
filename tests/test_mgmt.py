import unittest
import asyncio
import re
import logging
import logging.config
import warnings
import sys

from yarl import URL
import aiohttp

from sqlalchemy import select
from sqlalchemy.orm import (
    selectin_polymorphic,
)
from acmetk.models import (
    Account,
    Order,
    Certificate,
    Identifier,
)

from acmetk.models.base import Entity
from .test_broker import TestCertBotBrokerLocalCA
from acmetk.main import _url_for
import acmetk.util

import jinja2
import aiohttp_jinja2

log = logging.getLogger("acmetk.tests.test_mgmt")

DEFAULT_NETWORK_TIMEOUT = 45

if sys.version_info < (3, 11):
    ExceptionGroup = Exception


@unittest.skipUnless(sys.version_info >= (3, 11), "requires ExceptionGroup")
class TestMGMT(TestCertBotBrokerLocalCA, unittest.IsolatedAsyncioTestCase):
    # class TestMGMT(TestCA, unittest.IsolatedAsyncioTestCase):
    @property
    def NAME(self):
        return self.__class__.__name__[4:]

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.site = next(iter(self.runner.sites))

        aiohttp_jinja2.setup(self.runner.app, loader=jinja2.FileSystemLoader("./tpl/"))
        aiohttp_jinja2.get_env(self.runner.app).globals.update(
            {"url_for": _url_for, "names_of_csr": acmetk.util.names_of}
        )

    def setUp(self) -> None:
        super().setUp()
        self.log = logging.getLogger(f"acmetk.tests.{self.NAME}")
        self.CONTACT = f"koetter+{self.NAME}@luis.uni-hannover.de"

    def tearDown(self):
        super().tearDown()

    async def get(self, url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                self.assertEqual(response.status, 200)
                response = await response.read()
                return response

    async def test_dynamic(self):
        await self.test_run()

        warnings.simplefilter("error")

        base = URL(self.site.name)
        try:
            async with (asyncio.TaskGroup() as tg):
                for psar in self.runner.app.router._resources:
                    service = getattr(self, f"_{psar.canonical[1:]}")

                    assert isinstance(psar, aiohttp.web.PrefixedSubAppResource)
                    for r in psar._app.router._resources:
                        if not hasattr(r, "name") or (name := r.name) is None:
                            continue
                        if not (name.split(".")[-1]).startswith("mgmt-"):
                            continue

                        if r.__class__.__name__ == "DynamicResource":
                            dyn = [
                                i["name"]
                                for i in re.finditer(r"{(?P<name>\w+)}", r.canonical)
                            ]
                            self.assertEqual(len(dyn), 1)
                            n = dyn[0]

                            q = (
                                select(Entity)
                                .options(
                                    selectin_polymorphic(
                                        Entity,
                                        [Account, Order, Certificate, Identifier],
                                    )
                                )
                                .filter(Entity.identity == n)
                                .limit(10)
                            )

                            async with service._db.session() as session:
                                es = (await session.execute(q)).scalars().all()
                                for e in es:
                                    try:
                                        v = getattr(e, f"{n}_id")
                                    except Exception as exc:
                                        log.exception(exc)
                                        v = "1"
                                    u = base.with_path(r.canonical.format(**{n: v}))
                                    log.info(f"visit {psar} {u}")
                                    tg.create_task(self.get(u))
        except ExceptionGroup as eg:
            print(eg)

    async def test_static(self):
        warnings.simplefilter("error")

        base = URL(self.site.name)
        async with asyncio.TaskGroup() as tg:
            for psar in self.runner.app.router._resources:
                assert isinstance(psar, aiohttp.web.PrefixedSubAppResource)
                for r in psar._app.router._resources:
                    if not hasattr(r, "name") or (name := r.name) is None:
                        continue
                    if not (name.split(".")[-1]).startswith("mgmt-"):
                        continue

                    if r.__class__.__name__ == "PlainResource":
                        u = base.with_path(r.canonical)
                        tg.create_task(self.get(u))
