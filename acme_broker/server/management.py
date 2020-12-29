import collections

import aiohttp_jinja2
import cryptography
import sqlalchemy
from sqlalchemy import select
from sqlalchemy.orm import selectinload, selectin_polymorphic
from sqlalchemy.sql import text

from acme_broker.models import (
    Change,
    Account,
    Order,
    Identifier,
    Certificate,
    Challenge,
    Authorization,
)
from acme_broker.models.base import Entity
from acme_broker.server.routes import routes
from acme_broker.util import PerformanceMeasurementSystem
from .pagination import paginate


class AcmeManagement:
    @routes.get("/mgmt/", name="mgmt-index")
    @aiohttp_jinja2.template("index.jinja2")
    async def management_index(self, request):
        import datetime
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        async with self._session(request) as session:
            now = datetime.datetime.now()
            start_date = now - datetime.timedelta(days=28)
            q = (
                select(
                    sqlalchemy.func.date_trunc("day", Change.timestamp).label("dateof"),
                    sqlalchemy.func.count(Change.change).label("totalof"),
                    sqlalchemy.func.count(sqlalchemy.distinct(Change._entity)).label(
                        "uniqueof"
                    ),
                    Entity.identity.label("actionof"),
                )
                .select_from(Change)
                .join(Entity, Entity.entity == Change._entity)
                .filter(Change.timestamp.between(start_date, now))
                .group_by(text("dateof"), Entity.identity)
            )
            async with pms.measure():
                r = await session.execute(q)

            s = collections.defaultdict(lambda: dict())

            for m in r.mappings():
                s[m["dateof"].date()] = {k:{'total': 0, 'unique': 0} for k in ['identifier','account','order','challenge','authorization','certificate']}

                s[m["dateof"].date()][m["actionof"]].update({
                    "total": m["totalof"],
                    "unique": m["uniqueof"],
                })

            statistics = []
            for i in sorted(s.keys()):
                statistics.append(
                    (
                        i,
                        s[i],
                        sum(map(lambda x: x["unique"], s[i].values())),
                        sum(map(lambda x: x["total"], s[i].values())),
                    )
                )
            return {"statistics": statistics, "pms": pms}

    @routes.get("/mgmt/changes", name="mgmt-changes")
    @aiohttp_jinja2.template("changes.jinja2")
    async def management_changes(self, request):
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        async with self._session(request) as session:
            q = select(sqlalchemy.func.max(Change.change))
            async with pms.measure():
                total = (await session.execute(q)).scalars().first()

            q = (
                select(Change)
                .options(
                    selectin_polymorphic(Change.entity, [Account]),
                    selectinload(Change.entity.of_type(Authorization))
                    .selectinload(Authorization.identifier)
                    .selectinload(Identifier.order)
                    .selectinload(Order.account),
                    selectinload(Change.entity.of_type(Challenge))
                    .selectinload(Challenge.authorization)
                    .selectinload(Authorization.identifier)
                    .selectinload(Identifier.order)
                    .selectinload(Order.account),
                    selectinload(Change.entity.of_type(Certificate))
                    .selectinload(Certificate.order)
                    .selectinload(Order.account),
                    selectinload(Change.entity.of_type(Identifier))
                    .selectinload(Identifier.order)
                    .selectinload(Order.account),
                    selectinload(Change.entity.of_type(Order)).selectinload(
                        Order.account
                    ),
                )
                .order_by(Change.change.desc())
            )
            page = await paginate(session, request, q, Change.change, total, pms)

            return {"changes": page.items, "page": page, "pms": pms}

    @routes.get("/mgmt/accounts", name="mgmt-accounts")
    @aiohttp_jinja2.template("accounts.jinja2")
    async def management_accounts(self, request):
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        async with self._session(request) as session:
            q = select(sqlalchemy.func.count(Account.kid))
            async with pms.measure():
                total = (await session.execute(q)).scalars().first()

            q = (
                select(Account)
                .options(selectinload(Account.orders))
                .order_by(Account._entity.desc())
            )

            page = await paginate(session, request, q, "limit", total, pms=pms)

            return {"accounts": page.items, "page": page, "pms": pms}

    @routes.get("/mgmt/accounts/{account}", name="mgmt-account")
    @aiohttp_jinja2.template("account.jinja2")
    async def management_account(self, request):
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        account = request.match_info["account"]
        async with self._session(request) as session:
            q = (
                select(Account)
                .options(
                    selectinload(Account.orders),
                    selectinload(Account.changes).selectinload(Change.entity),
                )
                .filter(Account.kid == account)
            )
            async with pms.measure():
                a = await session.execute(q)
            a = a.scalars().first()
            return {"account": a, "orders": a.orders, "cryptography": cryptography, "pms": pms}

    @routes.get("/mgmt/orders", name="mgmt-orders")
    @aiohttp_jinja2.template("orders.jinja2")
    async def management_orders(self, request):
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        async with self._session(request) as session:
            q = select(sqlalchemy.func.count(Order.order_id))
            async with pms.measure():
                total = (await session.execute(q)).scalars().first()

            q = (
                select(Order)
                .options(
                    selectinload(Order.account),
                    selectinload(Order.identifiers),
                    selectinload(Order.changes),
                )
                .order_by(Order._entity.desc())
            )

            page = await paginate(session, request, q, "limit", total)
            return {"orders": page.items, "page": page, "pms": pms}

    @routes.get("/mgmt/orders/{order}", name="mgmt-order")
    @aiohttp_jinja2.template("order.jinja2")
    async def management_order(self, request):
        order = request.match_info["order"]
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        changes = []
        async with self._session(request) as session:
            q = (
                select(Order)
                .options(
                    selectinload(Order.account),
                    selectinload(Order.identifiers).options(
                        selectinload(Identifier.authorization).options(
                            selectinload(Authorization.challenges)
                            .selectinload(Challenge.changes)
                            .selectinload(Change.entity),
                            selectinload(Authorization.changes).selectinload(
                                Change.entity
                            ),
                        ),
                        selectinload(Identifier.changes).selectinload(Change.entity),
                    ),
                    selectinload(Order.changes).selectinload(Change.entity),
                    selectinload(Order.certificate)
                    .selectinload(Certificate.changes)
                    .selectinload(Change.entity),
                )
                .filter(Order.order_id == order)
            )
            async with pms.measure():
                r = await session.execute(q)
            o = r.scalars().first()

            changes.extend(o.changes)

        async with pms.measure():

            for i in o.identifiers:
                changes.extend(i.changes)
                changes.extend(i.authorization.changes)
                for c in i.authorization.challenges:
                    changes.extend(c.changes)

            if o.certificate:
                changes.extend(o.certificate.changes)

            changes = sorted(changes, key=lambda x: x.timestamp, reverse=True)

        return {"order": o, "changes": changes, "pms": pms}

    @routes.get("/mgmt/certificates", name="mgmt-certificates")
    @aiohttp_jinja2.template("certificates.jinja2")
    async def management_certificates(self, request):
        pms = PerformanceMeasurementSystem(enable=request.query.get('pms', False))
        async with self._session(request) as session:
            q = select(sqlalchemy.func.count(Certificate.certificate_id))
            async with pms.measure():
                total = (await session.execute(q)).scalars().first()

            q = (
                select(Certificate)
                .options(
                    selectinload(Certificate.changes),
                    selectinload(Certificate.order).selectinload(Order.account),
                )
                .order_by(Certificate._entity.desc())
            )

            page = await paginate(session, request, q, "limit", total, pms=pms)
            return {"certificates": page.items, "page": page, "pms": pms}

    @routes.get("/mgmt/certificates/{certificate}", name="mgmt-certificate")
    async def management_certificate(self, request):
        certificate = request.match_info["certificate"]
        async with self._session(request) as session:
            q = (
                select(Certificate)
                .options(
                    selectinload(Certificate.changes),
                    selectinload(Certificate.order).selectinload(Order.account),
                )
                .filter(Certificate.certificate_id == certificate)
            )

            r = await session.execute(q)
            a = r.scalars().first()
            context = {"certificate": a.cert, "cryptography": cryptography}
            response = aiohttp_jinja2.render_template(
                "certificate.jinja2", request, context
            )
            response.content_type = "text"
            response.charset = "utf-8"
            return response
